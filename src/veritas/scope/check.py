"""Scope checking: file loading, validation rules, address pinning, and the digest.

Relative paths in a scope file resolve against the directory that contains it.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from ..core.canonical import digest, file_digest
from ..core.netpolicy import classify_address
from ..documents import load_yaml
from ..imports.har import HarError, read_har
from .model import API_VERSION, AssessmentScope

Resolver = Callable[[str, int], list[str]]


def system_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return sorted({str(info[4][0]) for info in infos})


@dataclass
class PinnedTarget:
    id: str
    scheme: str
    host: str
    port: int
    addresses: list[str]
    labels: list[str]


@dataclass
class ScopeReport:
    path: Path
    scope: AssessmentScope | None = None
    errors: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    pinned: list[PinnedTarget] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)
    digest: str | None = None

    @property
    def ok(self) -> bool:
        return self.scope is not None and not self.errors


def _validation_messages(exc: ValidationError) -> list[str]:
    out = []
    for err in exc.errors():
        loc = ".".join(str(p) for p in err["loc"]) or "(root)"
        out.append(f"{loc}: {err['msg'].removeprefix('Value error, ')}")
    return out


def _compose_addresses(path: Path) -> dict[str, set[str]]:
    """Fixed addresses declared per compose service (by service name and hostname)."""
    doc = load_yaml(path) or {}
    out: dict[str, set[str]] = {}
    for name, svc in (doc.get("services") or {}).items():
        nets = (svc or {}).get("networks") or {}
        addrs = set()
        if isinstance(nets, dict):
            for cfg in nets.values():
                for key in ("ipv4_address", "ipv6_address"):
                    if isinstance(cfg, dict) and cfg.get(key):
                        addrs.add(str(cfg[key]))
        if addrs:
            out[name] = addrs
            if svc.get("hostname"):
                out[str(svc["hostname"])] = addrs
    return out


def check_scope(path: str | Path, *, now: datetime | None = None, resolver: Resolver = system_resolver) -> ScopeReport:
    path = Path(path)
    report = ScopeReport(path=path)
    try:
        raw = load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        report.errors.append(f"cannot read scope file: {exc}")
        return report
    if not isinstance(raw, dict):
        report.errors.append("scope file must be a YAML mapping")
        return report
    try:
        scope = AssessmentScope.model_validate(raw)
    except ValidationError as exc:
        report.errors.extend(_validation_messages(exc))
        return report
    report.scope = scope
    base = path.parent
    now = now or datetime.now(UTC)

    window = scope.authorization.window
    if now < window.start:
        report.errors.append(f"authorization window opens at {window.start.isoformat()}")
    if now >= window.end:
        report.errors.append(f"authorization window ended at {window.end.isoformat()}")

    ref = scope.authorization.reference
    if ref.file is not None:
        ref_path = base / ref.file
        if ref_path.is_file():
            report.files["authorization.reference"] = file_digest(str(ref_path))
        else:
            report.errors.append(f"authorization.reference.file not found: {ref_path}")
    else:
        report.notices.append(f"authorization reference recorded as identifier {ref.id!r}")

    compose: dict[str, set[str]] = {}
    volumes: set[str] = set()
    if scope.environment.compose_file:
        compose_path = base / scope.environment.compose_file
        if compose_path.is_file():
            report.files["environment.compose_file"] = file_digest(str(compose_path))
            try:
                compose = _compose_addresses(compose_path)
                volumes = set((load_yaml(compose_path) or {}).get("volumes") or {})
            except (yaml.YAMLError, AttributeError) as exc:
                report.errors.append(f"cannot parse compose file: {exc}")
        else:
            report.errors.append(f"environment.compose_file not found: {compose_path}")
    for sensor in scope.sensors:
        if scope.environment.compose_file and sensor.volume not in volumes:
            report.errors.append(f"sensor {sensor.id}: the compose file declares no volume {sensor.volume!r}")

    for t in scope.targets:
        if t.addresses is not None:
            addresses = sorted(set(t.addresses))
            declared = compose.get(t.host)
            if scope.environment.compose_file and declared is None:
                report.notices.append(f"target {t.id}: compose file declares no fixed address for {t.host!r}")
            elif declared is not None and set(addresses) != declared:
                report.errors.append(
                    f"target {t.id}: pinned addresses {addresses} differ from the compose file {sorted(declared)}"
                )
        else:
            try:
                addresses = resolver(t.host, t.port)
            except OSError as exc:
                report.errors.append(f"target {t.id}: cannot resolve {t.host!r} ({exc}); declare addresses to pin them")
                continue
            if not addresses:
                report.errors.append(f"target {t.id}: {t.host!r} resolved to no addresses")
                continue
        labels = []
        for addr in addresses:
            allowed, label = classify_address(addr)
            labels.append(label)
            if not allowed:
                report.errors.append(f"target {t.id}: {addr} is {label}")
        if t.scheme == "https":
            report.notices.append(
                f"target {t.id}: this gateway version does not support https; its requests will be refused"
            )
        if t.source is not None and not (base / t.source).is_dir():
            report.errors.append(f"target {t.id}: source directory not found: {base / t.source}")
        for n, name in enumerate(t.recordings):
            recording = base / name
            if not recording.is_file():
                report.errors.append(f"target {t.id}: recording not found: {recording}")
                continue
            try:
                catalog = read_har(recording)
            except HarError as exc:
                report.errors.append(f"target {t.id}: {name} isn't a HAR recording Veritas can read: {exc}")
                continue
            report.files[f"targets.{t.id}.recordings.{n}"] = file_digest(str(recording))
            origin = f"{t.scheme}://{t.host}:{t.port}"
            on = sum(1 for e in catalog.endpoints.values() if e.origin == origin)
            report.notices.append(
                f"target {t.id}: {name} shows {on} endpoint(s) on this origin; recon adds those in scope and "
                "replays none of them"
            )
        report.pinned.append(PinnedTarget(t.id, t.scheme, t.host, t.port, addresses, labels))

    if not report.errors:
        report.digest = digest(
            {
                "schema": API_VERSION,
                "scope": scope.model_dump(mode="json", by_alias=True),
                "files": report.files,
                "pinned": {p.id: p.addresses for p in report.pinned},
            }
        )
    return report
