"""Admission rules the gateway applies to every proxied request.

Pure logic: no sockets, no clocks except the `now` passed in. The proxy calls
`admit()` once per request and either forwards it to a pinned address or answers
with the `Denied` status. Rules are checked in a fixed order so the first failing
rule names the denial (docs/architecture.md §4.2, §6.5, §9).
"""

from __future__ import annotations

import base64
import binascii
import re
from collections import Counter
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict

from ..core.impact import HTTP_METHODS, SAFE_METHODS, Impact, impact_allows, method_impact
from ..core.netpolicy import any_path_matches, path_ambiguity
from ..core.tokens import NetGrant, TokenClaims, TokenError, verify_token

DEFAULT_PORTS = {"http": 80, "https": 443}


class Denied(Exception):
    def __init__(self, code: str, status: int, detail: str = ""):
        super().__init__(f"{code}: {detail}" if detail else code)
        self.code, self.status, self.detail = code, status, detail


class GatewayTarget(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    scheme: str
    host: str
    port: int
    addresses: list[str]
    allow_paths: list[str]
    allow_methods: list[str]
    deny_paths: list[str] = []
    unsafe_get: list[str] = []
    rps: float
    concurrency: int
    max_requests: int


class GatewayIdentity(BaseModel):
    """A synthetic identity the gateway signs in as. Its secret travels separately, never in the config."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    target: str
    login_path: str
    username: str
    username_field: str
    password_field: str


class GatewayConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    run: str
    targets: list[GatewayTarget]
    identities: list[GatewayIdentity] = []

    def target_for(self, scheme: str, host: str, port: int) -> GatewayTarget | None:
        for t in self.targets:
            if (t.scheme, t.host, t.port) == (scheme, host, port):
                return t
        return None

    def identity(self, identity_id: str) -> GatewayIdentity | None:
        return next((i for i in self.identities if i.id == identity_id), None)


def authority_of(target: GatewayTarget) -> str:
    return _authority(target.host, target.port, target.scheme)


@dataclass(frozen=True)
class ProxyRequest:
    method: str
    uri: str
    host_header: str | None
    proxy_authorization: str | None
    identity: str | None = None


@dataclass(frozen=True)
class Admission:
    target: GatewayTarget
    claims: TokenClaims
    grant: NetGrant
    impact: Impact
    path: str  # normalized path used for matching
    upstream_target: str  # origin-form request target sent upstream
    authority: str  # Host header value sent upstream
    identity: str | None


@dataclass
class AdmissionState:
    revoked: set[str] = field(default_factory=set)
    run_revoked: bool = False
    grant_counts: Counter[tuple[str, int]] = field(default_factory=Counter)
    target_counts: Counter[str] = field(default_factory=Counter)


_UNRESERVED_ESCAPE = re.compile(r"%([0-9A-Fa-f]{2})")


def _decode_unreserved(path: str) -> str:
    """Decode percent-escapes of unreserved characters (RFC 3986 §6.2.2.2) before matching."""

    def repl(m: re.Match[str]) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if (ch.isascii() and (ch.isalnum() or ch in "-_~")) else m.group(0).upper()

    return _UNRESERVED_ESCAPE.sub(repl, path)


def _authority(host: str, port: int, scheme: str) -> str:
    shown = f"[{host}]" if ":" in host else host
    return shown if DEFAULT_PORTS[scheme] == port else f"{shown}:{port}"


def _parse_host_header(value: str, scheme: str) -> tuple[str, int] | None:
    value = value.strip().lower()
    if value.startswith("["):
        host, _, rest = value[1:].partition("]")
        port_text = rest[1:] if rest.startswith(":") else ""
        if rest and not rest.startswith(":"):
            return None
    else:
        host, _, port_text = value.partition(":")
    if not host:
        return None
    try:
        port = int(port_text) if port_text else DEFAULT_PORTS[scheme]
    except ValueError:
        return None
    return host.rstrip("."), port


def _credentials(header: str | None) -> tuple[str, str]:
    if not header:
        raise Denied("auth_required", 407, "Proxy-Authorization with a task token is required")
    scheme, _, value = header.strip().partition(" ")
    if scheme.lower() != "basic":
        raise Denied("auth_invalid", 407, "Basic proxy credentials expected")
    try:
        user, sep, token = base64.b64decode(value.strip(), validate=True).decode("ascii").partition(":")
    except (binascii.Error, UnicodeDecodeError):
        raise Denied("auth_invalid", 407, "undecodable credentials") from None
    if not sep:
        raise Denied("auth_invalid", 407, "credentials must be task-id:token")
    return user, token


def admit(req: ProxyRequest, config: GatewayConfig, key: bytes, state: AdmissionState, now: float) -> Admission:
    # 1. Who is asking: a valid, unexpired, unrevoked token for this run.
    tid, token = _credentials(req.proxy_authorization)
    try:
        claims = verify_token(token, key, now)
    except TokenError as exc:
        raise Denied("auth_invalid", 407, str(exc)) from None
    if claims.tid != tid or claims.run != config.run:
        raise Denied("auth_invalid", 407, "token does not belong to this task and run")
    if state.run_revoked or tid in state.revoked:
        raise Denied("revoked", 407, "token revoked")

    # 2. What is being asked: a known method and an absolute-form http URI.
    if req.method == "CONNECT":
        raise Denied("connect_unsupported", 405, "tunnels are not supported")
    if req.method not in HTTP_METHODS:
        raise Denied("method_unsupported", 405, req.method)
    if not req.uri.isascii() or not req.uri.lower().startswith(("http://", "https://")):
        raise Denied("origin_form", 400, "send absolute-form http:// request targets through the proxy")
    parts = urlsplit(req.uri)
    if parts.username is not None or parts.password is not None:
        raise Denied("credentials_in_uri", 400)
    if parts.fragment:
        raise Denied("bad_uri", 400, "fragment in request target")
    try:
        port = parts.port or DEFAULT_PORTS[parts.scheme]
    except ValueError:
        raise Denied("bad_uri", 400, "invalid port") from None
    host = (parts.hostname or "").rstrip(".")
    if not host:
        raise Denied("bad_uri", 400, "missing host")
    if parts.scheme == "https":
        raise Denied("https_unsupported", 403, "this gateway version does not intercept TLS")
    if req.host_header is None or _parse_host_header(req.host_header, parts.scheme) != (host, port):
        raise Denied("host_mismatch", 400, "Host header must match the request target")

    # 3. Where: an in-scope target, an unambiguous path, inside the scope's allow list.
    target = config.target_for(parts.scheme, host, port)
    if target is None:
        raise Denied("out_of_scope", 403, f"{host}:{port} is not a target in this scope")
    raw_path = parts.path or "/"
    problem = path_ambiguity(raw_path)
    if problem:
        raise Denied("path_ambiguous", 400, problem)
    path = _decode_unreserved(raw_path)
    if req.method not in target.allow_methods:
        raise Denied("method_not_in_scope", 403, req.method)
    if not any_path_matches(target.allow_paths, path):
        raise Denied("path_not_in_scope", 403, path)
    if any_path_matches(target.deny_paths, path):
        raise Denied("path_denied", 403, path)

    # 4. How much: the request's impact must fit the token, and it must fall in a grant.
    impact = method_impact(req.method)
    if req.method in SAFE_METHODS and any_path_matches(target.unsafe_get, path):
        impact = Impact.MUTATE
    if not impact_allows(claims.impact_max, impact):
        raise Denied("impact_exceeds_token", 403, f"{impact} exceeds {claims.impact_max}")
    match = next(
        (
            (i, g)
            for i, g in enumerate(claims.net)
            if g.target == target.id and req.method in g.methods and any_path_matches(g.paths, path)
        ),
        None,
    )
    if match is None:
        raise Denied("outside_envelope", 403, f"{req.method} {path} is not in this task's grants")
    index, grant = match
    if req.identity is not None:
        if req.identity not in grant.identities:
            raise Denied("identity_not_granted", 403, req.identity)
        known = config.identity(req.identity)
        if known is None or known.target != target.id:
            raise Denied("unknown_identity", 403, f"{req.identity} is not an identity of target {target.id}")

    # 5. Budgets: reserve one request against the grant and the target.
    if state.grant_counts[(tid, index)] >= grant.max_requests:
        raise Denied("task_budget_exhausted", 429, f"grant allows {grant.max_requests} requests")
    if state.target_counts[target.id] >= target.max_requests:
        raise Denied("target_budget_exhausted", 429, f"target allows {target.max_requests} requests")
    state.grant_counts[(tid, index)] += 1
    state.target_counts[target.id] += 1

    upstream_target = raw_path + (f"?{parts.query}" if parts.query else "")
    return Admission(
        target, claims, grant, impact, path, upstream_target, _authority(host, port, parts.scheme), req.identity
    )


class TokenBucket:
    """Requests-per-second limiter; `reserve(now)` returns how long to wait."""

    def __init__(self, rate: float, burst: float = 1.0):
        self.rate, self.capacity = rate, burst
        self.tokens: float = burst
        self.updated: float | None = None

    def reserve(self, now: float) -> float:
        if self.updated is not None:
            self.tokens = min(self.capacity, self.tokens + (now - self.updated) * self.rate)
        self.updated = now
        self.tokens -= 1.0
        return 0.0 if self.tokens >= 0 else -self.tokens / self.rate
