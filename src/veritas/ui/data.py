"""What the local UI shows, read from the documents the CLI writes. Read-only: nothing here changes the workspace.

The workspace database is opened read-only, and each run's audit chain is verified on
every view, so the page says whether a run's record is intact. Files are served only by
name from an allowlist inside a run's directory.
"""

from __future__ import annotations

import json
import re
import sqlite3
from pathlib import Path
from typing import Any

from .. import __version__
from ..imports.osv import summary as advisory_summary
from ..models.profiles import ROUTES, RouteUnavailable, load_routing
from ..models.registry import load_models
from ..sandbox import DockerError, read_lock
from ..store.audit import verify

RUN_ID = re.compile(r"^r-\d{4,6}$")
FILES = re.compile(r"^(report\.md|report\.sarif|code-findings\.sarif|sbom\.cdx\.json|patches/S-\d{4}\.diff)$")
MAX_FILE = 4 * 1024 * 1024
KINDS = {"assess": "Assess", "reproduce": "Assess", "analyze": "Analyze", "eval": "Model evaluation"}


def _db(root: Path) -> sqlite3.Connection | None:
    path = root / ".veritas" / "veritas.db"
    if not path.exists():
        return None
    return sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True, check_same_thread=False)


def _json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _run_dir(root: Path, run_id: str) -> Path:
    return root / ".veritas" / "runs" / run_id


def _summary(root: Path, run_id: str, mode: str) -> dict[str, Any]:
    folder = _run_dir(root, run_id)
    if mode in ("assess", "reproduce"):
        doc = _json(folder / "findings.json") or {}
        return {"subject": (doc.get("scope") or {}).get("name"), "counts": doc.get("summary") or {},
                "started": doc.get("started"), "duration_s": doc.get("duration_s")}  # fmt: skip
    if mode == "analyze":
        doc = _json(folder / "analysis.json") or {}
        spec = doc.get("spec") or {}
        clean = _json(folder / "spec.json") or {}
        return {"subject": (doc.get("charter") or {}).get("name"), "started": doc.get("started"),
                "duration_s": doc.get("duration_s"), "digest": clean.get("digest"),
                "verifications": sum(1 for d in (folder / "cleanroom").glob("*") if d.is_dir()),
                "counts": {"candidates": (doc.get("code") or {}).get("candidates", 0), "claims": spec.get("claims", 0),
                           "subjects": len(doc.get("subjects") or [])}}  # fmt: skip
    if mode == "eval":
        doc = _json(root / ".veritas" / "evals" / f"{run_id}.json") or {}
        return {"subject": "routing eval", "counts": {"results": len(doc.get("results") or [])}}
    return {}


def overview(root: Path) -> dict[str, Any]:
    runs: list[dict[str, Any]] = []
    acknowledged = 0
    db = _db(root)
    if db is not None:
        try:
            rows = db.execute("SELECT id, mode, created_at, outcome FROM runs ORDER BY id DESC LIMIT 200").fetchall()
            acknowledged = db.execute("SELECT COUNT(*) FROM scope_acks").fetchone()[0]
            approved = set(db.execute("SELECT run_id, digest FROM spec_approvals").fetchall())
        finally:
            db.close()
        for run_id, mode, created, outcome in rows:
            summary = _summary(root, run_id, mode)
            runs.append({"id": run_id, "mode": mode, "kind": KINDS.get(mode, mode), "created": created,
                         "outcome": outcome, **summary,
                         "approved": (run_id, summary.get("digest")) in approved})  # fmt: skip
    try:
        lock = read_lock(root)
    except DockerError:  # no images built yet: an empty workspace is still worth showing
        lock = {}
    models = load_models(lock)
    routes = []
    routing = load_routing(root, models)
    for route in ROUTES:
        try:
            r = routing.resolve(route)
            routes.append({"route": route, "model": r.model.name, "aliased_to": r.serving if r.aliased else None})
        except RouteUnavailable as exc:
            routes.append({"route": route, "model": None, "reason": str(exc)})
    labs = []
    for lab in sorted((root / "labs").glob("*")) if (root / "labs").is_dir() else []:
        if lab.is_dir():
            labs.append({"name": lab.name, "scope": (lab / "veritas.scope.yaml").is_file(),
                         "charter": (lab / "veritas.charter.yaml").is_file()})  # fmt: skip
    return {
        "veritas": __version__,
        "runs": runs,
        "acknowledged_scopes": acknowledged,
        "models": [
            {"name": m.name, "quantization": m.quantization, "license": m.license, "gib": round(m.size / 2**30, 2)}
            for m in models.values()
        ],
        "routes": routes,
        "profile": routing.profile.name,
        "images": sorted((lock.get("images") or {}).keys()),
        "labs": labs,
        "advisories": advisory_summary(root / ".veritas"),
    }


def run_detail(root: Path, run_id: str) -> dict[str, Any] | None:
    if not RUN_ID.match(run_id):
        return None
    db = _db(root)
    if db is None:
        return None
    try:
        row = db.execute("SELECT mode, created_at, outcome, audit_head, audit_entries FROM runs WHERE id = ?",
                         (run_id,)).fetchone()  # fmt: skip
        approvals = {d for (d,) in db.execute("SELECT digest FROM spec_approvals WHERE run_id = ?", (run_id,))}
    finally:
        db.close()
    if row is None:
        return None
    mode, created, outcome, head, entries = row
    folder = _run_dir(root, run_id)
    audit_path = folder / "audit.jsonl"
    checked = verify(audit_path, expected_head=head, expected_entries=entries) if audit_path.exists() else None
    out: dict[str, Any] = {
        "id": run_id, "mode": mode, "kind": KINDS.get(mode, mode), "created": created, "outcome": outcome,
        "audit": {"ok": bool(checked and checked.ok), "entries": entries,
                  "problems": list(checked.problems)[:5] if checked else ["the audit log is missing"]},
        "files": sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*")
                        if p.is_file() and FILES.match(p.relative_to(folder).as_posix())),
    }  # fmt: skip
    if mode in ("assess", "reproduce"):
        out["assessment"] = _json(folder / "findings.json")
    elif mode == "analyze":
        document = _json(folder / "analysis.json") or {}
        clean = _json(folder / "spec.json")
        out["analysis"] = document
        out["spec"] = clean
        out["approved"] = bool(clean and clean.get("digest") in approvals)
        out["code"] = (_json(folder / "code-findings.json") or {}).get("findings", [])
        out["cleanroom"] = [
            {"task": d.name, "conformance": _json(d / "conformance.json"), "similarity": _json(d / "similarity.json")}
            for d in sorted((folder / "cleanroom").glob("*")) if d.is_dir()
        ]  # fmt: skip
        out["patches"] = [_json(p) for p in sorted((folder / "patches").glob("S-*.json"))]
    elif mode == "eval":
        out["eval"] = _json(root / ".veritas" / "evals" / f"{run_id}.json")
    return out


def run_file(root: Path, run_id: str, name: str) -> str | None:
    """One allowlisted text file from a run's directory, or None."""
    if not RUN_ID.match(run_id) or not FILES.match(name):
        return None
    folder = _run_dir(root, run_id).resolve()
    path = (folder / name).resolve()
    if folder not in path.parents or not path.is_file() or path.stat().st_size > MAX_FILE:
        return None
    return path.read_text(encoding="utf-8", errors="replace")
