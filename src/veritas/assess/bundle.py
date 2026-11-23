"""Evidence bundles: one portable, self-verifying archive per run (docs/architecture.md §11)."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..findings.lint import lint_document
from ..store import Workspace, verify
from ..store.audit import GENESIS

RUN_FILES = ("audit.jsonl", "findings.json", "report.md", "report.sarif")


def _add(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mtime, info.mode = len(data), 0, 0o644  # fixed metadata: equal runs give equal bundles
    tar.addfile(info, io.BytesIO(data))


def export(root: Path, run_id: str, out: Path) -> Path:
    ws = Workspace(root)
    try:
        row = ws.db.execute("SELECT audit_head, audit_entries FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"no such run: {run_id}")
        members: dict[str, bytes] = {}
        for name in RUN_FILES:
            path = ws.runs_dir / run_id / name
            if path.exists():
                members[name] = path.read_bytes()
        for evidence_id, ref in ws.run_evidence(run_id):
            members[f"evidence/{evidence_id}.json"] = ws.blobs.get(ref)
        manifest = {
            "bundle": "veritas/bundle/v1",
            "run": run_id,
            "audit": {"head": row[0], "entries": row[1]},
            "files": {name: "sha256:" + hashlib.sha256(data).hexdigest() for name, data in sorted(members.items())},
        }
        with tarfile.open(out, "w:gz") as tar:
            _add(tar, "bundle.json", json.dumps(manifest, indent=2, sort_keys=True).encode())
            for name, data in sorted(members.items()):
                _add(tar, name, data)
        return out
    finally:
        ws.close()


@dataclass
class BundleCheck:
    run: str = ""
    files: int = 0
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


MAX_MEMBERS = 100_000
MAX_MEMBER = 64 * 1024 * 1024
MAX_TOTAL = 1024 * 1024 * 1024  # a bundle someone sends can't make verification exhaust memory


def verify_bundle(path: Path) -> BundleCheck:
    """Check every file hash, every evidence ID, every claim reference, and the audit chain. Nothing is extracted."""
    result = BundleCheck()
    total = 0
    with tarfile.open(path, "r:gz") as tar:
        contents = {}
        for count, member in enumerate(tar, 1):
            if count > MAX_MEMBERS:
                result.problems.append(f"more than {MAX_MEMBERS} members; the rest weren't read")
                break
            name = member.name.replace("\\", "/")
            if not member.isfile() or name.startswith(("/", "..")) or "/../" in f"/{name}/" or ":" in name:
                result.problems.append(f"unexpected member {member.name!r}")
                continue
            if member.size > MAX_MEMBER or total + member.size > MAX_TOTAL:
                result.problems.append(f"{name}: too large to verify ({member.size} bytes)")
                continue
            handle = tar.extractfile(member)
            data = handle.read(MAX_MEMBER + 1) if handle else b""
            total += len(data)
            contents[name] = data
    manifest = json.loads(contents.pop("bundle.json", b"{}") or b"{}")
    result.run = manifest.get("run", "")
    expected = manifest.get("files", {})
    for name in sorted(set(expected) | set(contents)):
        data = contents.get(name)
        if data is None:
            result.problems.append(f"{name}: listed in the manifest but missing")
        elif name not in expected:
            result.problems.append(f"{name}: present but not in the manifest")
        elif "sha256:" + hashlib.sha256(data).hexdigest() != expected[name]:
            result.problems.append(f"{name}: contents do not match the manifest")
        elif name.startswith("evidence/") and "E-" + hashlib.sha256(data).hexdigest()[:12] != Path(name).stem:
            result.problems.append(f"{name}: contents do not match the evidence ID")
    result.files = len(contents)
    findings = contents.get("findings.json")
    if findings is not None:
        bundled = {Path(name).stem for name in contents if name.startswith("evidence/")}
        try:
            document = json.loads(findings)
        except ValueError:
            result.problems.append("findings.json: not valid JSON")
        else:
            result.problems += [f"findings.json: {p}" for p in lint_document(document, bundled.__contains__)]
    audit = contents.get("audit.jsonl")
    if audit is not None:
        with tempfile.TemporaryDirectory() as tmp:
            log = Path(tmp) / "audit.jsonl"
            log.write_bytes(audit)
            head = manifest.get("audit", {})
            check = verify(log, expected_head=head.get("head") or GENESIS, expected_entries=head.get("entries"))
        result.problems += [f"audit.jsonl: {p}" for p in check.problems]
    return result
