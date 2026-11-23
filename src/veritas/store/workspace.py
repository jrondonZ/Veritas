"""The `.veritas` workspace: SQLite index, blobs, and per-run directories with audit chains."""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .audit import AuditChain, VerifyResult, utc_now, verify
from .blobs import BlobStore

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id TEXT PRIMARY KEY,
    mode TEXT NOT NULL,
    scope_digest TEXT,
    created_at TEXT NOT NULL,
    outcome TEXT,
    audit_head TEXT,
    audit_entries INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS scope_acks (
    digest TEXT PRIMARY KEY,
    scope_name TEXT NOT NULL,
    acknowledged_at TEXT NOT NULL,
    summary TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES runs(id),  -- the first run that recorded it
    sha256 TEXT NOT NULL,
    media_type TEXT NOT NULL,
    source TEXT NOT NULL,
    created_at TEXT NOT NULL
);
-- Evidence IDs are content-derived, so equal records from different runs share one row; this links each run to all of
-- its evidence.
CREATE TABLE IF NOT EXISTS run_evidence (
    run_id TEXT NOT NULL REFERENCES runs(id),
    evidence_id TEXT NOT NULL REFERENCES evidence(id),
    PRIMARY KEY (run_id, evidence_id)
);
-- A person's approval of one clean spec version (the B5 gate), bound to its digest.
CREATE TABLE IF NOT EXISTS spec_approvals (
    run_id TEXT NOT NULL REFERENCES runs(id),
    digest TEXT NOT NULL,
    approved_at TEXT NOT NULL,
    PRIMARY KEY (run_id, digest)
);
"""


@dataclass
class Run:
    id: str
    dir: Path
    audit: AuditChain


class Workspace:
    def __init__(self, project_root: str | Path):
        self.root = Path(project_root) / ".veritas"
        self.blobs = BlobStore(self.root / "objects")
        self.runs_dir = self.root / "runs"
        fresh = not self.root.exists()
        self.root.mkdir(parents=True, exist_ok=True)
        if fresh and os.name == "posix":
            os.chmod(self.root, 0o700)  # evidence, secrets, and audit logs are for this user only
        self.runs_dir.mkdir(exist_ok=True)
        self.db = sqlite3.connect(self.root / "veritas.db", isolation_level=None, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        self.db.executescript(_SCHEMA)

    def close(self) -> None:
        self.db.close()

    # Runs -----------------------------------------------------------------

    def create_run(self, mode: str, scope_digest: str | None) -> Run:
        self.db.execute("BEGIN IMMEDIATE")
        try:
            (count,) = self.db.execute("SELECT COUNT(*) FROM runs").fetchone()
            run_id = f"r-{count + 1:04d}"
            self.db.execute(
                "INSERT INTO runs (id, mode, scope_digest, created_at) VALUES (?, ?, ?, ?)",
                (run_id, mode, scope_digest, utc_now()),
            )
            self.db.execute("COMMIT")
        except BaseException:
            self.db.execute("ROLLBACK")
            raise
        return self.open_run(run_id)

    def open_run(self, run_id: str) -> Run:
        if self.db.execute("SELECT 1 FROM runs WHERE id = ?", (run_id,)).fetchone() is None:
            raise KeyError(f"no such run: {run_id}")
        run_dir = self.runs_dir / run_id
        run_dir.mkdir(exist_ok=True)

        def on_append(entries: int, head: str) -> None:
            self.db.execute("UPDATE runs SET audit_head = ?, audit_entries = ? WHERE id = ?", (head, entries, run_id))

        return Run(run_id, run_dir, AuditChain(run_dir / "audit.jsonl", on_append))

    def set_outcome(self, run_id: str, outcome: str) -> None:
        self.db.execute("UPDATE runs SET outcome = ? WHERE id = ?", (outcome, run_id))

    def verify_run(self, run_id: str) -> VerifyResult:
        row = self.db.execute("SELECT audit_head, audit_entries FROM runs WHERE id = ?", (run_id,)).fetchone()
        if row is None:
            raise KeyError(f"no such run: {run_id}")
        path = self.runs_dir / run_id / "audit.jsonl"
        if not path.exists():
            result = VerifyResult()
            if row[1]:
                result.problems.append("audit log is missing")
            return result
        return verify(path, expected_head=row[0], expected_entries=row[1])

    # Scope acknowledgments --------------------------------------------------

    def is_acknowledged(self, scope_digest: str) -> bool:
        return self.db.execute("SELECT 1 FROM scope_acks WHERE digest = ?", (scope_digest,)).fetchone() is not None

    def acknowledge(self, scope_digest: str, scope_name: str, summary: dict[str, Any]) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO scope_acks (digest, scope_name, acknowledged_at, summary) VALUES (?, ?, ?, ?)",
            (scope_digest, scope_name, utc_now(), json.dumps(summary, sort_keys=True)),
        )

    # Spec approvals (Analyze, boundary B5) -------------------------------------

    def approve_spec(self, run_id: str, spec_digest: str) -> None:
        self.db.execute(
            "INSERT OR IGNORE INTO spec_approvals (run_id, digest, approved_at) VALUES (?, ?, ?)",
            (run_id, spec_digest, utc_now()),
        )

    def spec_approved(self, run_id: str, spec_digest: str) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM spec_approvals WHERE run_id = ? AND digest = ?", (run_id, spec_digest)
        ).fetchone()
        return row is not None

    # Evidence ---------------------------------------------------------------

    def run_evidence(self, run_id: str) -> list[tuple[str, str]]:
        """(evidence ID, blob ref) for every record a run produced, in ID order."""
        rows = self.db.execute(
            "SELECT id, sha256 FROM evidence WHERE run_id = ? OR id IN "
            "(SELECT evidence_id FROM run_evidence WHERE run_id = ?) ORDER BY id",
            (run_id, run_id),
        )
        return [(str(r[0]), str(r[1])) for r in rows]

    def evidence_ids(self, run_id: str) -> set[str]:
        return {evidence_id for evidence_id, _ in self.run_evidence(run_id)}

    def add_evidence(self, run_id: str, data: bytes, media_type: str, source: str) -> str:
        ref = self.blobs.put(data)
        evidence_id = "E-" + ref.removeprefix("sha256:")[:12]
        self.db.execute(
            "INSERT OR IGNORE INTO evidence (id, run_id, sha256, media_type, source, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (evidence_id, run_id, ref, media_type, source, utc_now()),
        )
        self.db.execute("INSERT OR IGNORE INTO run_evidence (run_id, evidence_id) VALUES (?, ?)", (run_id, evidence_id))
        return evidence_id
