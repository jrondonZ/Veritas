"""Replay and reproduce: re-decide recorded findings offline, or rebuild a finding's probe to rerun it."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..store import Workspace
from .checks import BY_ID, Check, OracleResult, run_oracle
from .evidence import WorkspaceEvidence
from .outcomes import AttemptResult, status_of
from .probes import Probe, Step


def load_document(ws: Workspace, run_id: str) -> dict[str, Any]:
    path = ws.runs_dir / run_id / "findings.json"
    if not path.exists():
        raise KeyError(f"run {run_id} has no findings document")
    document: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return document


def rebuild(finding: dict[str, Any]) -> tuple[Check, Probe]:
    check = BY_ID[finding["check"]]
    p = finding["probe"]
    steps = tuple(
        Step(s["id"], s["method"], s["path"], s["identity"], tuple(tuple(h) for h in s["headers"]), s["body"])
        for s in p["steps"]
    )
    return check, Probe(
        check.id, tuple(p["key"]), p["route"], p["description"], steps, tuple(p["evidence"]), p["params"]
    )


@dataclass
class ReplayRow:
    finding: str
    recorded: str
    replayed: str
    reason: str

    @property
    def matches(self) -> bool:
        return self.recorded == self.replayed


def replay(root: Path, run_id: str) -> list[ReplayRow]:
    """Re-run every oracle over the run's stored evidence; any difference is a Veritas bug."""
    ws = Workspace(root)
    try:
        document = load_document(ws, run_id)
        stored = WorkspaceEvidence(ws)
        rows = []
        for finding in document["findings"]:
            if not finding["history"]:
                continue  # blocked: nothing was sent
            check, probe = rebuild(finding)
            results: list[AttemptResult] = []
            for n, attempt in enumerate(finding["history"], 1):
                if attempt["verdict"] == "error" or None in attempt["evidence"]:
                    result = OracleResult.errored(attempt["reason"])
                else:
                    exchanges = [stored.get(e) for e in attempt["evidence"]]
                    signals = [stored.signal(s) for s in attempt.get("signals", [])]
                    result = run_oracle(check, probe, exchanges, signals, n)
                results.append(AttemptResult(n, result, [], None))
            status, reason, passes = status_of(check, results)
            recorded = f"{finding['status']} {finding['passed']}/{finding['attempts']}"
            rows.append(ReplayRow(finding["id"], recorded, f"{status} {passes}/{len(results)}", reason))
        return rows
    finally:
        ws.close()
