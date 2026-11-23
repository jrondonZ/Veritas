"""Move gateway captures into the workspace: decisions into the audit chain, exchanges into evidence."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .blobs import IntegrityError
from .workspace import Run, Workspace

EXCHANGE_MEDIA_TYPE = "application/vnd.veritas.exchange+json"
SENSOR_MEDIA_TYPE = "application/vnd.veritas.sensor+json"  # written by the kernel from a sensor's reply


@dataclass
class IngestReport:
    decisions: int
    exchanges: int


def ingest_gateway_capture(ws: Workspace, run: Run, capture_dir: Path) -> IngestReport:
    capture_dir = Path(capture_dir)
    if not capture_dir.is_dir():  # the run ended before the gateway started
        return IngestReport(0, 0)
    offset_file = capture_dir / ".ingested"
    done = int(offset_file.read_text()) if offset_file.exists() else 0
    lines = (
        (capture_dir / "decisions.jsonl").read_text(encoding="utf-8").splitlines()
        if (capture_dir / "decisions.jsonl").exists()
        else []
    )
    for line in lines[done:]:
        entry = json.loads(line)
        kind = "gateway.revoke" if entry.pop("event", None) == "revoke" else "gateway.request"
        entry["gateway_ts"] = entry.pop("ts", None)
        run.audit.append(kind, **entry)
    offset_file.write_text(str(len(lines)))

    exchanges = 0
    for path in sorted(capture_dir.glob("E-*.json")):
        evidence_id = ws.add_evidence(run.id, path.read_bytes(), EXCHANGE_MEDIA_TYPE, "gateway")
        if evidence_id != path.stem:
            raise IntegrityError(f"capture {path.name} does not match its content hash ({evidence_id})")
        exchanges += 1
    return IngestReport(len(lines) - done, exchanges)
