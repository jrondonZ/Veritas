"""Reading evidence by ID: gateway exchanges and sensor records.

Exchanges come from the gateway's capture directory while a run is live, and from
the workspace blob store afterwards. Sensor records are written by the kernel from a
sensor's reply. Either way the bytes are re-hashed and must match the content-derived
evidence ID, so a tampered record is rejected on read.
"""

from __future__ import annotations

import base64
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ..core.canonical import canonical_bytes, sha256_hex
from ..store import EXCHANGE_MEDIA_TYPE, SENSOR_MEDIA_TYPE, IntegrityError, Workspace


def _check_id(evidence_id: str, data: bytes) -> None:
    if "E-" + sha256_hex(data)[:12] != evidence_id:
        raise IntegrityError(f"evidence {evidence_id} does not match its content")


@dataclass(frozen=True)
class Exchange:
    id: str
    kind: str  # "exchange" or "login"
    tid: str | None
    target: str
    identity: str | None
    method: str
    path: str  # request target: path and query
    request_headers: tuple[tuple[str, str], ...]
    request_body: bytes
    status: int
    response_headers: tuple[tuple[str, str], ...]
    response_body: bytes

    @classmethod
    def from_bytes(cls, evidence_id: str, data: bytes) -> Exchange:
        _check_id(evidence_id, data)
        record = json.loads(data)
        req, resp = record["request"], record["response"]
        return cls(
            id=evidence_id,
            kind=record.get("kind", "exchange"),
            tid=record.get("tid"),
            target=record["target"],
            identity=record.get("identity"),
            method=req["method"],
            path=req["target"],
            request_headers=tuple((n.lower(), v) for n, v in req["headers"]),
            request_body=base64.b64decode(req["body_b64"]),
            status=resp["status"],
            response_headers=tuple((n.lower(), v) for n, v in resp["headers"]),
            response_body=base64.b64decode(resp["body_b64"]),
        )

    def header(self, name: str) -> str | None:
        return next((v for n, v in self.response_headers if n == name.lower()), None)

    def headers(self, name: str) -> list[str]:
        return [v for n, v in self.response_headers if n == name.lower()]

    def request_header(self, name: str) -> str | None:
        return next((v for n, v in self.request_headers if n == name.lower()), None)

    @property
    def content_type(self) -> str:
        return (self.header("content-type") or "").split(";")[0].strip().lower()

    @property
    def text(self) -> str:
        return self.response_body.decode("utf-8", "replace")

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def json(self) -> Any:
        try:
            return json.loads(self.response_body)
        except ValueError:
            return None


@dataclass(frozen=True)
class SensorRecord:
    """What a sensor reported after one attempt: the log entries that mention the attempt's markers.

    The entries are target-derived data, selected by a sandboxed plugin. Oracles read them; reports
    cite the record by ID and never quote its contents.
    """

    id: str
    sensor: str  # plugin ref, e.g. veritas.sensor.query-log@0.0.1
    image: str  # the sensor image's ID
    source: str  # the scope's sensor id
    markers: tuple[str, ...]
    entries: tuple[dict[str, Any], ...]
    malformed: int
    truncated: bool

    @staticmethod
    def encode(sensor: str, image: str, source: str, markers: tuple[str, ...], reply: dict[str, Any]) -> bytes:
        """The canonical bytes of a record; the evidence ID is derived from them."""
        return canonical_bytes(
            {
                "v": 1,
                "kind": "sensor",
                "sensor": sensor,
                "image": image,
                "source": source,
                "markers": sorted(markers),
                "entries": list(reply.get("entries") or []),
                "malformed": int(reply.get("malformed") or 0),
                "truncated": bool(reply.get("truncated")),
            }
        )

    @classmethod
    def from_bytes(cls, evidence_id: str, data: bytes) -> SensorRecord:
        _check_id(evidence_id, data)
        record = json.loads(data)
        if record.get("kind") != "sensor":
            raise IntegrityError(f"evidence {evidence_id} is not a sensor record")
        entries = tuple(e for e in record["entries"] if isinstance(e, dict))
        return cls(
            id=evidence_id,
            sensor=record["sensor"],
            image=record["image"],
            source=record["source"],
            markers=tuple(record["markers"]),
            entries=entries,
            malformed=int(record["malformed"]),
            truncated=bool(record["truncated"]),
        )


class EvidenceSource(Protocol):
    def get(self, evidence_id: str) -> Exchange: ...


class CaptureEvidence:
    """Evidence written by the gateway during a live run (its capture directory is bind-mounted)."""

    def __init__(self, capture_dir: Path, wait: float = 3.0):
        self.dir = Path(capture_dir)
        self.wait = wait  # a bind mount may surface a just-written file a moment later

    def get(self, evidence_id: str) -> Exchange:
        path = self.dir / f"{evidence_id}.json"
        deadline = time.monotonic() + self.wait
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        return Exchange.from_bytes(evidence_id, path.read_bytes())

    def logins(self) -> dict[str, str]:
        """Identity -> evidence ID of its successful gateway sign-in."""
        path = self.dir / "decisions.jsonl"
        found: dict[str, str] = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                entry = json.loads(line)
                if entry.get("verdict") == "login" and entry.get("code") == "ok" and entry.get("evidence"):
                    found.setdefault(entry["identity"], entry["evidence"])
        return found


class WorkspaceEvidence:
    """Evidence after a run, from the workspace blob store."""

    def __init__(self, ws: Workspace):
        self.ws = ws

    def _load(self, evidence_id: str, media_type: str) -> bytes:
        row = self.ws.db.execute("SELECT sha256, media_type FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        if row is None:
            raise KeyError(f"no such evidence: {evidence_id}")
        if row[1] != media_type:
            raise KeyError(f"evidence {evidence_id} is {row[1]}, not {media_type}")
        data: bytes = self.ws.blobs.get(row[0])
        return data

    def media_type(self, evidence_id: str) -> str | None:
        row = self.ws.db.execute("SELECT media_type FROM evidence WHERE id = ?", (evidence_id,)).fetchone()
        return None if row is None else str(row[0])

    def get(self, evidence_id: str) -> Exchange:
        return Exchange.from_bytes(evidence_id, self._load(evidence_id, EXCHANGE_MEDIA_TYPE))

    def signal(self, evidence_id: str) -> SensorRecord:
        return SensorRecord.from_bytes(evidence_id, self._load(evidence_id, SENSOR_MEDIA_TYPE))
