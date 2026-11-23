"""The kernel's side of sensor plugins (docs/architecture.md §6.1 and §9.4 rule 6).

A sensor runs with no network and reads one read-only volume of an owned app. Around
each attempt the kernel marks the log, sends the attempt's requests, and collects the
entries that mention the attempt's markers. The kernel stores what the sensor returned
as evidence and the check's oracle decides what it means.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass

from ..plugins.host import PluginSession
from ..store import SENSOR_MEDIA_TYPE, AuditChain, Run, Workspace
from .evidence import SensorRecord

MAX_ENTRIES = 100


class SensorError(Exception):
    pass


@dataclass
class SensorSession:
    sensor_id: str  # the scope's sensor id
    kind: str
    session: PluginSession
    image: str  # image ID from the lock

    @property
    def ref(self) -> str:
        return self.session.manifest.ref


class SensorHub:
    def __init__(self, sessions: Sequence[SensorSession], ws: Workspace, run: Run):
        self.by_kind = {s.kind: s for s in sessions}
        self.ws, self.run = ws, run

    @property
    def audit(self) -> AuditChain:
        return self.run.audit

    @property
    def kinds(self) -> frozenset[str]:
        return frozenset(self.by_kind)

    def _session(self, kind: str) -> SensorSession:
        if kind not in self.by_kind:
            raise SensorError(f"no {kind} sensor is running")
        return self.by_kind[kind]

    async def mark(self, kind: str) -> int:
        reply = await self._session(kind).session.call("mark", {})
        offset = reply.get("offset")
        if not isinstance(offset, int) or offset < 0:
            raise SensorError(f"{kind} sensor returned an invalid mark")
        return offset

    async def collect(self, kind: str, markers: tuple[str, ...], since: int) -> SensorRecord:
        s = self._session(kind)
        reply = await s.session.call("collect", {"since": since, "markers": list(markers), "max_entries": MAX_ENTRIES})
        entries = reply.get("entries")
        if not isinstance(entries, list) or len(entries) > MAX_ENTRIES:
            raise SensorError(f"{kind} sensor returned an invalid entry list")
        data = SensorRecord.encode(s.ref, s.image, s.sensor_id, markers, reply)
        evidence_id = self.ws.add_evidence(self.run.id, data, SENSOR_MEDIA_TYPE, f"sensor:{s.ref}")
        self.audit.append(
            "sensor.collect",
            sensor=s.ref,
            source=s.sensor_id,
            evidence=evidence_id,
            markers=len(markers),
            entries=len(entries),
            scanned=reply.get("scanned"),
            restarted=bool(reply.get("restarted")),
        )
        return SensorRecord.from_bytes(evidence_id, data)

    async def close(self) -> None:
        for s in self.by_kind.values():
            await s.session.close()
