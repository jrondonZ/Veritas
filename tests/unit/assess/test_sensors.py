"""The kernel's side of sensors, with a stand-in for the sensor plugin."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from veritas.assess.evidence import WorkspaceEvidence
from veritas.assess.sensors import SensorError, SensorHub, SensorSession
from veritas.store import Workspace


class FakeSensor:
    manifest = SimpleNamespace(ref="veritas.sensor.query-log@0.0.1")

    def __init__(self, replies):
        self.replies, self.calls, self.closed = replies, [], False

    async def call(self, op, args):
        self.calls.append((op, args))
        return self.replies[op]

    async def close(self):
        self.closed = True


ENTRY = {"sql": "SELECT id FROM notes WHERE title LIKE '%vrt-mk-a-1%'", "params": []}
COLLECTED = {"entries": [ENTRY], "scanned": 3, "malformed": 0, "truncated": False, "restarted": False, "offset": 99}


@pytest.fixture
def workspace(tmp_path):
    ws = Workspace(tmp_path)
    yield ws, ws.create_run("assess", "sha256:test")
    ws.close()


def test_hub_records_what_the_sensor_returned(workspace):
    ws, run = workspace
    plugin = FakeSensor({"mark": {"offset": 7}, "collect": COLLECTED})
    hub = SensorHub([SensorSession("queries", "query-log", plugin, "sha256:image")], ws, run)

    async def main():
        since = await hub.mark("query-log")
        record = await hub.collect("query-log", ("vrt-mk-a-1",), since)
        await hub.close()
        return since, record

    since, record = asyncio.run(main())
    assert since == 7
    assert plugin.calls[1] == ("collect", {"since": 7, "markers": ["vrt-mk-a-1"], "max_entries": 100})
    assert (record.entries, record.source, record.image) == ((ENTRY,), "queries", "sha256:image")
    assert WorkspaceEvidence(ws).signal(record.id) == record
    assert WorkspaceEvidence(ws).media_type(record.id) == "application/vnd.veritas.sensor+json"
    event = json.loads((run.dir / "audit.jsonl").read_text().splitlines()[-1])
    assert (event["type"], event["evidence"], event["scanned"]) == ("sensor.collect", record.id, 3)
    assert plugin.closed


def test_equal_sensor_output_gives_equal_evidence(workspace):
    ws, run = workspace
    hub = SensorHub([SensorSession("queries", "query-log", FakeSensor({"collect": COLLECTED}), "sha256:i")], ws, run)
    first = asyncio.run(hub.collect("query-log", ("vrt-mk-a-1",), 0))
    later = asyncio.run(hub.collect("query-log", ("vrt-mk-a-1",), 50))
    assert first.id == later.id  # offsets and scan counts go to the audit log, not into the evidence


def test_hub_refuses_unknown_sensors_and_bad_replies(workspace):
    ws, run = workspace
    bad = FakeSensor({"mark": {"offset": -1}, "collect": {"entries": "everything"}})
    hub = SensorHub([SensorSession("queries", "query-log", bad, "sha256:i")], ws, run)
    with pytest.raises(SensorError, match="no app-log sensor"):
        asyncio.run(hub.mark("app-log"))
    with pytest.raises(SensorError, match="invalid mark"):
        asyncio.run(hub.mark("query-log"))
    with pytest.raises(SensorError, match="invalid entry list"):
        asyncio.run(hub.collect("query-log", ("vrt-mk-a-1",), 0))
