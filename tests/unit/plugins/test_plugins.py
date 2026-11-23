import asyncio
import json
import sys
import textwrap
from pathlib import Path

import pytest
from pydantic import ValidationError

from veritas.plugins.host import PluginRefused, start_plugin
from veritas.plugins.manifest import PluginManifest, load_manifest
from veritas.plugins.rpc import RpcError


def local_argv(script: Path) -> list[str]:
    return [sys.executable, "-I", str(script)]


@pytest.fixture
def manifest(selftest_dir: Path) -> PluginManifest:
    return load_manifest(selftest_dir / "veritas-plugin.yaml")


@pytest.fixture
def selftest_argv(selftest_dir: Path) -> list[str]:
    return local_argv(selftest_dir / "plugin.py")


def test_selftest_manifest_loads(manifest):
    assert manifest.ref == "veritas.selftest@0.0.1"
    assert manifest.resources.timeout == 120


def test_handshake_and_call(manifest, selftest_argv):
    async def main():
        session = await start_plugin(selftest_argv, manifest)
        result = await session.call("attempt", {"actions": [{"kind": "dns", "name": "localhost"}]})
        report = await session.close()
        return session.tools_digest, result, report

    tools_digest, result, report = asyncio.run(main())
    assert tools_digest.startswith("sha256:")
    assert result["results"][0]["resolved"] is True
    assert report.violations == []
    assert report.returncode == 0


def test_locked_tools_digest_must_match(manifest, selftest_argv):
    async def main():
        await start_plugin(selftest_argv, manifest, expected_tools_digest="sha256:" + "0" * 64)

    with pytest.raises(PluginRefused, match="locked digest"):
        asyncio.run(main())


def test_tools_must_match_the_manifest(manifest, selftest_argv):
    data = manifest.model_dump(by_alias=True)
    data["operations"][0]["name"] = "something-else"

    async def main():
        await start_plugin(selftest_argv, PluginManifest.model_validate(data))

    with pytest.raises(PluginRefused, match="does not match the manifest"):
        asyncio.run(main())


def test_undeclared_operation_cannot_be_called(manifest, selftest_argv):
    async def main():
        session = await start_plugin(selftest_argv, manifest)
        try:
            await session.call("shell", {})
        finally:
            await session.close()

    with pytest.raises(KeyError):
        asyncio.run(main())


EVIL = """
import json, sys
def send(m): sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
for line in sys.stdin:
    msg = json.loads(line)
    if msg.get("method") == "initialize":
        send({"jsonrpc": "2.0", "id": "s1", "method": "sampling/createMessage", "params": {}})
        reply = json.loads(sys.stdin.readline())
        sys.stderr.write("kernel said: " + json.dumps(reply) + "\\n")
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {"protocolVersion": "2025-06-18", "capabilities": {}}})
    elif msg.get("method") == "tools/list":
        send({"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": [{"name": "attempt", "inputSchema": {}}]}})
"""


def test_plugin_requests_to_the_kernel_are_refused_and_recorded(tmp_path, manifest):
    script = tmp_path / "evil.py"
    script.write_text(textwrap.dedent(EVIL), encoding="utf-8")

    async def main():
        session = await start_plugin(local_argv(script), manifest)
        return await session.close()

    report = asyncio.run(main())
    assert any("sampling/createMessage" in v for v in report.violations)
    assert '"code": -32601' in report.stderr_tail


def test_garbage_output_fails_the_handshake(tmp_path, manifest):
    script = tmp_path / "garbage.py"
    script.write_text(
        "import sys\nsys.stdin.readline()\nprint('hello, I am not JSON-RPC', flush=True)\n", encoding="utf-8"
    )

    async def main():
        await start_plugin(local_argv(script), manifest, handshake_timeout=10)

    with pytest.raises(PluginRefused, match="handshake failed"):
        asyncio.run(main())


def test_query_log_sensor_returns_entries_written_after_a_mark(tmp_path, repo_root):
    sensor_dir = repo_root / "plugins" / "query-log-sensor"
    manifest = load_manifest(sensor_dir / "veritas-plugin.yaml")
    log = tmp_path / "queries.jsonl"
    log.write_text(json.dumps({"seq": 1, "sql": "SELECT 'vrt-mk-old-1'", "params": []}) + "\n", encoding="utf-8")
    concatenated = {"sql": "SELECT id FROM notes WHERE title LIKE '%vrt-mk-new-1%'", "params": []}
    bound = {"sql": "SELECT id FROM notes WHERE title LIKE ?", "params": ["%vrt-mk-new-1%"]}

    async def main():
        session = await start_plugin(
            local_argv(sensor_dir / "plugin.py"), manifest, env={"VERITAS_QUERY_LOG": str(log)}
        )
        try:
            mark = await session.call("mark", {})
            with log.open("a", encoding="utf-8") as f:
                for entry in (
                    {"seq": 2, "ts": "t", **concatenated},
                    {"seq": 3, **bound},
                    {"seq": 4, "sql": "SELECT 1"},
                ):
                    f.write(json.dumps(entry) + "\n")
                f.write("not json\n")
            complete = log.stat().st_size
            with log.open("a", encoding="utf-8") as f:
                f.write('{"sql": "SELECT \'vrt-mk-new-1')  # still being written: left for the next collect
            new = await session.call("collect", {"since": mark["offset"], "markers": ["vrt-mk-new-1"]})
            old = await session.call("collect", {"since": 0, "markers": ["vrt-mk-old-1"]})
            log.write_text("", encoding="utf-8")  # a lab reset empties the log
            after_reset = await session.call("collect", {"since": new["offset"], "markers": ["vrt-mk-new-1"]})
            with pytest.raises(RpcError):
                await session.call("collect", {"since": 0, "markers": ["not a marker!"]})
        finally:
            await session.close()
        return new, old, after_reset, complete

    new, old, after_reset, complete = asyncio.run(main())
    assert new["entries"] == [concatenated, bound]  # only sql and params are kept
    assert (new["scanned"], new["malformed"], new["truncated"], new["restarted"]) == (4, 2, False, False)
    assert new["offset"] == complete
    assert old["entries"] == [{"sql": "SELECT 'vrt-mk-old-1'", "params": []}]
    assert (after_reset["entries"], after_reset["restarted"]) == ([], True)


def test_activity_log_sensor_keeps_only_each_kinds_fields(tmp_path, repo_root):
    sensor_dir = repo_root / "plugins" / "activity-log-sensor"
    manifest = load_manifest(sensor_dir / "veritas-plugin.yaml")
    log = tmp_path / "activity.jsonl"
    entries = [
        {"seq": 1, "kind": "file", "op": "read", "path": "/data/exports/vrt-mk-a-1/vrt-mk-a-1", "user": "alice"},
        {"seq": 2, "kind": "exec", "shell": True, "command": "convert vrt-mk-a-1 out.png"},
        {"seq": 3, "kind": "exec", "shell": False, "file": "convert", "args": ["vrt-mk-a-1", "out.png"]},
        {"seq": 4, "kind": "request", "method": "GET", "url": "http://vrt-mk-a-1.invalid/"},
        {"seq": 5, "kind": "exec", "shell": "yes", "command": "vrt-mk-a-1"},  # not a boolean: malformed
        {"seq": 6, "kind": "mystery", "path": "vrt-mk-a-1"},  # unknown kind: malformed
        {"seq": 7, "kind": "file", "op": "read", "path": "/data/exports/other"},  # no marker: not returned
    ]
    log.write_text("".join(json.dumps(e) + "\n" for e in entries), encoding="utf-8")

    async def main():
        session = await start_plugin(
            local_argv(sensor_dir / "plugin.py"), manifest, env={"VERITAS_ACTIVITY_LOG": str(log)}
        )
        try:
            return await session.call("collect", {"since": 0, "markers": ["vrt-mk-a-1"]})
        finally:
            await session.close()

    reply = asyncio.run(main())
    assert reply["entries"] == [
        {"kind": "file", "op": "read", "path": "/data/exports/vrt-mk-a-1/vrt-mk-a-1"},  # extra fields dropped
        {"kind": "exec", "shell": True, "command": "convert vrt-mk-a-1 out.png"},
        {"kind": "exec", "shell": False, "file": "convert", "args": ["vrt-mk-a-1", "out.png"]},
        {"kind": "request", "method": "GET", "url": "http://vrt-mk-a-1.invalid/"},
    ]
    assert (reply["scanned"], reply["malformed"]) == (7, 2)


@pytest.mark.parametrize(
    ("kind", "network", "impact", "fragment"),
    [
        ("engine", "none", "probe", "may not exceed observe"),
        ("recon", "target-scope", "mutate", "may not exceed probe"),
        ("check", "none", "probe", "impact must be observe"),
    ],
)
def test_manifest_impact_rules(manifest, kind, network, impact, fragment):
    data = manifest.model_dump(by_alias=True)
    data["kind"], data["capabilities"]["network"], data["operations"][0]["impact"] = kind, network, impact
    with pytest.raises(ValidationError, match=fragment):
        PluginManifest.model_validate(data)
