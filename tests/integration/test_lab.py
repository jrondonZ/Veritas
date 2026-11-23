"""Lab lifecycle: isolated, resettable, observable by its sensor, and leaves nothing behind (pytest -m docker)."""

import asyncio
import json

import pytest

from veritas.environments import Lab
from veritas.gateway.admission import GatewayConfig
from veritas.plugins.host import start_plugin
from veritas.plugins.manifest import load_manifest
from veritas.sandbox import SENSOR_IMAGE, RunSandbox, docker, remove_labeled

pytestmark = pytest.mark.docker
INSERT_NOTE = (
    "import('node:sqlite').then(({DatabaseSync}) => { const db = new DatabaseSync('/data/notes.db');"
    " db.prepare(\"INSERT INTO notes (owner_id, title, body) VALUES (1, 'scratch', 'x')\").run(); db.close(); })"
)
MARKER = "vrt-mk-lifecycle-1"
# A failed sign-in: the app looks the address up with a bound parameter, and the marker rides in it.
SIGN_IN = (
    "fetch('http://127.0.0.1:8080/api/login', {method: 'POST', headers: {'content-type': "
    f"'application/x-www-form-urlencoded'}}, body: 'email={MARKER}%40lab.test&password=x'}})"
    ".then((r) => console.log(r.status))"
)


async def sensor_entries(argv, manifest):
    session = await start_plugin(argv, manifest)
    try:
        reply = await session.call("collect", {"since": 0, "markers": [MARKER]})
    finally:
        await session.close()
    return reply["entries"]


def test_lab_lifecycle(docker_engine, images, repo_root, tmp_path):
    lab = Lab("vuln-notes", repo_root)
    sandbox = RunSandbox("lab-test", tmp_path, "", GatewayConfig(run="lab-test", targets=[]), b"")
    manifest = load_manifest(repo_root / "plugins" / "query-log-sensor" / "veritas-plugin.yaml")
    argv = sandbox.sensor_argv(images[SENSOR_IMAGE], manifest, "queries", lab.volume("query-log"), "/inputs/query-log")
    try:
        assert lab.up() == {"ok": True, "users": 2, "notes": 6}

        network = json.loads(docker("network", "inspect", "vrt-lab-vuln-notes"))[0]
        assert network["Internal"] is True
        container = lab.compose("ps", "-q", lab.service)
        bindings = json.loads(docker("inspect", "--format", "{{json .HostConfig.PortBindings}}", container))
        assert not bindings, bindings
        host_config = json.loads(docker("inspect", "--format", "{{json .HostConfig}}", container))
        assert host_config["ReadonlyRootfs"] is True
        assert host_config["CapDrop"] == ["ALL"]

        # The app logs each statement and its bound parameters; the sensor reads them with no network.
        assert lab.compose("exec", "-T", lab.service, "node", "-e", SIGN_IN) == "401"
        expected = {"sql": "SELECT * FROM users WHERE email = ?", "params": [f"{MARKER}@lab.test"]}
        assert asyncio.run(sensor_entries(argv, manifest)) == [expected]
        assert argv[argv.index("--network") + 1] == "none"

        lab.compose("exec", "-T", lab.service, "node", "-e", INSERT_NOTE)
        assert lab.health()["notes"] == 7
        assert lab.reset()["notes"] == 6
        assert asyncio.run(sensor_entries(argv, manifest)) == []  # a reset empties the query log
    finally:
        leftovers = lab.down() + remove_labeled("lab-test")
    assert leftovers == []
