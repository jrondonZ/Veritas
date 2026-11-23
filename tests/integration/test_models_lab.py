"""Phase 2 acceptance with models on: models change no finding's status, and a running model has no network.

Needs Docker, the model-server image, registered weights with a model on the `analysis` route,
and (for the lab test) the vuln-notes scope acknowledged by the operator in a terminal:
    veritas models add <file.gguf>
    veritas models route analysis <name>
    veritas scope check labs/vuln-notes/veritas.scope.yaml
The tests never register weights, choose routes, or acknowledge a scope themselves.
"""

import asyncio
import json
import secrets

import pytest

from veritas.assess.runner import RunOptions, assess
from veritas.environments import Lab
from veritas.models import RouteUnavailable, load_models, load_routing
from veritas.sandbox import docker, read_lock
from veritas.sandbox.images import MODEL_IMAGE
from veritas.sandbox.model import ModelSandbox
from veritas.scope import check_scope
from veritas.store import Workspace

pytestmark = pytest.mark.docker
SCOPE = "labs/vuln-notes/veritas.scope.yaml"


@pytest.fixture(scope="module")
def analysis_model(repo_root, docker_engine):
    lock = read_lock(repo_root)
    image = lock.get("images", {}).get(MODEL_IMAGE)
    if image is None:
        pytest.skip("the model-server image isn't built: veritas images build --models")
    routing = load_routing(repo_root, load_models(lock))
    try:
        served = routing.resolve("analysis")
    except RouteUnavailable as exc:
        pytest.skip(f"no model serves the analysis route ({exc})")
    return served.model, image, routing


def test_a_running_model_has_no_network(analysis_model):
    model, image, routing = analysis_model
    sandbox = ModelSandbox(
        f"it-{secrets.token_hex(3)}", image, model.file, routing.profile.limits_for(model), model.name
    )
    sandbox.up()
    try:
        (inspect,) = json.loads(docker("inspect", sandbox.name))
        assert inspect["HostConfig"]["NetworkMode"] == "none"
        interfaces = docker("exec", sandbox.name, "cat", "/proc/net/dev")
        assert [n.split(":")[0].strip() for n in interfaces.splitlines()[2:]] == ["lo"]  # loopback only
        attempt = docker("exec", sandbox.name, "bash", "-c",
                         "timeout 5 bash -c 'exec 3<>/dev/tcp/1.1.1.1/53' && echo connected || echo refused",
                         check=False)  # fmt: skip
        assert "connected" not in attempt
    finally:
        sandbox.down()


@pytest.fixture(scope="module")
def lab_ready(repo_root, images):
    report = check_scope(repo_root / SCOPE)
    ws = Workspace(repo_root)
    try:
        if not ws.is_acknowledged(report.digest):
            pytest.skip(f"acknowledge the lab scope in a terminal first: veritas scope check {SCOPE}")
    finally:
        ws.close()
    lab = Lab("vuln-notes", repo_root)
    lab.up()
    return lab


def test_models_change_no_finding_status(repo_root, lab_ready, analysis_model):
    rules = asyncio.run(assess(repo_root / SCOPE, repo_root, RunOptions(attempts=3, models=False)))
    lab_ready.reset()
    enriched = asyncio.run(assess(repo_root / SCOPE, repo_root, RunOptions(attempts=3, models=True)))
    assert enriched.document["models"]["status"] == "on", enriched.document["models"]
    statuses = lambda result: {(f.check, f.route): f.status for f in result.findings}  # noqa: E731
    assert statuses(enriched) == statuses(rules)  # models describe findings; they never decide them
    assert enriched.document["lint"]["problems"] == []  # every model claim is typed and cites what it rests on
    events = [json.loads(e)["type"] for e in
              (repo_root / ".veritas" / "runs" / enriched.run_id / "audit.jsonl").read_text().splitlines()]  # fmt: skip
    assert {"model.start", "model.call", "model.stop"} <= set(events)
