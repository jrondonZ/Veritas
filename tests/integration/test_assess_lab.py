"""Phase 1 acceptance: CI-mode runs against the vuln-notes lab match the ground truth, deterministically.

Needs Docker and the lab scope acknowledged by the operator in a terminal:
    veritas scope check labs/vuln-notes/veritas.scope.yaml
The test never acknowledges a scope or approves a probe itself. In CI mode nobody can approve,
so the sensitive mass-assignment probe must end blocked; approving it is a manual check at the terminal.
"""

import asyncio
import json
import time

import pytest

from veritas.assess.bundle import export, verify_bundle
from veritas.assess.envelopes import audit_envelopes
from veritas.assess.replay import replay
from veritas.assess.runner import RunOptions, assess
from veritas.documents import load_yaml
from veritas.environments import Lab
from veritas.sandbox import docker
from veritas.scope import check_scope
from veritas.store import Workspace

pytestmark = pytest.mark.docker
SCOPE = "labs/vuln-notes/veritas.scope.yaml"
RUNS = 3
BUDGET_SECONDS = 300


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
    lab.up()  # rebuilds from the current source when it changed, so the test never runs a stale lab
    return lab


def expected(truth):
    rows = {}
    for item in truth["planted"]:
        if item.get("implemented"):
            rows[item["id"]] = (
                (item["match"]["check"], item["match"]["route"]),
                item.get("expected_ci", item["expected"]),
            )
    for item in truth["negative_controls"]:
        if item.get("implemented", True) and "match" in item:
            rows[item["id"]] = ((item["match"]["check"], item["match"]["route"]), item["expected"])
    return rows


def test_ci_runs_match_the_ground_truth_deterministically(repo_root, lab_ready, tmp_path):
    truth = expected(load_yaml(repo_root / "labs" / "vuln-notes" / "expected-findings.yaml"))
    network = json.loads(docker("network", "inspect", "vrt-lab-vuln-notes"))[0]
    assert network["Internal"] is True  # the lab, and the gateway's side of it, have no route out

    signatures = []
    for _ in range(RUNS):
        started = time.monotonic()
        result = asyncio.run(assess(repo_root / SCOPE, repo_root, RunOptions(attempts=3, models=False)))
        seconds = time.monotonic() - started
        by_route = {(f.check, f.route): f for f in result.findings}
        print(f"\n{result.run_id}: {result.outcome} in {seconds:.0f}s · {result.document['summary']}")

        assert result.outcome == "completed_with_gaps", result.document["message"]  # L5 is blocked in CI
        assert result.leftovers == []
        assert seconds < BUDGET_SECONDS
        assert result.document["lint"]["problems"] == []  # every claim is typed and every reference resolves
        for item_id, (key, status) in truth.items():
            finding = by_route.get(key)
            assert finding is not None, f"{item_id}: no probe for {key}"
            assert finding.status == status, f"{item_id}: {finding.status} ({finding.reason}), expected {status}"
        expected_confirmed = {key for key, status in truth.values() if status == "confirmed"}
        assert {k for k, f in by_route.items() if f.status == "confirmed"} == expected_confirmed

        run_dir = repo_root / ".veritas" / "runs" / result.run_id
        assert audit_envelopes(run_dir / "audit.jsonl") == []
        assert all(row.matches for row in replay(repo_root, result.run_id))
        signatures.append(sorted((f.fingerprint, f.status, f.passed, f.attempts) for f in result.findings))

    assert all(s == signatures[0] for s in signatures)
    bundle = export(repo_root, result.run_id, tmp_path / "run.tar.gz")
    assert verify_bundle(bundle).ok
