"""Gate, approvals, outcomes, envelope audit, replay, and bundles, without Docker."""

import base64
import json

import pytest

from veritas.assess.bundle import export, verify_bundle
from veritas.assess.checks import CHECKS, OracleResult
from veritas.assess.checks.mass_assignment import MassAssignment
from veritas.assess.checks.reflected_html import ReflectedHtml
from veritas.assess.envelopes import audit_envelopes
from veritas.assess.evidence import SensorRecord
from veritas.assess.outcomes import AttemptResult, build_finding, number, status_of
from veritas.assess.policy import ApprovalRequest, decide, deny_all, terminal_approver
from veritas.assess.probes import Probe, Step, envelope
from veritas.assess.replay import replay
from veritas.assess.runner import RunOptions, _gate
from veritas.core.canonical import canonical_bytes, sha256_hex
from veritas.core.impact import Impact
from veritas.scope import check_scope
from veritas.store import EXCHANGE_MEDIA_TYPE, SENSOR_MEDIA_TYPE, Workspace


@pytest.fixture
def scope(repo_root):
    return check_scope(repo_root / "labs" / "vuln-notes" / "veritas.scope.yaml").scope


def test_policy_matrix(scope):
    assert decide(Impact.PROBE, scope, []).verdict == "allow"
    assert decide(Impact.MUTATE, scope, []).verdict == "allow"  # disposable lab with a reset
    assert decide(Impact.SENSITIVE, scope, []).verdict == "needs_approval"
    assert decide(Impact.PROBE, scope, ["DELETE /x"]).verdict == "deny"


def test_envelope_grants_exact_counts():
    steps = (Step("a", "GET", "/api/p", "alice"), Step("b", "PUT", "/api/p", "alice"), Step("c", "GET", "/api/p?x=1"))
    grants = {(g.methods[0], g.paths[0]): (g.max_requests, g.identities) for g in envelope(steps, "web")}
    assert grants == {("GET", "/api/p"): (2, ["alice"]), ("PUT", "/api/p"): (1, ["alice"])}


def test_gate_batches_approvals_and_blocks_without_them(tmp_path, scope):
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", "sha256:test")
    check = MassAssignment()
    probe = Probe(
        check.id,
        ("PUT", "/api/profile", "role", "write"),
        "PUT /api/profile",
        "write a sentinel",
        (Step("w", "PUT", "/api/profile", "alice"),),
    )
    (blocked,) = _gate([(check, probe)], scope, "sha256:test", run, RunOptions(approver=deny_all))
    assert not blocked.runs
    assert "A-0001 was not granted" in blocked.decision.reason
    seen = []
    (approved,) = _gate(
        [(check, probe)], scope, "sha256:test", run, RunOptions(approver=lambda r: seen.append(r) or True)
    )
    assert approved.approval == "A-0001"
    assert seen[0].digest.startswith("sha256:")
    events = [json.loads(line)["type"] for line in (run.dir / "audit.jsonl").read_text().splitlines()]
    assert events == ["approval.requested", "approval.denied", "approval.requested", "approval.granted"]
    ws.close()


def test_terminal_approver_requires_typing_the_id_for_sensitive_actions():
    request = ApprovalRequest("A-0007", "r-1", "c", Impact.SENSITIVE, (Probe("c", ("k",), "r", "d"),), 3, "sha256:x")
    shown = []
    assert terminal_approver(shown.append, lambda q: "A-0007")(request) is True
    assert terminal_approver(shown.append, lambda q: "y")(request) is False
    assert shown[0].startswith("APPROVAL A-0007")


def test_status_of_and_numbering(exchange, target, identities):
    check = ReflectedHtml()
    passed, failed = OracleResult.passed("ok"), OracleResult.failed("no")

    def attempt(n, result):
        return AttemptResult(n, result, [], None)

    assert status_of(check, [attempt(1, passed)] * 3)[:2] == ("confirmed", "ok")
    assert status_of(check, [attempt(1, passed), attempt(2, failed)])[0] == "confirmed"  # decisive oracle
    assert status_of(check, [attempt(1, failed)])[0] == "rejected"
    assert status_of(check, [attempt(1, OracleResult.ambiguous("?"))])[0] == "inconclusive"
    assert status_of(check, [attempt(1, OracleResult.errored("refused"))])[0] == "error"

    from veritas.assess.checks import PlanContext

    ctx = PlanContext(target, identities, "t")
    probe = Probe(check.id, ("GET", "/search", "q", "html"), "GET /search", "d", (Step("s", "GET", "/search?q=x"),))
    page = exchange(body="<vrt-mk-a>", headers=[("Content-Type", "text/html")])
    result = check.evaluate(Probe(check.id, (), "", "", params={"marker": "vrt-mk-a", "param": "q"}), [page], 1)
    finding = build_finding(check, probe, [AttemptResult(1, result, [page], "t-0001")], ctx)
    (numbered,) = number([finding])
    assert numbered.id == "F-0001"
    assert numbered.severity == "medium"
    assert numbered.cvss["score"] == 6.1
    inferred = [c for c in numbered.claims if c.kind == "inferred"]
    assert inferred[0].based_on == [c.id for c in numbered.claims if c.kind == "observed"]


def test_envelope_audit_flags_requests_outside_their_script(tmp_path):
    log = tmp_path / "audit.jsonl"
    entries = [
        {"type": "task.start", "tid": "t-0001", "requests": ["GET /a as alice"]},
        {"type": "gateway.request", "verdict": "allow", "tid": "t-0001", "method": "GET", "uri": "http://h:1/a"},
        {"type": "gateway.request", "verdict": "allow", "tid": "t-0001", "method": "GET", "uri": "http://h:1/a"},
        {"type": "gateway.request", "verdict": "deny", "tid": "t-0001", "method": "GET", "uri": "http://h:1/b"},
        {"type": "gateway.request", "verdict": "allow", "tid": "t-0009", "method": "GET", "uri": "http://h:1/a"},
    ]
    log.write_text("\n".join(json.dumps(e) for e in entries))
    assert audit_envelopes(log) == [
        "t-0001: allowed GET /a beyond its declared script",
        "t-0009: allowed GET /a with no declared script",
    ]


def _record(body: str) -> bytes:
    return canonical_bytes(
        {
            "v": 1,
            "kind": "exchange",
            "tid": "t-0001",
            "target": "web",
            "identity": None,
            "request": {"method": "GET", "authority": "h", "target": "/search?q=x", "headers": [], "body_b64": ""},
            "response": {
                "status": 200,
                "reason": "OK",
                "headers": [["content-type", "text/html"]],
                "body_b64": base64.b64encode(body.encode()).decode(),
            },
        }
    )


def test_replay_and_bundle_round_trip(tmp_path):
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", "sha256:test")
    data = _record("<p><vrt-mk-a></p>")
    evidence_id = ws.add_evidence(run.id, data, "application/vnd.veritas.exchange+json", "gateway")
    assert evidence_id == "E-" + sha256_hex(data)[:12]
    run.audit.append("run.start")
    finding = {
        "id": "F-0001",
        "check": CHECKS[1].id,
        "status": "confirmed",
        "passed": 1,
        "attempts": 1,
        "probe": {
            "key": ["GET", "/search", "q", "html"],
            "route": "GET /search",
            "description": "d",
            "evidence": [],
            "params": {"marker": "vrt-mk-a", "param": "q"},
            "steps": [{"id": "s", "method": "GET", "path": "/search?q=x", "identity": None, "headers": [], "body": ""}],
        },
        "history": [{"verdict": "pass", "reason": "ok", "evidence": [evidence_id], "tid": "t-0001"}],
        "claims": confirmed_claims(evidence_id),
        "cvss": {"version": "3.1", "vector": CHECKS[1].info.cvss, "score": 6.1},
    }
    (run.dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    ws.close()
    (row,) = replay(tmp_path, run.id)
    assert row.matches
    bundle = export(tmp_path, run.id, tmp_path / "b.tar.gz")
    assert verify_bundle(bundle).ok
    (run.dir / "findings.json").write_text("{}")  # bundles are self-contained: later edits don't matter
    assert verify_bundle(bundle).ok


def confirmed_claims(*evidence):
    return [
        {"id": "C-0001", "kind": "observed", "text": "seen", "evidence": list(evidence), "based_on": []},
        {"id": "C-0002", "kind": "inferred", "text": "likely", "evidence": [], "based_on": ["C-0001"]},
        {"id": "C-0003", "kind": "guidance", "text": "fix it", "evidence": [], "based_on": []},
    ]


def test_bundle_verification_rejects_claims_whose_references_do_not_resolve(tmp_path):
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", "sha256:test")
    evidence_id = ws.add_evidence(run.id, _record("<p>x</p>"), EXCHANGE_MEDIA_TYPE, "gateway")
    claims = confirmed_claims(evidence_id, "E-000000000000")
    finding = {"id": "F-0001", "status": "confirmed", "claims": claims, "cvss": {"score": 6.1}}
    (run.dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    ws.close()
    problems = verify_bundle(export(tmp_path, run.id, tmp_path / "b.tar.gz")).problems
    assert problems == [
        "findings.json: F-0001 C-0001: evidence 'E-000000000000' does not resolve to a record of this run "
        "(reference.evidence)",
        "findings.json: F-0001 C-0002: based_on 'C-0001' is not an earlier, supported claim of this finding "
        "(reference.claim)",
    ]


def test_equal_evidence_from_two_runs_belongs_to_both(tmp_path):
    ws = Workspace(tmp_path)
    first, second = ws.create_run("assess", "sha256:test"), ws.create_run("assess", "sha256:test")
    data = _record("<p>same</p>")
    assert ws.add_evidence(first.id, data, EXCHANGE_MEDIA_TYPE, "gateway") == ws.add_evidence(
        second.id, data, EXCHANGE_MEDIA_TYPE, "gateway"
    )
    assert ws.evidence_ids(first.id) == ws.evidence_ids(second.id) == {"E-" + sha256_hex(data)[:12]}
    ws.close()


def test_replay_re_decides_sensor_findings_from_stored_records(tmp_path):
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", "sha256:test")
    exchange_id = ws.add_evidence(run.id, _record("[]"), EXCHANGE_MEDIA_TYPE, "gateway")
    entry = {"sql": "SELECT id FROM notes WHERE title LIKE '%vrt-mk-q-1%'", "params": []}
    data = SensorRecord.encode(
        "veritas.sensor.query-log@0.0.1", "sha256:i", "queries", ("vrt-mk-q-1",), {"entries": [entry]}
    )
    sensor_id = ws.add_evidence(run.id, data, SENSOR_MEDIA_TYPE, "sensor:veritas.sensor.query-log@0.0.1")
    run.audit.append("run.start")
    finding = {
        "id": "F-0001",
        "check": "veritas.check.sql-string-built",
        "status": "confirmed",
        "passed": 1,
        "attempts": 1,
        "probe": {
            "key": ["GET", "/api/search", "q", "sql-text"],
            "route": "GET /api/search",
            "description": "d",
            "evidence": [],
            "params": {"canary": "vrt-mk-q", "param": "q", "path": "/api/search", "identity": "alice"},
            "steps": [
                {
                    "id": "canary",
                    "method": "GET",
                    "path": "/api/search?q=vrt-mk-q-1",
                    "identity": "alice",
                    "headers": [],
                    "body": "",
                }
            ],
        },
        "history": [
            {"verdict": "pass", "reason": "r", "evidence": [exchange_id], "tid": "t-0001", "signals": [sensor_id]}
        ],
        "claims": confirmed_claims(exchange_id, sensor_id),
        "cvss": {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "score": 8.8},
    }
    (run.dir / "findings.json").write_text(json.dumps({"findings": [finding]}))
    ws.close()
    (row,) = replay(tmp_path, run.id)
    assert (row.recorded, row.replayed) == ("confirmed 1/1", "confirmed 1/1")
    bundle = export(tmp_path, run.id, tmp_path / "b.tar.gz")
    assert verify_bundle(bundle).ok
    assert verify_bundle(bundle).files == 4  # the sensor record travels with the exchange
