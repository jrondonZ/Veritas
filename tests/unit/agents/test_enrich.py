"""Model roles and the enrich stage, with a scripted stand-in for the model service."""

import asyncio
import base64
import copy
from collections import Counter

import pytest

from veritas.agents import analyst, reviewer, triage
from veritas.agents.context import FindingContext
from veritas.agents.enrich import enrich
from veritas.assess.checks import BY_ID
from veritas.assess.evidence import WorkspaceEvidence
from veritas.core.canonical import canonical_bytes
from veritas.findings.lint import lint_document
from veritas.models.calls import ModelResult, TokenBudget
from veritas.models.profiles import PROFILES, Routing
from veritas.models.registry import RegisteredModel
from veritas.models.schema import supported
from veritas.store import EXCHANGE_MEDIA_TYPE, Workspace

AUTHZ = "veritas.check.object-authz"


def model(name):
    return RegisteredModel(name, "sha256:" + name[0] * 64, 1, f"{name}.gguf", "mit", "Q4_K_M", "qwen3", 8192, name, "t")


def exchange_record(path, body):
    return canonical_bytes(
        {
            "v": 1,
            "kind": "exchange",
            "tid": "t-0001",
            "target": "web",
            "identity": "alice",
            "request": {"method": "GET", "authority": "h", "target": path, "headers": [], "body_b64": ""},
            "response": {
                "status": 200,
                "reason": "OK",
                "headers": [["content-type", "application/json"], ["date", "Thu, 19 Nov 2026 10:00:00 GMT"]],
                "body_b64": base64.b64encode(body.encode()).decode(),
            },
        }
    )


@pytest.fixture
def document(tmp_path):
    ws = Workspace(tmp_path)
    run = ws.create_run("assess", "sha256:test")
    e1 = ws.add_evidence(
        run.id, exchange_record("/api/notes/4", '{"body": "vrt-seed-bob-1"}'), EXCHANGE_MEDIA_TYPE, "g"
    )
    e2 = ws.add_evidence(
        run.id, exchange_record("/api/notes/4?x", '{"body": "vrt-seed-bob-1"}'), EXCHANGE_MEDIA_TYPE, "g"
    )
    doc = {
        "recon": {"routes": ["GET /api/notes/{id}", "GET /search"], "auth": ["GET /api/notes/{id}"]},
        "findings": [
            {
                "id": "F-0001",
                "check": AUTHZ,
                "title": "Missing object-level authorization: GET /api/notes/{id}",
                "route": "GET /api/notes/{id}",
                "status": "confirmed",
                "severity": "medium",
                "cvss": {"version": "3.1", "vector": BY_ID[AUTHZ].info.cvss, "score": 6.5},
                "claims": [
                    {
                        "id": "C-0001",
                        "kind": "observed",
                        "text": "alice read bob's note",
                        "evidence": [e1],
                        "based_on": [],
                        "producer": f"oracle:{AUTHZ}",
                    },
                    {
                        "id": "C-0002",
                        "kind": "observed",
                        "text": "bob read his own note",
                        "evidence": [e2],
                        "based_on": [],
                        "producer": f"oracle:{AUTHZ}",
                    },
                    {
                        "id": "C-0003",
                        "kind": "inferred",
                        "text": "any user can read any note",
                        "evidence": [],
                        "based_on": ["C-0001", "C-0002"],
                        "producer": f"oracle:{AUTHZ}",
                    },
                    {
                        "id": "C-0004",
                        "kind": "guidance",
                        "text": "scope the lookup",
                        "evidence": [],
                        "based_on": [],
                        "producer": f"template:{AUTHZ}",
                    },
                ],
            },
            {"id": "F-0002", "check": AUTHZ, "status": "rejected", "claims": [], "route": "GET /api/v2/notes/{id}"},
        ],
    }
    yield doc, ws, run, {e1, e2}
    ws.close()


class ScriptedService:
    """Answers each role from a script; checks every task the way the real service would."""

    def __init__(self, answers, routing):
        self.answers, self.routing, self.tasks = answers, routing, []
        self.stats, self.redactions, self.budget = Counter(), Counter(), TokenBudget(10**6)

    async def run(self, task):
        assert supported(task.schema) == []  # role schemas stay inside the grammar subset (§10.4)
        self.tasks.append(task)
        status, output = self.answers[task.role]
        result = ModelResult(status, task.role, reason="scripted", model=self.routing.resolve(task.route).model)
        if status == "answered":
            assert task.check(output) == [], task.check(output)
            result.output = output
        return result


def answer(**fields):
    return {"status": "answered", "reason": "none", "escalate": "none", **fields}


ANALYST = answer(
    guidance="Filter the note lookup in GET /api/notes/{id} by the signed-in user's id and answer 404 otherwise.",
    inferences=[{"text": "Note ids are sequential, so they are easy to guess.", "based_on": ["C1"]}],
    cvss=[],
)
TRIAGE = answer(
    labels=[
        {"route": "GET /api/notes/{id}", "sensitivity": "user-data", "note": ""},
        {"route": "GET /search", "sensitivity": "public", "note": ""},
    ]
)


def laptop(**choices):
    return Routing(PROFILES["laptop"], choices or {"analysis": "small"}, {"small": model("small"), "big": model("big")})


def run_enrich(doc, ws, answers, routing):
    service = ScriptedService(answers, routing)
    summary = asyncio.run(enrich(doc, WorkspaceEvidence(ws), service, routing))
    return service, summary


def test_analyst_claims_are_added_renumbered_and_pass_the_linter(document):
    doc, ws, _, evidence = document
    service, summary = run_enrich(doc, ws, {"triage": ("answered", TRIAGE), "analyst": ("answered", ANALYST)}, laptop())
    claims = doc["findings"][0]["claims"]
    assert [c["id"] for c in claims] == [f"C-{n:04d}" for n in range(1, 7)]
    added = [c for c in claims if c["producer"].startswith("analyst@")]
    assert [(c["kind"], c["based_on"]) for c in added] == [("inferred", ["C-0001"]), ("guidance", [])]
    assert claims[3]["text"].startswith("Note ids are sequential")  # after the oracle's reasoning, before guidance
    assert lint_document(doc, evidence.__contains__) == []
    assert doc["recon"]["labels"]["routes"]["GET /search"]["sensitivity"] == "public"
    assert summary["routes"]["deep"]["aliased_to"] == "analysis"
    assert [t.role for t in service.tasks] == ["triage", "analyst"]  # nothing runs for the rejected finding


def test_prompts_use_aliases_and_wrap_target_data(document):
    doc, ws, _, evidence = document
    service, _ = run_enrich(doc, ws, {"triage": ("answered", TRIAGE), "analyst": ("answered", ANALYST)}, laptop())
    user = service.tasks[1].prompt.messages()[1]["content"]
    assert "C1 observed: alice read bob's note [E1]" in user
    assert '<untrusted source="target">' in user
    assert not any(e in user for e in evidence)  # raw evidence IDs never reach a prompt
    assert "Thu, 19 Nov 2026" not in user  # volatile headers are left out, so reruns hit the cache


def test_analyst_checks_reject_bad_references_and_cvss_changes(document):
    doc, _, _, _ = document
    finding = doc["findings"][0]
    ctx = FindingContext(finding)
    check = analyst.task(finding, ctx, BY_ID[AUTHZ].info).check
    bad = answer(
        guidance="too short",
        inferences=[{"text": "any user can read any note", "based_on": ["C4"]}],
        cvss=[{"metric": "AV", "value": "H", "based_on": ["C1"]}, {"metric": "PR", "value": "L", "based_on": ["C1"]}],
    )
    assert check(bad) == [
        "guidance must be two to four sentences",
        "inferences[0] cites C4, which are not observed claims",
        "inferences[0] restates a claim or is empty",
        "cvss[0]: H is not a value of AV",
        "cvss[1]: PR is already L",
    ]


def test_a_cvss_adjustment_is_recomputed_by_the_calculator(document):
    doc, ws, _, _ = document
    adjusted = {**ANALYST, "cvss": [{"metric": "PR", "value": "N", "based_on": ["C1"]}]}
    run_enrich(doc, ws, {"triage": ("declined", None), "analyst": ("answered", adjusted)}, laptop())
    cvss = doc["findings"][0]["cvss"]
    assert (cvss["vector"], cvss["score"], cvss["source"]) == (
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        7.5,
        "model-adjusted",
    )
    assert cvss["default"] == BY_ID[AUTHZ].info.cvss
    assert cvss["adjustments"][0]["based_on"] == ["C-0001"]
    assert doc["findings"][0]["severity"] == "high"


def test_unanswered_tasks_leave_the_rules_output_and_say_why(document):
    doc, ws, _, evidence = document
    before = copy.deepcopy(doc["findings"][0]["claims"])
    run_enrich(doc, ws, {"triage": ("invalid", None), "analyst": ("budget", None)}, laptop())
    claims = doc["findings"][0]["claims"]
    assert claims[:4] == before
    assert claims[4]["text"] == "No tailored guidance: the analyst model's task ended budget (scripted)."
    assert "labels" not in doc["recon"]
    assert lint_document(doc, evidence.__contains__) == []


def test_high_findings_note_that_no_deep_review_ran_when_deep_is_aliased(document):
    doc, ws, _, _ = document
    doc["findings"][0]["severity"] = "high"
    run_enrich(doc, ws, {"triage": ("declined", None), "analyst": ("answered", ANALYST)}, laptop())
    assert doc["findings"][0]["claims"][-1]["text"] == (
        "No deep review ran (the deep route is aliased to analysis); the claim linter checked every claim."
    )


def test_the_reviewer_removes_model_claims_it_does_not_support(document):
    doc, ws, _, evidence = document
    doc["findings"][0]["severity"] = "high"
    rulings = answer(
        rulings=[
            {"claim": "C4", "verdict": "overstated", "reason": "sequential ids are not shown"},
            {"claim": "C6", "verdict": "supported", "reason": "matches the evidence"},
        ]
    )
    answers = {"triage": ("declined", None), "analyst": ("answered", ANALYST), "reviewer": ("answered", rulings)}
    service, _ = run_enrich(doc, ws, answers, laptop(analysis="small", deep="big"))
    assert [t.role for t in service.tasks] == ["triage", "analyst", "reviewer"]
    texts = [c["text"] for c in doc["findings"][0]["claims"]]
    assert not any(t.startswith("Note ids are sequential") for t in texts)
    assert texts[-1] == "The deep review removed 1 model-written claim(s) it found unsupported or overstated."
    assert lint_document(doc, evidence.__contains__) == []


def test_triage_must_label_every_route_once():
    check = triage.task([{"label": "GET /a", "auth": False}, {"label": "GET /b", "auth": True}]).check
    twice = answer(labels=[{"route": "GET /a", "sensitivity": "public", "note": ""}] * 2)
    assert check(twice) == ["GET /a is labeled more than once", "GET /b has no label"]


def test_the_reviewer_sees_only_model_written_claims(document):
    doc, _, _, _ = document
    assert reviewer.task(doc["findings"][0], FindingContext(doc["findings"][0])) is None  # nothing a model wrote yet
