"""The routing eval: scripted models answer each case, and the report scores them and recommends one per route."""

import asyncio

import pytest

from veritas.evals.routing import TRIAGE_KEY, CaseResult, EvalReport, evaluate
from veritas.models.calls import ModelResult


class ScriptedModel:
    """Answers like a model of a known quality, after the same checks a real model's answer gets."""

    def __init__(self, careful: bool, valid: bool = True):
        self.careful, self.valid, self.tasks = careful, valid, []

    async def run(self, task):
        self.tasks.append(task)
        base = {"status": "answered", "reason": "none", "escalate": "none"}
        if not self.valid:
            return ModelResult("invalid", task.role, reason="model_output_invalid: not JSON")
        if task.role == "triage":
            labels = [{"route": r, "sensitivity": want if self.careful else "public", "note": ""}
                      for r, (want, _) in TRIAGE_KEY.items()]  # fmt: skip
            output = {**base, "labels": labels}
        else:
            guidance = ("Encode the 'q' parameter of GET /search for HTML before writing it into the page, and send a "
                        "restrictive Content-Security-Policy." if self.careful else
                        "Encode untrusted values before writing them into pages, and add a policy.")  # fmt: skip
            output = {**base, "guidance": guidance, "inferences": [], "cvss": []}
        assert task.check(output) == []
        return ModelResult("answered", task.role, output=output, tokens=100)


def test_the_careful_model_wins_every_route_it_was_scored_on():
    models = {"careful": ScriptedModel(True), "sloppy": ScriptedModel(False), "broken": ScriptedModel(True, False)}
    report = asyncio.run(evaluate(list(models), models.__getitem__, "laptop"))
    scores = report.scores()
    assert scores["triage"]["careful"][0] == 1.0
    assert scores["triage"]["sloppy"][0] == 2 / len(TRIAGE_KEY)  # only the public routes are right
    assert scores["analysis"]["careful"][0] == 1.0
    assert scores["analysis"]["sloppy"][0] == pytest.approx(1 / 3, abs=1e-3)  # valid, but names neither
    assert {r.score for r in report.results if r.model == "broken"} == {0.0}
    assert report.recommend() == {"triage": "careful", "analysis": "careful"}
    assert report.skipped == ["code: pass an approved lexfmt analysis run to score the code route"]
    assert report.to_json()["recommended"] == {"triage": "careful", "analysis": "careful"}


def test_a_tie_goes_to_the_faster_model_and_a_zero_recommends_nothing():
    report = EvalReport("laptop")
    report.results = [
        CaseResult("slow", "triage", "t", "answered", 0.9, 30.0, 100),
        CaseResult("fast", "triage", "t", "answered", 0.9, 5.0, 100),
        CaseResult("none", "analysis", "a", "invalid", 0.0, 1.0, 0),
    ]
    assert report.recommend() == {"triage": "fast"}
