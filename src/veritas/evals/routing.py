"""The routing eval (docs/architecture.md §10.2, ADR 0007): which registered model should serve each route here.

Each case is a role task with a known good answer, built from the bundled labs:

- triage: label a route catalog like vuln-notes', with one admin route added. It's scored label
  by label against an answer key.
- analysis: write guidance for a confirmed reflected-HTML finding. It's scored on three things:
  a valid answer, the route and parameter named, and only real claims cited.
- code: write the lexfmt reader from an approved spec. It's scored by the share of conformance
  vectors passed. This case runs only with an approved lexfmt analysis run, because a person
  approves what crosses into a clean room, even for an eval.

Every case records whether the first answer was valid, its latency, and its tokens. A
model's score on a route is its mean case score, and a tie goes to the faster model. The eval
only recommends. `veritas models eval --apply` saves the recommended routes, and nothing else
changes.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

from ..agents import analyst, implementer, triage
from ..agents.context import FindingContext
from ..assess.checks import BY_ID
from ..assess.evidence import Exchange
from ..models.calls import ModelResult, ModelTask

# The vuln-notes catalog and the sensitivity a careful reviewer gives each route.
TRIAGE_KEY = {
    "GET /": ("public", False),
    "GET /search": ("public", False),
    "POST /api/login": ("account", False),
    "GET /api/notes": ("user-data", True),
    "GET /api/notes/{id}": ("user-data", True),
    "POST /api/notes": ("user-data", True),
    "GET /api/profile": ("account", True),
    "PUT /api/profile": ("account", True),
    "GET /api/search": ("user-data", True),
    "GET /api/admin/users": ("admin", True),
}


class Service(Protocol):
    async def run(self, task: ModelTask) -> ModelResult: ...


@dataclass
class CaseResult:
    model: str
    route: str
    case: str
    status: str
    score: float  # 0 to 1
    seconds: float
    tokens: int
    note: str = ""


@dataclass
class EvalReport:
    profile: str
    results: list[CaseResult] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)

    def scores(self) -> dict[str, dict[str, tuple[float, float]]]:
        """route -> model -> (mean score, mean seconds)."""
        out: dict[str, dict[str, list[CaseResult]]] = {}
        for r in self.results:
            out.setdefault(r.route, {}).setdefault(r.model, []).append(r)
        return {
            route: {
                m: (sum(c.score for c in cs) / len(cs), sum(c.seconds for c in cs) / len(cs)) for m, cs in by.items()
            }
            for route, by in out.items()
        }

    def recommend(self) -> dict[str, str]:
        """The best model per route: the highest score, then the fastest. A route nobody scored on is left out."""
        best = {}
        for route, by_model in self.scores().items():
            ranked = sorted(by_model.items(), key=lambda kv: (-kv[1][0], kv[1][1], kv[0]))
            if ranked and ranked[0][1][0] > 0:
                best[route] = ranked[0][0]
        return best

    def to_json(self) -> dict[str, Any]:
        return {"schema": "veritas/routing-eval/v1alpha1", "profile": self.profile,
                "results": [asdict(r) for r in self.results], "skipped": self.skipped,
                "scores": {route: {m: {"score": round(s, 3), "seconds": round(t, 1)} for m, (s, t) in by.items()}
                           for route, by in self.scores().items()},
                "recommended": self.recommend()}  # fmt: skip


# ---------------------------------------------------------------- cases


def triage_case() -> tuple[ModelTask, Callable[[dict[str, Any]], tuple[float, str]]]:
    routes = [{"label": label, "auth": auth} for label, (_, auth) in TRIAGE_KEY.items()]

    def score(output: dict[str, Any]) -> tuple[float, str]:
        given = {item["route"]: item["sensitivity"] for item in output["labels"]}
        right = [label for label, (want, _) in TRIAGE_KEY.items() if given.get(label) == want]
        wrong = sorted(set(TRIAGE_KEY) - set(right))
        return len(right) / len(TRIAGE_KEY), f"mislabeled: {', '.join(wrong)}" if wrong else ""

    return triage.task(routes), score


def analyst_case() -> tuple[ModelTask, Callable[[dict[str, Any]], tuple[float, str]]]:
    page = Exchange(id="E-0000000000a1", kind="exchange", tid="t-0001", target="web", identity=None, method="GET",
                    path="/search?q=%3Cvrt-mk-0123456789%3E", request_headers=(), request_body=b"", status=200,
                    response_headers=(("content-type", "text/html; charset=utf-8"),),
                    response_body=b"<p>Results for: <vrt-mk-0123456789></p><p>No notes matched.</p>")  # fmt: skip
    finding = {
        "id": "F-0001", "title": "Reflected HTML injection: GET /search", "route": "GET /search",
        "claims": [
            {"id": "C-0001", "kind": "observed", "evidence": [page.id], "based_on": [],
             "text": "An inert marker sent in 'q' was reflected unencoded and parsed as an element node."},
            {"id": "C-0002", "kind": "observed", "evidence": [page.id], "based_on": [],
             "text": "The response has no Content-Security-Policy header."},
            {"id": "C-0003", "kind": "inferred", "evidence": [], "based_on": ["C-0001", "C-0002"],
             "text": "Script injection through this parameter is likely; it was not demonstrated."},
        ],
    }  # fmt: skip
    ctx = FindingContext(finding, exchanges={page.id: page})
    task = analyst.task(finding, ctx, BY_ID["veritas.check.reflected-html"].info)

    def score(output: dict[str, Any]) -> tuple[float, str]:
        guidance = output["guidance"]
        names_route = "/search" in guidance
        names_param = "'q'" in guidance or '"q"' in guidance or "`q`" in guidance or " q " in guidance
        points = 1 + names_route + names_param  # valid, the route, the parameter
        missing = [n for n, ok in (("the route", names_route), ("the parameter", names_param)) if not ok]
        return points / 3, f"guidance doesn't name {' or '.join(missing)}" if missing else ""

    return task, score


# The code case needs the conformance harness, so its scorer is given by the caller.
CodeScorer = Callable[[dict[str, Any]], Awaitable[tuple[float, str]]]


def code_case(clean: dict[str, Any], samples: dict[str, bytes]) -> ModelTask:
    return implementer.task(clean, samples)


# ---------------------------------------------------------------- the run


async def _one(service: Service, model: str, route: str, case: str, task: ModelTask,
               score: Callable[[dict[str, Any]], Any]) -> CaseResult:  # fmt: skip
    started = time.monotonic()
    result = await service.run(task)
    seconds = round(time.monotonic() - started, 1)
    if result.status != "answered" or result.output is None:
        return CaseResult(model, route, case, result.status, 0.0, seconds, result.tokens, result.reason)
    value = score(result.output)
    points, note = (await value) if isinstance(value, Awaitable) else value
    return CaseResult(model, route, case, "answered", round(points, 3), seconds, result.tokens, note)


async def evaluate(
    models: list[str],
    service_for: Callable[[str], Service],
    profile: str,
    code: tuple[ModelTask, CodeScorer] | None = None,
    close: Callable[[Service], Awaitable[None]] | None = None,
) -> EvalReport:
    """Run every case with every model. `service_for(model)` gives a service that routes every route to that model."""
    report = EvalReport(profile)
    if code is None:
        report.skipped.append("code: pass an approved lexfmt analysis run to score the code route")
    for model in models:
        service = service_for(model)
        try:
            task, score = triage_case()
            report.results.append(await _one(service, model, "triage", "triage-vuln-notes", task, score))
            task, score = analyst_case()
            report.results.append(await _one(service, model, "analysis", "analyst-reflected-html", task, score))
            if code is not None:
                report.results.append(await _one(service, model, "code", "implementer-lexfmt", code[0], code[1]))
        finally:
            if close is not None:
                await close(service)
    return report
