"""Stage 9, enrich (docs/architecture.md §8.1): optional model work over a finished run's findings.

It runs after every status is decided and the target is torn down, on recorded evidence only:

1. triage labels the route catalog, once;
2. the analyst tailors each confirmed finding;
3. high and critical findings get a deep review. When `deep` is aliased or absent, they get
   a limitation claim saying no deep review ran instead; the claim linter checks every claim
   either way (§10.3 rule 3);
4. claims are renumbered so IDs stay sequential, and every reference is rewritten.

A task that doesn't answer leaves the finding as the rules wrote it, plus a limitation
claim that says why. Statuses never change here.
"""

from __future__ import annotations

import time
from typing import Any

from ..assess.checks import BY_ID
from ..assess.evidence import WorkspaceEvidence
from ..models.calls import ModelResult, ModelService
from ..models.profiles import ROUTES, RouteUnavailable, Routing
from ..store import EXCHANGE_MEDIA_TYPE, SENSOR_MEDIA_TYPE
from . import analyst, reviewer, triage
from .context import FindingContext

HIGH = ("high", "critical")


def describe_routes(routing: Routing) -> dict[str, Any]:
    """Which model serves each route, so the report names the model behind every task (§10.2)."""
    routes: dict[str, Any] = {}
    for route in ROUTES:
        try:
            r = routing.resolve(route)
        except RouteUnavailable as exc:
            routes[route] = {"available": False, "reason": str(exc)}
            continue
        m = r.model
        routes[route] = {"available": True, "model": m.name, "weights": m.sha256, "license": m.license,
                         "quantization": m.quantization, "source": r.source,
                         **({"aliased_to": r.serving} if r.aliased else {})}  # fmt: skip
    return routes


def _context(finding: dict[str, Any], evidence: WorkspaceEvidence) -> FindingContext:
    ctx = FindingContext(finding)
    for real in ctx.evidence_alias.values():
        kind = evidence.media_type(real)
        if kind == EXCHANGE_MEDIA_TYPE:
            ctx.exchanges[real] = evidence.get(real)
        elif kind == SENSOR_MEDIA_TYPE:
            ctx.signals[real] = evidence.signal(real)
    return ctx


def _note(finding: dict[str, Any], tag: str, text: str) -> None:
    finding["claims"].append(
        {"id": f"{finding['id']}-{tag}", "kind": "limitation", "text": text, "evidence": [], "based_on": [],
         "producer": "kernel"}
    )  # fmt: skip


def _unanswered(role: str, result: ModelResult) -> str:
    return f"the {role} model's task ended {result.status} ({result.reason})"


def renumber_claims(document: dict[str, Any]) -> None:
    mapping: dict[str, str] = {}
    for finding in document["findings"]:
        for claim in finding["claims"]:
            mapping[claim["id"]] = f"C-{len(mapping) + 1:04d}"
    for finding in document["findings"]:
        for claim in finding["claims"]:
            claim["id"] = mapping[claim["id"]]
            claim["based_on"] = [mapping.get(b, b) for b in claim.get("based_on", [])]
        for adjustment in (finding.get("cvss") or {}).get("adjustments", []):
            adjustment["based_on"] = [mapping.get(b, b) for b in adjustment["based_on"]]


async def enrich(
    document: dict[str, Any], evidence: WorkspaceEvidence, service: ModelService, routing: Routing
) -> dict[str, Any]:
    started = time.monotonic()
    tasks: dict[str, int] = {}

    def count(result: ModelResult) -> None:
        key = f"{result.role}:{result.status}"
        tasks[key] = tasks.get(key, 0) + 1

    recon = document.get("recon")
    if recon and recon.get("routes"):
        catalog = [{"label": label, "auth": label in set(recon.get("auth", []))} for label in recon["routes"]]
        result = await service.run(triage.task(catalog))
        count(result)
        if result.status == "answered" and result.output is not None:
            recon["labels"] = triage.apply(result.output, result.producer)

    try:
        deep = routing.resolve("deep")
        no_review = None if not deep.aliased else f"the deep route is aliased to {deep.serving}"
    except RouteUnavailable as exc:
        no_review = str(exc)

    for finding in document["findings"]:
        if finding["status"] != "confirmed":
            continue
        ctx = _context(finding, evidence)
        if not ctx.observed_aliases():
            continue
        result = await service.run(analyst.task(finding, ctx, BY_ID[finding["check"]].info))
        count(result)
        if result.status == "answered":
            analyst.apply(finding, ctx, result)
        else:
            _note(finding, "an", f"No tailored guidance: {_unanswered('analyst', result)}.")
        if finding.get("severity") not in HIGH:
            continue
        if no_review is not None:
            _note(finding, "dr", f"No deep review ran ({no_review}); the claim linter checked every claim.")
            continue
        review_ctx = _context(finding, evidence)  # now includes the analyst's claims
        review = reviewer.task(finding, review_ctx)
        if review is None:
            continue
        result = await service.run(review)
        count(result)
        if result.status == "answered":
            reviewer.apply(finding, review_ctx, result)
        else:
            _note(finding, "dr", f"No deep review: {_unanswered('reviewer', result)}.")

    renumber_claims(document)
    return {
        "profile": routing.profile.name,
        "routes": describe_routes(routing),
        "tasks": dict(sorted(tasks.items())),
        "calls": service.stats["calls"],
        "cache_hits": service.stats["cache_hits"],
        "tokens": service.budget.used,
        "redactions": dict(sorted(service.redactions.items())),
        "duration_s": round(time.monotonic() - started, 1),
    }
