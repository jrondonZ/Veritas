"""The analyst role (docs/architecture.md §10.1): tailor one confirmed finding.

It reads the finding's claims and evidence excerpts, and writes:

- guidance tailored to this application, next to the check's curated template;
- at most two inferences, each resting on the finding's observed claims;
- optional CVSS metric adjustments, each citing the claims that show the metric is wrong.

The output schema is built per finding, so the decoding grammar itself limits `based_on`
to the finding's real aliases; the kernel checks every reference again anyway. The
deterministic calculator recomputes any adjusted score. A model never changes a status.
"""

from __future__ import annotations

from typing import Any

from ..assess.checks import CheckInfo
from ..findings.cvss import base_score, parse, severity
from ..models.calls import ModelResult, ModelTask, answer_envelope
from ..models.prompts import Prompt
from .context import FindingContext

VERSION = "1"
METRICS = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("N", "L", "H"),
    "I": ("N", "L", "H"),
    "A": ("N", "L", "H"),
}
SYSTEM = """\
You are the analyst. You get one confirmed finding: the claims Veritas recorded about it, excerpts of the evidence, \
and the check's remediation template. Write:
- "guidance": two to four sentences of advice for this application's developers, tailored to the evidence. Name the \
route and the parameter or field involved. Do not copy the template.
- "inferences": at most two short statements that follow from the observed claims. List the claim IDs each one rests \
on in "based_on". Never restate an observation, and never say anything was exploited; Veritas proves that a control \
is missing, not what an attacker could do.
- "cvss": usually empty. Add an entry only when an observed claim shows a base metric of the default vector is wrong, \
with the metric, its new value, and the claim IDs that show it.
"""


def schema(ctx: FindingContext) -> dict[str, Any]:
    cite = {
        "type": "array",
        "minItems": 1,
        "maxItems": 4,
        "items": {"type": "string", "enum": sorted(ctx.observed_aliases())},
    }
    return answer_envelope(
        {
            "guidance": {"type": "string", "maxLength": 700},
            "inferences": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "properties": {"text": {"type": "string", "maxLength": 300}, "based_on": cite},
                    "required": ["text", "based_on"],
                    "additionalProperties": False,
                },
            },
            "cvss": {
                "type": "array",
                "maxItems": 2,
                "items": {
                    "type": "object",
                    "properties": {
                        "metric": {"type": "string", "enum": list(METRICS)},
                        "value": {"type": "string", "enum": sorted({v for vs in METRICS.values() for v in vs})},
                        "based_on": cite,
                    },
                    "required": ["metric", "value", "based_on"],
                    "additionalProperties": False,
                },
            },
        },
        ["guidance", "inferences", "cvss"],
    )


def reference(info: CheckInfo) -> str:
    """Stable across every finding of one check, so the server reuses this prefix."""
    tags = " · ".join([*info.cwe, *info.wstg])
    return (
        f"Check: {info.title} ({info.id}; {tags})\nDefault CVSS vector: {info.cvss}\n"
        f"Remediation template: {info.remediation}"
    )


def task(finding: dict[str, Any], ctx: FindingContext, info: CheckInfo) -> ModelTask:
    data = (
        f"Finding: {finding['title']}\nRoute: {finding['route']}\n\nClaims:\n{ctx.claims_text()}\n\n"
        f"Evidence:\n{ctx.evidence_text()}"
    )
    prompt = Prompt("analyst", VERSION, SYSTEM, reference(info), data)
    current = parse(info.cvss)
    texts = {c["text"].strip().lower() for c in finding.get("claims", [])}

    def check(output: dict[str, Any]) -> list[str]:
        problems = []
        if len(output["guidance"].strip()) < 40:
            problems.append("guidance must be two to four sentences")
        allowed = ctx.observed_aliases()
        for i, inference in enumerate(output["inferences"]):
            if unknown := ctx.unknown_aliases(inference["based_on"], allowed):
                problems.append(f"inferences[{i}] cites {', '.join(unknown)}, which are not observed claims")
            if len(inference["text"].strip()) < 10 or inference["text"].strip().lower() in texts:
                problems.append(f"inferences[{i}] restates a claim or is empty")
        for i, change in enumerate(output["cvss"]):
            metric, value = change["metric"], change["value"]
            if value not in METRICS[metric]:
                problems.append(f"cvss[{i}]: {value} is not a value of {metric}")
            elif current.get(metric) == value:
                problems.append(f"cvss[{i}]: {metric} is already {value}")
            if unknown := ctx.unknown_aliases(change["based_on"], allowed):
                problems.append(f"cvss[{i}] cites {', '.join(unknown)}, which are not observed claims")
        return problems

    return ModelTask("analyst", "analysis", finding["id"], prompt, schema(ctx), 400, check)


def apply(finding: dict[str, Any], ctx: FindingContext, result: ModelResult) -> None:
    """Add the analyst's claims (with provisional IDs; the document is renumbered afterwards) and any CVSS change."""
    output = result.output or {}
    claims = finding["claims"]
    last_reasoning = max((i for i, c in enumerate(claims) if c["kind"] in ("observed", "inferred")), default=-1)
    added = [
        {"id": f"{finding['id']}-a{n}", "kind": "inferred", "text": inference["text"].strip(), "evidence": [],
         "based_on": ctx.real_claims(inference["based_on"]), "producer": result.producer}
        for n, inference in enumerate(output.get("inferences", []), 1)
    ]  # fmt: skip
    claims[last_reasoning + 1 : last_reasoning + 1] = added
    claims.append({"id": f"{finding['id']}-ag", "kind": "guidance", "text": output["guidance"].strip(), "evidence": [],
                   "based_on": [], "producer": result.producer})  # fmt: skip
    changes = output.get("cvss") or []
    if changes and finding.get("cvss"):
        metrics = parse(finding["cvss"]["vector"])
        adjustments = []
        for change in changes:
            metric, value = change["metric"], change["value"]
            basis = ctx.real_claims(change["based_on"])
            adjustments.append(
                {"metric": metric, "from": metrics[metric], "to": value, "based_on": basis, "producer": result.producer}
            )
            metrics[metric] = value
        vector = "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in METRICS)
        score = base_score(vector)
        finding["cvss"] = {**finding["cvss"], "vector": vector, "score": score, "source": "model-adjusted",
                           "default": finding["cvss"]["vector"], "adjustments": adjustments}  # fmt: skip
        finding["severity"] = severity(score)
