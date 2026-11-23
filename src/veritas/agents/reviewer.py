"""The reviewer role (docs/architecture.md §10.1, §10.3 rule 3): a deep review of high and critical findings.

It rules on every claim a model wrote: supported, unsupported, or overstated, measured
against the finding's evidence. Unsupported and overstated claims are removed, and a
limitation claim says how many. Oracle claims rest on captured evidence and are never
overruled by a model. When the `deep` route is aliased or absent, no review runs and
the finding says so instead.
"""

from __future__ import annotations

from typing import Any

from ..models.calls import ModelResult, ModelTask, answer_envelope
from ..models.prompts import Prompt
from .context import FindingContext

VERSION = "1"
VERDICTS = ("supported", "unsupported", "overstated")
SYSTEM = """\
You are the reviewer. You get one high-severity finding: its claims and the evidence they cite. Rule on each claim \
listed under "Claims to review": "supported" if the evidence and the observed claims show it, "overstated" if it \
says more than they show, "unsupported" if they don't show it. Give a short reason for every ruling.
"""


def reviewable(finding: dict[str, Any]) -> list[dict[str, Any]]:
    return [c for c in finding.get("claims", []) if "@" in c.get("producer", "")]


def task(finding: dict[str, Any], ctx: FindingContext) -> ModelTask | None:
    claims = reviewable(finding)
    if not claims:
        return None
    aliases = [ctx.alias_of(c["id"]) for c in claims]
    listing = "\n".join(f"{a}: {c['text']}" for a, c in zip(aliases, claims, strict=True))
    data = (
        f"Finding: {finding['title']}\n\nClaims:\n{ctx.claims_text()}\n\nEvidence:\n{ctx.evidence_text()}\n\n"
        f"Claims to review:\n{listing}"
    )
    schema = answer_envelope(
        {
            "rulings": {
                "type": "array",
                "maxItems": len(aliases),
                "items": {
                    "type": "object",
                    "properties": {
                        "claim": {"type": "string", "enum": aliases},
                        "verdict": {"type": "string", "enum": list(VERDICTS)},
                        "reason": {"type": "string", "maxLength": 200},
                    },
                    "required": ["claim", "verdict", "reason"],
                    "additionalProperties": False,
                },
            }
        },
        ["rulings"],
    )

    def check(output: dict[str, Any]) -> list[str]:
        ruled = [r["claim"] for r in output["rulings"]]
        return [f"{a} has no ruling" for a in aliases if a not in ruled] + [
            f"{a} is ruled more than once" for a in sorted({a for a in ruled if ruled.count(a) > 1})
        ]

    prompt = Prompt("reviewer", VERSION, SYSTEM, "Review these claims.", data)
    return ModelTask("reviewer", "deep", finding["id"], prompt, schema, 80 + 60 * len(aliases), check)


def apply(finding: dict[str, Any], ctx: FindingContext, result: ModelResult) -> int:
    """Remove claims the reviewer did not support, and anything resting on them. Returns how many were removed."""
    rejected = {ctx.claim_alias[r["claim"]] for r in (result.output or {}).get("rulings", [])
                if r["verdict"] != "supported"}  # fmt: skip
    if not rejected:
        return 0
    kept, removed = [], set(rejected)
    for claim in finding["claims"]:
        if claim["id"] in removed or removed.intersection(claim.get("based_on", [])):
            removed.add(claim["id"])
        else:
            kept.append(claim)
    finding["claims"] = kept
    kept.append(
        {"id": f"{finding['id']}-rv", "kind": "limitation", "evidence": [], "based_on": [], "producer": result.producer,
         "text": f"The deep review removed {len(removed)} model-written claim(s) it found unsupported or overstated."}
    )  # fmt: skip
    return len(removed)
