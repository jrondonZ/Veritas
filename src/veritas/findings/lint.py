"""The claim linter (docs/architecture.md §10.3 and §10.4): every claim is typed and every reference resolves.

It runs over the canonical JSON findings document, so the runner, bundle verification,
and model-output validation all apply the same rules:

- Each claim has a known kind, a unique well-formed ID, and non-empty text.
- An `observed` claim cites evidence, and every evidence ID resolves to a record of the run.
- An `inferred` claim is based on earlier `observed` or `inferred` claims of the same finding.
- A `based_on` reference always names an earlier claim of the same finding.
- A confirmed finding has an observed claim and guidance. Only confirmed findings carry CVSS.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from .model import CLAIM_KINDS

CLAIM_ID = re.compile(r"^C-\d{4,}$")
EVIDENCE_ID = re.compile(r"^E-[0-9a-f]{12}$")
MAX_TEXT = 2000

Resolves = Callable[[str], bool]


@dataclass(frozen=True)
class LintProblem:
    finding: str
    claim: str | None  # None for a problem with the finding as a whole
    rule: str
    detail: str

    def __str__(self) -> str:
        where = f"{self.finding} {self.claim}" if self.claim else self.finding
        return f"{where}: {self.detail} ({self.rule})"


def _lint_claim(
    finding_id: str, claim: dict[str, Any], resolves: Resolves, earlier: dict[str, str], seen: set[str]
) -> list[LintProblem]:
    claim_id = claim.get("id") if isinstance(claim.get("id"), str) else None
    problems: list[LintProblem] = []

    def bad(rule: str, detail: str) -> None:
        problems.append(LintProblem(finding_id, claim_id, rule, detail))

    kind = claim.get("kind")
    if kind not in CLAIM_KINDS:
        bad("claim.kind", f"unknown claim kind {kind!r}")
        return problems
    if claim_id is None or not CLAIM_ID.match(claim_id):
        bad("claim.id", f"malformed claim ID {claim.get('id')!r}")
    elif claim_id in seen:
        bad("claim.id", "duplicate claim ID")
    text = claim.get("text")
    if not isinstance(text, str) or not text.strip():
        bad("claim.text", "the claim has no text")
    elif len(text) > MAX_TEXT:
        bad("claim.text", f"the text is longer than {MAX_TEXT} characters")
    evidence = claim.get("evidence") or []
    for evidence_id in evidence:
        if not (isinstance(evidence_id, str) and EVIDENCE_ID.match(evidence_id) and resolves(evidence_id)):
            bad("reference.evidence", f"evidence {evidence_id!r} does not resolve to a record of this run")
    based_on = claim.get("based_on") or []
    for basis in based_on:
        if basis not in earlier:
            bad("reference.claim", f"based_on {basis!r} is not an earlier, supported claim of this finding")
        elif kind == "inferred" and earlier[basis] not in ("observed", "inferred"):
            bad("inferred.basis", f"{basis} is a {earlier[basis]} claim, which cannot support an inference")
    if kind == "observed" and not evidence:
        bad("observed.evidence", "an observed claim must cite evidence")
    if kind == "observed" and based_on:
        bad("observed.basis", "an observed claim rests on evidence, not on other claims")
    if kind == "inferred" and not based_on:
        bad("inferred.basis", "an inferred claim must be based on other claims")
    if claim_id is not None:
        seen.add(claim_id)
        if not problems:  # an unsupported claim supports nothing, so claims based on it are flagged too
            earlier[claim_id] = str(kind)
    return problems


def lint_finding(finding: dict[str, Any], resolves: Resolves, seen: set[str] | None = None) -> list[LintProblem]:
    """Problems with one finding. `seen` collects claim IDs across a document, which must be unique."""
    seen = set() if seen is None else seen
    finding_id = str(finding.get("id") or "?")
    earlier: dict[str, str] = {}
    claims = [c for c in finding.get("claims") or [] if isinstance(c, dict)]
    problems = [p for c in claims for p in _lint_claim(finding_id, c, resolves, earlier, seen)]
    status, kinds = finding.get("status"), {c.get("kind") for c in claims}
    if status == "confirmed" and "observed" not in kinds:
        problems.append(
            LintProblem(finding_id, None, "finding.observed", "a confirmed finding needs an observed claim")
        )
    if status in ("confirmed", "inconclusive") and "guidance" not in kinds:
        problems.append(LintProblem(finding_id, None, "finding.guidance", f"a {status} finding needs guidance"))
    if (status == "confirmed") != (finding.get("cvss") is not None):
        problems.append(LintProblem(finding_id, None, "finding.cvss", "only a confirmed finding carries CVSS"))
    return problems


def lint_claims(owner: str, claims: list[dict[str, Any]], resolves: Resolves) -> list[LintProblem]:
    """The claim rules alone, for claim lists that aren't findings (an Analyze behavior spec, for example)."""
    earlier: dict[str, str] = {}
    seen: set[str] = set()
    return [p for c in claims if isinstance(c, dict) for p in _lint_claim(owner, c, resolves, earlier, seen)]


def lint_document(document: dict[str, Any], resolves: Resolves) -> list[LintProblem]:
    seen: set[str] = set()
    return [p for f in document.get("findings") or [] for p in lint_finding(f, resolves, seen)]


def drop_unsupported(document: dict[str, Any], problems: list[LintProblem]) -> int:
    """Remove every claim the linter flagged, so no unsupported claim reaches a report. Returns how many."""
    flagged = {(p.finding, p.claim) for p in problems if p.claim is not None}
    dropped = 0
    for finding in document.get("findings") or []:
        kept = [c for c in finding.get("claims") or [] if (finding.get("id"), c.get("id")) not in flagged]
        dropped += len(finding.get("claims") or []) - len(kept)
        finding["claims"] = kept
    return dropped
