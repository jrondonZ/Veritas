"""Compare a behavior spec with a lab's ground truth (docs/architecture.md §14, Phase 3 exit criteria).

Precision is the share of observed claims whose structured fact is in the ground truth.
Recall (reported, not gated) is the share of ground-truth facts the spec observed. A
spec fails when it asserts any `never_observed` pattern in an observed claim, or omits
a required limitation.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


def canonical(fact: dict[str, Any]) -> str:
    return json.dumps(fact, sort_keys=True)


@dataclass
class GroundResult:
    observed: int = 0
    matched: int = 0
    unmatched: list[dict[str, Any]] = field(default_factory=list)  # observed claims not in the ground truth
    missed: list[dict[str, Any]] = field(default_factory=list)  # ground-truth facts the spec didn't observe
    forbidden: list[str] = field(default_factory=list)  # never_observed patterns that an observed claim asserted
    missing_limitations: list[dict[str, Any]] = field(default_factory=list)

    @property
    def precision(self) -> float:
        return self.matched / self.observed if self.observed else 0.0

    @property
    def recall(self) -> float:
        total = self.matched + len(self.missed)
        return self.matched / total if total else 0.0

    def passes(self, threshold: float = 0.95) -> bool:
        return self.precision >= threshold and not self.forbidden and not self.missing_limitations


@dataclass
class CodeGroundResult:
    found: int = 0
    matched: int = 0
    unexpected: list[dict[str, Any]] = field(default_factory=list)  # candidates the ground truth doesn't list
    missed: list[dict[str, Any]] = field(default_factory=list)  # expected candidates not found
    look_alikes: list[dict[str, Any]] = field(default_factory=list)  # candidates in a correct look-alike

    @property
    def precision(self) -> float:
        return self.matched / self.found if self.found else 1.0

    @property
    def recall(self) -> float:
        total = self.matched + len(self.missed)
        return self.matched / total if total else 1.0


def compare_code(
    findings: list[dict[str, Any]], truth: dict[str, Any], files: set[str] | None = None
) -> CodeGroundResult:
    """Candidates against a lab's expected-code-findings: (rule, file, function) must match exactly.

    `files` limits the ground truth to the subjects that were read, for a test that reads only some of them.
    """
    result = CodeGroundResult(found=len(findings))
    truth = {k: [i for i in truth.get(k) or [] if files is None or i["file"] in files] for k in ("expected", "never")}
    expected = {(e["rule"], e["file"], e["function"]) for e in truth.get("expected") or []}
    never = {(n["file"], n["function"]) for n in truth.get("never") or []}
    seen = set()
    for f in findings:
        key = (f["rule"], f["file"], f["function"])
        if key in expected:
            result.matched += 1
            seen.add(key)
        else:
            result.unexpected.append(f)
        if (f["file"], f["function"]) in never:
            result.look_alikes.append(f)
    result.missed = [e for e in truth.get("expected") or [] if (e["rule"], e["file"], e["function"]) not in seen]
    return result


def compare(claims: list[dict[str, Any]], truth: dict[str, Any]) -> GroundResult:
    result = GroundResult()
    expected = {canonical(f) for f in truth.get("facts") or []}
    observed = [c for c in claims if c.get("kind") == "observed"]
    seen = set()
    for claim in observed:
        key = canonical(claim.get("fact") or {})
        result.observed += 1
        if key in expected:
            result.matched += 1
            seen.add(key)
        else:
            result.unmatched.append(claim)
    result.missed = [f for f in truth.get("facts") or [] if canonical(f) not in seen]
    for rule in truth.get("never_observed") or []:
        pattern = re.compile(rule["pattern"])
        if any(pattern.search(c["text"]) for c in observed):
            result.forbidden.append(rule["what"])
    limitation_facts = {canonical(c.get("fact") or {}) for c in claims if c.get("kind") == "limitation"}
    result.missing_limitations = [
        lim for lim in truth.get("limitations") or [] if canonical(lim) not in limitation_facts
    ]
    return result
