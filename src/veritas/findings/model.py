"""Findings and typed claims (docs/architecture.md §7 and §8.4)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

from ..core.canonical import digest

Status = Literal["confirmed", "rejected", "inconclusive", "blocked", "error"]
ClaimKind = Literal["observed", "inferred", "unknown", "limitation", "guidance"]
STATUSES: tuple[Status, ...] = ("confirmed", "rejected", "inconclusive", "blocked", "error")
SEVERITY_ORDER = ("none", "low", "medium", "high", "critical")


CLAIM_KINDS: tuple[ClaimKind, ...] = ("observed", "inferred", "unknown", "limitation", "guidance")


@dataclass
class Claim:
    id: str
    kind: ClaimKind
    text: str
    evidence: list[str] = field(default_factory=list)
    based_on: list[str] = field(default_factory=list)
    # What wrote the claim: "oracle:<check>", "check:<check>", "template:<check>", "kernel",
    # or "<role>@<model>" for a model role (docs/architecture.md §6.4).
    producer: str = ""


@dataclass
class Attempt:
    verdict: str  # pass | fail | ambiguous | error
    reason: str
    evidence: list[str | None]  # one entry per step; None when the step produced no exchange
    tid: str | None = None
    signals: list[str] = field(default_factory=list)  # sensor records the oracle also read


@dataclass
class Finding:
    id: str
    fingerprint: str
    check: str
    title: str
    route: str
    status: Status
    reason: str
    passed: int
    attempts: int
    cwe: list[str]
    wstg: list[str]
    severity: str | None = None
    cvss: dict[str, Any] | None = None
    claims: list[Claim] = field(default_factory=list)
    repro: list[str] = field(default_factory=list)
    probe: dict[str, Any] = field(default_factory=dict)  # what was sent, so replay and reproduce can repeat it
    history: list[Attempt] = field(default_factory=list)

    @property
    def intermittent(self) -> bool:
        return self.status == "confirmed" and self.passed < self.attempts

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> Finding:
        data = dict(data)
        data["claims"] = [Claim(**c) for c in data.get("claims", [])]
        data["history"] = [Attempt(**a) for a in data.get("history", [])]
        return cls(**data)


def fingerprint(check_id: str, target_id: str, key: tuple[str, ...]) -> str:
    """Stable across runs: what was tested and where, never when or with which values."""
    return digest({"check": check_id, "target": target_id, "key": list(key)})


def at_least(severity: str | None, threshold: str) -> bool:
    return severity is not None and SEVERITY_ORDER.index(severity) >= SEVERITY_ORDER.index(threshold)
