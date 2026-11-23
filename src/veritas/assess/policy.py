"""The gate: run, ask, or refuse each probe (docs/architecture.md §9.1 and §9.3)."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import Literal

from ..core.canonical import digest
from ..core.impact import Impact
from ..scope.model import AssessmentScope
from .probes import Probe

Verdict = Literal["allow", "needs_approval", "deny"]


@dataclass(frozen=True)
class Decision:
    verdict: Verdict
    rule: str
    reason: str


def decide(impact: Impact, scope: AssessmentScope, outside: Sequence[str]) -> Decision:
    if outside:
        return Decision("deny", "scope.outside", f"outside the scope: {', '.join(outside)}")
    if impact == Impact.SENSITIVE:
        return Decision("needs_approval", "sensitive.requires_approval", "sensitive actions always need approval")
    if impact in scope.policy.auto_approve:
        return Decision("allow", f"{impact}.auto_approved", f"{impact} is auto-approved by the scope")
    return Decision(
        "needs_approval",
        f"{impact}.requires_approval",
        f"{impact} is not auto-approved for a {scope.environment.kind} environment",
    )


@dataclass(frozen=True)
class ApprovalRequest:
    id: str  # A-0001
    run: str
    check: str
    impact: Impact
    probes: tuple[Probe, ...]  # one batch: same check, same impact
    attempts: int
    digest: str

    def lines(self) -> list[str]:
        first = self.probes[0]
        identities = sorted({s.identity for p in self.probes for s in p.steps if s.identity})
        requests = sorted({f"{s.method} {s.path_only}" for p in self.probes for s in p.steps})
        per_attempt = max(len(p.steps) for p in self.probes)
        return [
            f"APPROVAL {self.id} · run {self.run} · impact {self.impact}",
            f"  check    {self.check}",
            f"  intent   {first.description}"
            + (f" (and {len(self.probes) - 1} more like it)" if len(self.probes) > 1 else ""),
            f"  traffic  ≤ {per_attempt} requests per attempt, {self.attempts} attempts · {', '.join(requests)}",
            f"  as       {', '.join(identities) or 'anonymous'}",
            "  effect   changes synthetic state; the lab is reset from its snapshot at teardown",
            f"  digest   {self.digest} · single use",
        ]


Approver = Callable[[ApprovalRequest], bool]


def approval_digest(
    run: str, scope_digest: str, check: str, impact: Impact, probes: Sequence[Probe], attempts: int
) -> str:
    return digest(
        {
            "run": run,
            "scope": scope_digest,
            "check": check,
            "impact": str(impact),
            "attempts": attempts,
            "probes": [
                {"key": list(p.key), "steps": [[s.method, s.path, s.identity, s.body] for s in p.steps]} for p in probes
            ],
        }
    )


def deny_all(request: ApprovalRequest) -> bool:
    """CI and non-interactive runs: approvals are impossible, so the probes end blocked."""
    return False


def terminal_approver(echo: Callable[[str], None], ask: Callable[[str], str]) -> Approver:
    def approve(request: ApprovalRequest) -> bool:
        for line in request.lines():
            echo(line)
        if request.impact == Impact.SENSITIVE:
            return ask(f"Type {request.id} to approve, anything else to deny").strip() == request.id
        return ask("Approve? [y/N]").strip().lower() in ("y", "yes")

    return approve
