"""Probes: the requests a check plans to send, their impact, and the exact token envelope they need."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from ..core.impact import SAFE_METHODS, Impact, impact_rank, method_impact
from ..core.netpolicy import any_path_matches
from ..core.tokens import NetGrant
from ..scope.model import Target


@dataclass(frozen=True)
class Step:
    id: str
    method: str
    path: str  # path plus optional query, e.g. "/search?q=x"
    identity: str | None = None
    headers: tuple[tuple[str, str], ...] = ()
    body: str = ""

    @property
    def path_only(self) -> str:
        return urlsplit(self.path).path

    def wire(self, base_url: str) -> dict[str, Any]:
        """The executor's view of this step."""
        return {
            "id": self.id,
            "method": self.method,
            "url": base_url.rstrip("/") + self.path,
            "identity": self.identity,
            "headers": dict(self.headers),
            "body": self.body,
        }


@dataclass(frozen=True)
class Probe:
    check: str
    key: tuple[str, ...]  # fingerprint input: method, route template, parameter, sink
    route: str  # e.g. "GET /api/notes/{id}"
    description: str  # shown to approvers
    steps: tuple[Step, ...] = ()  # empty for passive probes
    evidence: tuple[str, ...] = ()  # existing evidence a passive probe evaluates
    params: dict[str, Any] = field(default_factory=dict, compare=False)

    @property
    def passive(self) -> bool:
        return not self.steps


def step_impact(step: Step, target: Target) -> Impact:
    impact = method_impact(step.method)
    if step.method in SAFE_METHODS and any_path_matches(target.unsafe_get, step.path_only):
        impact = Impact.MUTATE
    return impact


def probe_impact(check_impact: Impact, steps: tuple[Step, ...], target: Target) -> Impact:
    return max([check_impact, *(step_impact(s, target) for s in steps)], key=impact_rank)


def outside_scope(steps: tuple[Step, ...], target: Target) -> list[str]:
    """Steps the scope does not permit (the gateway would refuse them too)."""
    return [f"{s.method} {s.path_only}" for s in steps if not target.permits(s.method, s.path_only)]


def envelope(steps: tuple[Step, ...], target_id: str) -> list[NetGrant]:
    """Exactly what a script may send: one grant per (method, path) with its exact request count."""
    counts: dict[tuple[str, str], int] = defaultdict(int)
    identities: dict[tuple[str, str], set[str]] = defaultdict(set)
    for s in steps:
        key = (s.method, s.path_only)
        counts[key] += 1
        if s.identity:
            identities[key].add(s.identity)
    return [
        NetGrant(target=target_id, methods=[method], paths=[path], identities=sorted(identities[(method, path)]),
                 max_requests=counts[(method, path)])
        for method, path in sorted(counts)
    ]  # fmt: skip
