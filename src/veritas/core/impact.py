"""Shared kernel types."""

from __future__ import annotations

from enum import StrEnum


class Impact(StrEnum):
    OBSERVE = "observe"  # no target traffic: static analysis, recorded data
    PROBE = "probe"  # read-only requests with inert inputs
    MUTATE = "mutate"  # changes target state; synthetic records only
    SENSITIVE = "sensitive"  # may expose secrets or personal data, or change access-control state
    # No member exists for destructive or out-of-scope actions, so they cannot be requested.


_RANK = {Impact.OBSERVE: 0, Impact.PROBE: 1, Impact.MUTATE: 2, Impact.SENSITIVE: 3}


def impact_rank(impact: Impact | str) -> int:
    return _RANK[Impact(impact)]


def impact_allows(ceiling: Impact | str, needed: Impact | str) -> bool:
    return impact_rank(ceiling) >= impact_rank(needed)


HTTP_METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


def method_impact(method: str) -> Impact:
    return Impact.PROBE if method.upper() in SAFE_METHODS else Impact.MUTATE
