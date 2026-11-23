"""Checks are deterministic recipes: `plan` turns recon into probes, `evaluate` is the oracle.

Oracles are pure functions of recorded evidence (gateway exchanges, and for sensor
checks the sensor's records): no network, no models (docs/architecture.md P3). A
check's probes prove that a control is missing using inert markers and synthetic
identities; they never demonstrate impact (§9.4).
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Literal

from ...core.impact import Impact
from ...scope.model import Identity, Target
from ..evidence import Exchange, SensorRecord
from ..probes import Probe, Step
from ..recon import ReconResult

Verdict = Literal["pass", "fail", "ambiguous", "error"]


@dataclass(frozen=True)
class Observation:
    text: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class OracleResult:
    verdict: Verdict
    reason: str
    observed: tuple[Observation, ...] = ()
    inferred: tuple[str, ...] = ()  # reasoned from every observation above

    @classmethod
    def passed(cls, reason: str, *observed: Observation, inferred: tuple[str, ...] = ()) -> OracleResult:
        return cls("pass", reason, observed, inferred)

    @classmethod
    def failed(cls, reason: str, *observed: Observation) -> OracleResult:
        return cls("fail", reason, observed)

    @classmethod
    def ambiguous(cls, reason: str, *observed: Observation) -> OracleResult:
        return cls("ambiguous", reason, observed)

    @classmethod
    def errored(cls, reason: str) -> OracleResult:
        """Not an oracle verdict: the probe could not be evaluated (a request was refused or failed)."""
        return cls("error", reason)


def seen(text: str, *items: Exchange | SensorRecord) -> Observation:
    return Observation(text, tuple(i.id for i in items))


@dataclass(frozen=True)
class PlanContext:
    target: Target
    identities: tuple[Identity, ...]
    tag: str  # stable per scope, so markers are comparable across runs
    sensors: frozenset[str] = frozenset()  # sensor kinds the scope declares for this target

    def marker(self, *parts: str) -> str:
        return "vrt-mk-" + hashlib.sha256("|".join((self.tag, *parts)).encode()).hexdigest()[:10]

    @property
    def login_paths(self) -> set[str]:
        return {i.login.path for i in self.identities}

    @property
    def canary_owners(self) -> list[Identity]:
        return sorted((i for i in self.identities if i.canary), key=lambda i: i.id)


@dataclass(frozen=True)
class CheckInfo:
    id: str
    title: str
    cwe: tuple[str, ...]
    wstg: tuple[str, ...]
    impact: Impact
    cvss: str
    remediation: str
    decisive: bool = True
    extra: dict[str, Any] = field(default_factory=dict)


class Check(ABC):
    info: ClassVar[CheckInfo]

    @property
    def id(self) -> str:
        return self.info.id

    @abstractmethod
    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]: ...

    def steps_for(self, probe: Probe, attempt: int) -> tuple[Step, ...]:
        """The steps of one attempt. Override when attempts must differ, for example to use a fresh sentinel."""
        return probe.steps

    @abstractmethod
    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult: ...

    def unknowns(self, probe: Probe, ctx: PlanContext) -> list[str]:
        return []

    def limitations(self, probe: Probe, ctx: PlanContext) -> list[str]:
        return []

    def make_probe(
        self,
        key: tuple[str, ...],
        route: str,
        description: str,
        steps: tuple[Step, ...] = (),
        evidence: tuple[str, ...] = (),
        **params: Any,
    ) -> Probe:
        return Probe(self.id, key, route, description, steps, evidence, params)


class SensorCheck(Check):
    """A check whose oracle also reads what a sensor saw (§9.4 rule 6: preferred where the operator owns the app).

    Around each attempt the kernel marks the sensor, sends the steps, and collects the entries that
    mention `markers(probe, attempt)`. Plan probes only when `ctx.sensors` includes `sensor`.
    """

    sensor: ClassVar[str]

    @abstractmethod
    def markers(self, probe: Probe, attempt: int) -> tuple[str, ...]: ...

    @abstractmethod
    def evaluate_signals(
        self, probe: Probe, exchanges: Sequence[Exchange], signals: Sequence[SensorRecord], attempt: int
    ) -> OracleResult: ...

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        return OracleResult.errored("this oracle needs the sensor's records")


def run_oracle(
    check: Check, probe: Probe, exchanges: Sequence[Exchange], signals: Sequence[SensorRecord], attempt: int
) -> OracleResult:
    """Decide one attempt. The runner and replay both call this, so they cannot diverge."""
    if isinstance(check, SensorCheck):
        return check.evaluate_signals(probe, exchanges, signals, attempt)
    return check.evaluate(probe, exchanges, attempt)
