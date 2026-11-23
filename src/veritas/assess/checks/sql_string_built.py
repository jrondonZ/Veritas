"""SQL statement built from request input (lab L7), decided from the app's own query log.

The probe sends an inert canary as a query parameter: letters, digits, and hyphens, which
are plain text in any SQL context. The query-log sensor then reports the statements that
mention it. A canary inside the statement text means the value was concatenated into SQL;
a canary only among the bound parameters means it was bound. No metacharacter and no
attack input is ever sent (docs/architecture.md §9.4 rule 6).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from urllib.parse import urlencode

from ...core.impact import Impact
from ..evidence import Exchange, SensorRecord
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import CheckInfo, OracleResult, PlanContext, SensorCheck, seen


class StringBuiltQuery(SensorCheck):
    sensor = "query-log"
    info = CheckInfo(
        id="veritas.check.sql-string-built",
        title="SQL statement built from request input",
        cwe=("CWE-89",),
        wstg=("WSTG-INPV-05",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        remediation="Bind request values as query parameters through placeholders; never concatenate them into "
        "SQL text. Map identifiers such as sort columns through an allowlist.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        if self.sensor not in ctx.sensors:
            return []
        probes = []
        for route in recon.routes:
            if route.method != "GET" or route.path_params or not route.query_params:
                continue
            identity = ctx.identities[0].id if route.auth and ctx.identities else None
            if route.auth and identity is None:
                continue
            for param in route.query_params:
                canary = ctx.marker("sql", route.template, param)
                probes.append(
                    self.make_probe(
                        ("GET", route.template, param, "sql-text"),
                        route.label,
                        f"send a canary in {param!r} and look for it in the app's SQL statement text",
                        self._steps(route.template, param, canary, identity, 1),
                        canary=canary,
                        param=param,
                        path=route.template,
                        identity=identity,
                    )
                )
        return probes

    @staticmethod
    def _steps(path: str, param: str, canary: str, identity: str | None, attempt: int) -> tuple[Step, ...]:
        return (Step("canary", "GET", f"{path}?{urlencode({param: f'{canary}-{attempt}'})}", identity=identity),)

    def steps_for(self, probe: Probe, attempt: int) -> tuple[Step, ...]:
        p = probe.params
        return self._steps(p["path"], p["param"], p["canary"], p["identity"], attempt)

    def markers(self, probe: Probe, attempt: int) -> tuple[str, ...]:
        return (f"{probe.params['canary']}-{attempt}",)

    def evaluate_signals(
        self, probe: Probe, exchanges: Sequence[Exchange], signals: Sequence[SensorRecord], attempt: int
    ) -> OracleResult:
        (sent,) = exchanges
        (record,) = signals
        (canary,) = self.markers(probe, attempt)
        param = probe.params["param"]
        in_text = [e for e in record.entries if canary in str(e.get("sql", ""))]
        bound = [e for e in record.entries if e not in in_text and canary in json.dumps(e.get("params"))]
        request = seen(
            f"GET {probe.params['path']} sent the canary {canary} in {param!r}; it returned {sent.status}.", sent
        )
        if in_text:
            return OracleResult.passed(
                "the canary appeared inside SQL statement text",
                request,
                seen(
                    "The app's query log shows the canary inside SQL statement text, not as a bound parameter.", record
                ),
                inferred=(f"{param!r} is concatenated into SQL, so SQL injection is likely; it was not attempted.",),
            )
        if bound:
            return OracleResult.failed(
                "the canary was bound as a query parameter",
                request,
                seen("The app's query log shows the canary only among a statement's bound parameters.", record),
            )
        if record.truncated or record.malformed:
            return OracleResult.ambiguous("the query log could not be read completely", request)
        if sent.status >= 400:  # a redirect was handled normally; an error may have stopped before the database
            return OracleResult.ambiguous(
                f"the request returned {sent.status} and no logged statement used it", request
            )
        return OracleResult.failed("no logged SQL statement used the parameter", request)

    def limitations(self, probe: Probe, ctx: PlanContext) -> list[str]:
        return ["Only statements the app writes to its query log are visible to the sensor."]
