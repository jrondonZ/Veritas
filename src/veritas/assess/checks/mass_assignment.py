"""Client-controlled protected field (lab L5): does an update accept a field the API doesn't document?

The probe writes a non-privileged sentinel value (never "admin") and reads it back.
Writing to access-control state is `sensitive`, so the probe always needs approval.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen

PROTECTED = ("role", "roles", "is_admin", "admin", "permissions", "group", "groups", "scope", "scopes")
JSON_HEADERS = (("Content-Type", "application/json"),)


class MassAssignment(Check):
    info = CheckInfo(
        id="veritas.check.mass-assignment",
        title="Client-controlled protected field",
        cwe=("CWE-915",),
        wstg=(),
        impact=Impact.SENSITIVE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N",
        remediation="Bind request bodies to an explicit allowlist of writable fields; never copy client "
        "input into access-control fields.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        if not ctx.identities:
            return []
        actor = ctx.identities[0].id
        probes = []
        for route in recon.routes:
            if route.method not in ("PUT", "PATCH") or route.path_params or "application/json" not in route.body_types:
                continue
            reader = recon.route("GET", route.template)
            if reader is None or not route.auth:
                continue
            for field in [f for f in reader.response_fields if f in PROTECTED and f not in route.request_fields][:1]:
                probes.append(
                    self.make_probe(
                        (route.method, route.template, field, "write"),
                        route.label,
                        f"write a non-privileged sentinel to {field!r} as {actor} and read it back",
                        self._steps(route.method, route.template, actor, field, ctx.marker(route.template, field), 1),
                        actor=actor,
                        field=field,
                        sentinel=ctx.marker(route.template, field),
                        method=route.method,
                        path=route.template,
                    )
                )
        return probes

    @staticmethod
    def _steps(method: str, path: str, actor: str, field: str, sentinel: str, attempt: int) -> tuple[Step, ...]:
        body = json.dumps({field: f"{sentinel}-{attempt}"})
        return (
            Step("before", "GET", path, identity=actor),
            Step("write", method, path, identity=actor, headers=JSON_HEADERS, body=body),
            Step("after", "GET", path, identity=actor),
        )

    def steps_for(self, probe: Probe, attempt: int) -> tuple[Step, ...]:
        p = probe.params
        return self._steps(p["method"], p["path"], p["actor"], p["field"], p["sentinel"], attempt)

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        before, write, after = exchanges
        p = probe.params
        field, value = p["field"], f"{p['sentinel']}-{attempt}"

        def current(response: Exchange) -> object:
            body = response.json()
            return body.get(field) if isinstance(body, dict) else None

        if current(before) == value:
            return OracleResult.ambiguous(f"{field!r} already held the sentinel before the write")
        if not write.ok:
            return OracleResult.failed(f"the write was refused with {write.status}")
        if current(after) != value:
            return OracleResult.failed(f"{field!r} was not changed by the write")
        return OracleResult.passed(
            f"{field!r} is client-writable",
            seen(
                f"{p['method']} {p['path']} accepted a client-supplied {field!r}; a following GET returned "
                f"{field} = {value!r}.",
                write,
                after,
            ),
            inferred=(f"A client may be able to set {field!r} to a privileged value; that was not attempted.",),
        )
