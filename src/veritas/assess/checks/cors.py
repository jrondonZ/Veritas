"""Credentialed cross-origin reads (lab L10): may another site read this API with the user's session?

The probe repeats a signed-in GET twice. First it sends an Origin under the reserved
`.invalid` TLD, which no site can own, then `Origin: null`, which sandboxed frames send. A
response that allows exactly that origin and allows credentials lets any page the user
visits read their data. Nothing is changed, and nothing leaves the lab.
"""

from __future__ import annotations

from collections.abc import Sequence

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen


class CrossOriginReads(Check):
    info = CheckInfo(
        id="veritas.check.cors",
        title="Credentialed cross-origin reads allowed",
        cwe=("CWE-942",),
        wstg=("WSTG-CLNT-07",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
        remediation="Allow credentialed cross-origin requests only from an explicit list of trusted origins. "
        "Never echo the request's Origin back, and never allow null.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        if not ctx.identities:
            return []
        reader = ctx.identities[0].id
        probes = []
        for route in recon.routes:
            if route.method != "GET" or route.path_params or not route.auth:
                continue
            origin = f"http://{ctx.marker(route.template, 'origin')}.invalid"
            steps = (
                Step("foreign", "GET", route.template, identity=reader, headers=(("Origin", origin),)),
                Step("null", "GET", route.template, identity=reader, headers=(("Origin", "null"),)),
            )
            probes.append(
                self.make_probe(
                    ("GET", route.template, "origin", "cors"),
                    route.label,
                    f"read as {reader} with a foreign Origin, then with Origin: null",
                    steps,
                    origin=origin,
                    reader=reader,
                )
            )
        return probes

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        foreign, null = exchanges
        allowed = []
        for response, origin in ((foreign, probe.params["origin"]), (null, "null")):
            allow = (response.header("access-control-allow-origin") or "").strip()
            credentials = (response.header("access-control-allow-credentials") or "").strip().lower() == "true"
            if response.ok and allow == origin and credentials:
                allowed.append(
                    seen(
                        f"As {probe.params['reader']}, {probe.route} with Origin: {origin} answered {response.status} "
                        f"with Access-Control-Allow-Origin: {origin} and Access-Control-Allow-Credentials: true.",
                        response,
                    )
                )
        if not allowed:
            return OracleResult.failed("neither a foreign origin nor null may read it with credentials")
        return OracleResult.passed(
            "another origin may read it with credentials",
            *allowed,
            inferred=("A page on any site the signed-in user visits can read this response with their session.",),
        )
