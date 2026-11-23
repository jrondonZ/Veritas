"""Cross-site request forgery (lab L6): is a state-changing form post accepted from another site?

The probe sends the request a forged cross-site form would send: form-encoded, with a
signed-in session, a cross-site Origin under the reserved `.invalid` TLD, and no
anti-CSRF token. It creates one synthetic record, which the lab reset removes.
"""

from __future__ import annotations

from collections.abc import Sequence
from urllib.parse import urlencode

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import FORM_TYPE, ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen

CROSS_SITE = "http://cross-site.invalid"


class CrossSiteRequestForgery(Check):
    info = CheckInfo(
        id="veritas.check.csrf",
        title="Cross-site request forgery",
        cwe=("CWE-352",),
        wstg=("WSTG-SESS-05",),
        impact=Impact.MUTATE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N",
        remediation="Require an anti-CSRF token (or a custom request header) on state-changing requests, "
        "check Origin, and set SameSite on the session cookie.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        if not ctx.identities:
            return []
        victim = ctx.identities[0].id
        probes = []
        for route in recon.routes:
            if route.method not in ("POST", "PUT", "PATCH", "DELETE") or route.path_params or not route.auth:
                continue
            if FORM_TYPE not in route.body_types or route.template in ctx.login_paths:
                continue
            fields = route.request_fields or ("vrt",)
            body = urlencode({f: f"vrt-csrf-{i}" for i, f in enumerate(fields, 1)})
            headers = (("Content-Type", FORM_TYPE), ("Origin", CROSS_SITE), ("Referer", f"{CROSS_SITE}/"))
            step = Step("forged", route.method, route.template, identity=victim, headers=headers, body=body)
            probes.append(
                self.make_probe(
                    (route.method, route.template, "session", "csrf"),
                    route.label,
                    f"send a cross-site form post as {victim}",
                    (step,),
                    victim=victim,
                )
            )
        return probes

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (response,) = exchanges
        victim = probe.params["victim"]
        if response.ok:
            return OracleResult.passed(
                "cross-site request accepted",
                seen(
                    f"As {victim}, {probe.route} with Origin {CROSS_SITE} and no anti-CSRF token "
                    f"returned {response.status}.",
                    response,
                ),
            )
        return OracleResult.failed(f"the cross-site request was refused with {response.status}")
