"""Open redirect (lab L9): does a destination parameter send the browser to any site?

The probe puts an absolute URL under the reserved `.invalid` TLD into a parameter whose name
says it holds a destination (`next`, `url`, `return_to`, and so on). The executor never follows
redirects, so nothing is fetched from there. The oracle reads the Location header the app sent.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from urllib.parse import urlencode, urlsplit

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen

DESTINATION = re.compile(
    r"^(next|url|uri|redirect|redirect_?ur[il]|redirect_?to|return|return_?to|return_?url|continue|dest|destination|"
    r"goto|target|to|back|forward)$",
    re.I,
)


class OpenRedirect(Check):
    info = CheckInfo(
        id="veritas.check.open-redirect",
        title="Open redirect",
        cwe=("CWE-601",),
        wstg=("WSTG-CLNT-04",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        remediation="Redirect only to relative paths on the same site, or map a short key to a fixed list of "
        "destinations.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        probes = []
        for route in recon.routes:
            if route.method != "GET" or route.path_params:
                continue
            identity = ctx.identities[0].id if route.auth and ctx.identities else None
            for param in route.query_params:
                if not DESTINATION.match(param):
                    continue
                host = f"{ctx.marker(route.template, param, 'redirect')}.invalid"
                path = f"{route.template}?{urlencode({param: f'http://{host}/'})}"
                probes.append(
                    self.make_probe(
                        ("GET", route.template, param, "redirect"),
                        route.label,
                        f"ask {param!r} to send the browser to {host}, a host that can't exist",
                        (Step("redirect", "GET", path, identity=identity),),
                        host=host,
                        param=param,
                    )
                )
        return probes

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (response,) = exchanges
        host, param = probe.params["host"], probe.params["param"]
        location = (response.header("location") or "").strip()
        if not 300 <= response.status < 400 or not location:
            return OracleResult.failed(f"the response was {response.status}, not a redirect")
        try:
            went = (urlsplit(location).hostname or "").rstrip(".").lower()
        except ValueError:
            return OracleResult.ambiguous("the Location header couldn't be parsed as a URL")
        if went != host:
            return OracleResult.failed("the redirect stayed on the site" if not went else "the redirect went elsewhere")
        quoted = re.sub(r"[^\x21-\x7e]", "", location)[:200]
        text = f"{probe.route} with {param}=http://{host}/ answered {response.status} with Location: {quoted}, "
        return OracleResult.passed("the browser is sent to another site", seen(text + "outside the target.", response))
