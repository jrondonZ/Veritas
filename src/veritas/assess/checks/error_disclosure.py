"""Error details disclosed (lab L4; L8 is its ambiguous case): do malformed bodies leak stack traces?"""

from __future__ import annotations

import re
from collections.abc import Sequence

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen

SIGNATURES = (
    ("Node.js stack frame", re.compile(r"\n\s+at [^\n]*\([^)\n]*:\d+:\d+\)")),
    ("Python traceback", re.compile(r"Traceback \(most recent call last\):")),
    ("Java stack frame", re.compile(r"\n\s+at [\w.$]+\([\w$]+\.java:\d+\)")),
    (".NET stack frame", re.compile(r"\n\s+at [\w.`<>]+\(.*\) in .+:line \d+")),
    ("PHP stack trace", re.compile(r"Stack trace:\s*\n#0 ")),
)
MALFORMED = ('{"vrt": ', "[vrt-malformed")
JSON_HEADERS = (("Content-Type", "application/json"),)


def signature(text: str) -> str | None:
    return next((name for name, pattern in SIGNATURES if pattern.search(text)), None)


class ErrorDisclosure(Check):
    info = CheckInfo(
        id="veritas.check.error-disclosure",
        title="Error details disclosed",
        cwe=("CWE-209",),
        wstg=("WSTG-ERRH-01",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
        remediation="Return a generic error to clients and log the details server-side; reject malformed "
        "input with 400 before it reaches code that can throw.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        probes = []
        for route in recon.routes:
            if (
                route.method not in ("POST", "PUT", "PATCH")
                or route.path_params
                or "application/json" not in route.body_types
            ):
                continue
            identity = ctx.identities[0].id if route.auth and ctx.identities else None
            steps = tuple(
                Step(f"malformed-{i}", route.method, route.template, identity=identity, headers=JSON_HEADERS, body=body)
                for i, body in enumerate(MALFORMED, 1)
            )
            probes.append(
                self.make_probe(
                    (route.method, route.template, "body", "error"),
                    route.label,
                    "send two malformed JSON bodies",
                    steps,
                )
            )
        return probes

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        for response in exchanges:
            found = signature(response.text) if response.status >= 500 else None
            if found:
                return OracleResult.passed(
                    "stack trace disclosed",
                    seen(
                        f"A malformed JSON body to {probe.route} returned {response.status} with a {found} "
                        "in the response body.",
                        response,
                    ),
                )
        errors = [r for r in exchanges if r.status >= 500]
        statuses = ", ".join(str(r.status) for r in exchanges)
        if not errors:
            return OracleResult.failed(f"malformed bodies were answered with {statuses}, without error details")
        if len(errors) == len(exchanges) and len({r.response_body for r in errors}) > 1:
            return OracleResult.ambiguous(
                "500 bodies vary with input but match no error signature",
                seen(
                    f"Malformed bodies to {probe.route} returned {statuses} with bodies that differ by input.", *errors
                ),
            )
        return OracleResult.failed(f"server errors ({statuses}) carried no error details")
