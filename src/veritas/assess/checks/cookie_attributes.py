"""Session cookie without protective attributes (lab L3). Passive: it judges the gateway's sign-ins."""

from __future__ import annotations

from collections.abc import Sequence

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe
from ..recon import ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen


def cookie_attributes(exchange: Exchange, name: str) -> set[str] | None:
    """Lower-cased attribute names (and samesite value) of a Set-Cookie for `name`, or None if not set."""
    for header in exchange.headers("set-cookie"):
        pair, *attributes = header.split(";")
        if pair.strip().partition("=")[0] == name:
            found = set()
            for attribute in attributes:
                key, _, value = attribute.strip().partition("=")
                found.add(key.lower())
                if key.lower() == "samesite":
                    found.add(f"samesite={value.strip().lower()}")
            return found
    return None


class CookieAttributes(Check):
    info = CheckInfo(
        id="veritas.check.cookie-attributes",
        title="Session cookie without protective attributes",
        cwe=("CWE-1004", "CWE-1275"),
        wstg=("WSTG-SESS-02",),
        impact=Impact.OBSERVE,
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        remediation="Set HttpOnly and SameSite=Lax (or Strict) on session cookies, and Secure once the site "
        "is served over https.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        logins = sorted(recon.logins.items())
        if not logins:
            return []
        path = sorted(ctx.login_paths)[0]
        evidence = tuple(e for _, e in logins)
        return [
            self.make_probe(
                ("SET-COOKIE", path, "session", "attributes"),
                f"POST {path}",
                "inspect the session cookie set at sign-in",
                evidence=evidence,
            )
        ]

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (signin,) = exchanges
        names = [h.split(";")[0].partition("=")[0].strip() for h in signin.headers("set-cookie")]
        if not names:
            return OracleResult.ambiguous("the sign-in response set no cookie")
        problems = []
        for name in names:
            attributes = cookie_attributes(signin, name) or set()
            missing = [
                label
                for label, ok in (
                    ("HttpOnly", "httponly" in attributes),
                    ("SameSite", "samesite" in attributes and "samesite=none" not in attributes),
                )
                if not ok
            ]
            if missing:
                problems.append(seen(f"The {name} cookie set by {probe.route} lacks {' and '.join(missing)}.", signin))
        if problems:
            return OracleResult.passed("session cookie lacks protective attributes", *problems)
        return OracleResult.failed("session cookies set HttpOnly and SameSite")

    def limitations(self, probe: Probe, ctx: PlanContext) -> list[str]:
        if ctx.target.scheme == "http":
            return ["The Secure attribute was not assessed because the target is served over http."]
        return []
