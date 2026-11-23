"""Missing response protections, judged from what recon already fetched. Passive: nothing new is sent.

Page protections (a Content-Security-Policy, framing protection) are judged on each HTML page
recon fetched. Site-wide ones (nosniff, HSTS, a server banner) are judged on the crawl's first
successful response, the site's front door. Precision comes first: only a missing protection
counts, not a weak one, so a page with any enforced policy passes.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import ClassVar

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe
from ..recon import Fetched, ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen

_LOW = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # a missing defense-in-depth header
_CSP_META = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']?content-security-policy", re.I)
_VERSION = re.compile(r"\d+\.\d+")


def _ok(f: Fetched) -> bool:
    return 200 <= f.status < 300


def html_pages(recon: ReconResult) -> dict[str, list[Fetched]]:
    """The successful HTML responses recon fetched, by route."""
    out: dict[str, list[Fetched]] = {}
    for f in recon.fetched:
        if _ok(f) and f.content_type == "text/html":
            out.setdefault(f.route, []).append(f)
    return out


def front_door(recon: ReconResult) -> Fetched | None:
    return next((f for f in recon.fetched if _ok(f)), None)


def _clean(value: str) -> str:
    """A header value from the target, safe to quote in a claim."""
    return re.sub(r"[^\w .,;:/()+\-]", "", value)[:100]


class _PageCheck(Check):
    """One passive probe per HTML page, deciding on each recorded response of it."""

    protection: ClassVar[str]

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        return [
            self.make_probe(
                ("GET", fetches[0].template, "response", self.protection),
                route,
                f"inspect {len(fetches)} recorded response(s) for {self.protection}",
                evidence=tuple(f.evidence for f in fetches),
            )
            for route, fetches in sorted(html_pages(recon).items())
        ]


class _SiteCheck(Check):
    """One passive probe per target, deciding on the front door's recorded response."""

    protection: ClassVar[str]

    def applies(self, ctx: PlanContext) -> bool:
        return True

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        door = front_door(recon)
        if door is None or not self.applies(ctx):
            return []
        return [
            self.make_probe(
                ("GET", door.template, "response", self.protection),
                door.route,
                f"inspect the site's first recorded response for {self.protection}",
                evidence=(door.evidence,),
            )
        ]


class ContentSecurityPolicy(_PageCheck):
    protection = "content-security-policy"
    info = CheckInfo(
        id="veritas.check.csp",
        title="Page served without a Content-Security-Policy",
        cwe=("CWE-693",),
        wstg=("WSTG-CONF-12",),
        impact=Impact.OBSERVE,
        cvss=_LOW,
        remediation="Send a Content-Security-Policy header with a restrictive default-src on every page.",
    )

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (page,) = exchanges
        if page.header("content-security-policy"):
            return OracleResult.failed("the page sends a Content-Security-Policy")
        if _CSP_META.search(page.text):
            return OracleResult.failed("the page sets a Content-Security-Policy in a meta tag")
        only = (
            " (only a report-only policy, which isn't enforced)"
            if page.header("content-security-policy-report-only")
            else ""
        )
        return OracleResult.passed(
            "no Content-Security-Policy",
            seen(f"The response to {probe.route} has no Content-Security-Policy{only}.", page),
        )


class FramingProtection(_PageCheck):
    protection = "framing protection"
    info = CheckInfo(
        id="veritas.check.framing",
        title="Page can be framed by another site",
        cwe=("CWE-1021",),
        wstg=("WSTG-CLNT-09",),
        impact=Impact.OBSERVE,
        cvss=_LOW,
        remediation="Send Content-Security-Policy: frame-ancestors 'self' (or 'none'), or X-Frame-Options: DENY.",
    )

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (page,) = exchanges
        if (page.header("x-frame-options") or "").strip().lower() in ("deny", "sameorigin"):
            return OracleResult.failed("X-Frame-Options forbids framing")
        if "frame-ancestors" in (page.header("content-security-policy") or "").lower():
            return OracleResult.failed("the Content-Security-Policy sets frame-ancestors")
        text = f"The response to {probe.route} has neither X-Frame-Options nor a frame-ancestors directive, so any "
        return OracleResult.passed("the page can be framed", seen(text + "site can frame it.", page))


class ContentTypeOptions(_SiteCheck):
    protection = "nosniff"
    info = CheckInfo(
        id="veritas.check.content-type-options",
        title="Responses without X-Content-Type-Options: nosniff",
        cwe=("CWE-693",),
        wstg=("WSTG-CONF-14",),
        impact=Impact.OBSERVE,
        cvss=_LOW,
        remediation="Send X-Content-Type-Options: nosniff with every response.",
    )

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (page,) = exchanges
        if (page.header("x-content-type-options") or "").strip().lower() == "nosniff":
            return OracleResult.failed("the response sends X-Content-Type-Options: nosniff")
        text = f"The response to {probe.route} has no X-Content-Type-Options: nosniff, so browsers may guess its "
        return OracleResult.passed("no X-Content-Type-Options: nosniff", seen(text + "content type.", page))


class StrictTransportSecurity(_SiteCheck):
    protection = "HSTS"
    info = CheckInfo(
        id="veritas.check.hsts",
        title="https site without Strict-Transport-Security",
        cwe=("CWE-319",),
        wstg=("WSTG-CONF-07",),
        impact=Impact.OBSERVE,
        cvss="CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
        remediation="Send Strict-Transport-Security with a max-age of at least six months.",
    )

    def applies(self, ctx: PlanContext) -> bool:
        return ctx.target.scheme == "https"  # HSTS means nothing over plain http

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (page,) = exchanges
        policy = (page.header("strict-transport-security") or "").lower()
        age = re.search(r"max-age\s*=\s*\"?(\d+)", policy)
        if age and int(age.group(1)) > 0:
            return OracleResult.failed("the response sends Strict-Transport-Security")
        return OracleResult.passed(
            "no Strict-Transport-Security",
            seen(f"The https response to {probe.route} has no Strict-Transport-Security with a max-age.", page),
        )


class ServerBanner(_SiteCheck):
    protection = "a server banner"
    info = CheckInfo(
        id="veritas.check.server-banner",
        title="Server software named in response headers",
        cwe=("CWE-497",),
        wstg=("WSTG-INFO-02",),
        impact=Impact.OBSERVE,
        cvss="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
        remediation="Remove X-Powered-By, and the version from Server.",
    )

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (page,) = exchanges
        named = []
        server, powered = page.header("server"), page.header("x-powered-by")
        if server and _VERSION.search(server):
            named.append(f"Server: {_clean(server)}")
        if powered:
            named.append(f"X-Powered-By: {_clean(powered)}")
        if not named:
            return OracleResult.failed("no X-Powered-By, and no version in Server")
        return OracleResult.passed(
            "the software is named",
            seen(f"The response to {probe.route} names its software: {'; '.join(named)}.", page),
        )
