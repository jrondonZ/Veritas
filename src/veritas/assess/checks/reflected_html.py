"""Reflected HTML injection (lab L2): is a query parameter written into a page without encoding?

The probe value is an inert marker element, `<vrt-mk-...>`: a custom tag with no
attributes and no script. The oracle confirms only when an HTML parser builds that
element in markup context, which proves the missing encoding without running anything.
"""

from __future__ import annotations

from collections.abc import Sequence
from html.parser import HTMLParser
from urllib.parse import urlencode

from ...core.impact import Impact
from ..evidence import Exchange
from ..probes import Probe, Step
from ..recon import ReconResult
from .base import Check, CheckInfo, OracleResult, PlanContext, seen

# Elements whose content the HTML parsing algorithm treats as text, not markup.
_TEXT_ONLY = {"script", "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "noscript", "plaintext"}


class _MarkerFinder(HTMLParser):
    def __init__(self, marker: str):
        super().__init__(convert_charrefs=True)
        self.marker = marker
        self.stack: list[str] = []
        self.found = False
        self.text_only_hit: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == self.marker:
            inside = next((t for t in reversed(self.stack) if t in _TEXT_ONLY), None)
            if inside is None:
                self.found = True
            else:
                self.text_only_hit = inside
        self.stack.append(tag)

    def handle_endtag(self, tag: str) -> None:
        if tag in self.stack:
            while self.stack and self.stack.pop() != tag:
                pass

    def handle_data(self, data: str) -> None:
        if f"<{self.marker}>" in data and self.stack and self.stack[-1] in _TEXT_ONLY:
            self.text_only_hit = self.stack[-1]  # the stdlib parser keeps script/style content as data


def marker_context(html: str, marker: str) -> tuple[bool, str | None]:
    finder = _MarkerFinder(marker)
    finder.feed(html)
    finder.close()
    return finder.found, finder.text_only_hit


class ReflectedHtml(Check):
    info = CheckInfo(
        id="veritas.check.reflected-html",
        title="Reflected HTML injection",
        cwe=("CWE-79",),
        wstg=("WSTG-INPV-01",),
        impact=Impact.PROBE,
        cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        remediation="HTML-encode untrusted values for the context they are written into, and send a "
        "restrictive Content-Security-Policy.",
    )

    def plan(self, recon: ReconResult, ctx: PlanContext) -> list[Probe]:
        probes = []
        for route in recon.routes:
            if route.method != "GET" or route.path_params or not route.query_params:
                continue
            identity = ctx.identities[0].id if route.auth and ctx.identities else None
            for param in route.query_params:
                marker = ctx.marker(route.template, param)
                path = f"{route.template}?{urlencode({param: f'<{marker}>'})}"
                probes.append(
                    self.make_probe(
                        ("GET", route.template, param, "html"),
                        route.label,
                        f"reflect an inert marker through {param!r}",
                        (Step("reflect", "GET", path, identity=identity),),
                        marker=marker,
                        param=param,
                    )
                )
        return probes

    def evaluate(self, probe: Probe, exchanges: Sequence[Exchange], attempt: int) -> OracleResult:
        (page,) = exchanges
        marker, param = probe.params["marker"], probe.params["param"]
        if "html" not in page.content_type:
            return OracleResult.failed(f"the response is {page.content_type or 'untyped'}, not HTML")
        if f"<{marker}>" not in page.text:
            encoded = f"&lt;{marker}&gt;" in page.text
            return OracleResult.failed("the marker was HTML-encoded" if encoded else "the marker was not reflected")
        element, text_only = marker_context(page.text, marker)
        if not element:
            return OracleResult.ambiguous(
                f"the marker was reflected unencoded inside <{text_only}>, where it is not parsed as markup",
                seen(f"The marker sent in {param!r} was reflected unencoded inside <{text_only}>.", page),
            )
        observed = [
            seen(f"An inert marker sent in {param!r} was reflected unencoded and parsed as an element node.", page)
        ]
        inferred: tuple[str, ...] = ()
        if page.header("content-security-policy") is None:
            observed.append(seen("The response has no Content-Security-Policy header.", page))
            inferred = ("Script injection through this parameter is likely; it was not demonstrated.",)
        return OracleResult.passed("markup injection confirmed", *observed, inferred=inferred)
