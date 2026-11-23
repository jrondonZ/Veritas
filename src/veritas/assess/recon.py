"""Recon: map the in-scope surface from the target's OpenAPI document, a scope-bounded crawl, and recordings.

Recon sends only GET requests the scope permits. Links to other origins are recorded,
never fetched, and so are in-origin links the scope excludes or marks state-changing.
Recordings (HAR files the scope names) add the routes they show on the target's origin,
in scope, that the document and the crawl didn't find. Nothing in a recording is replayed.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from typing import Any, Protocol
from urllib.parse import parse_qs, urljoin, urlsplit

from ..core.impact import Impact
from ..core.netpolicy import any_path_matches, path_ambiguity
from ..imports.har import Catalog
from ..scope.model import DEFAULT_PORTS, Identity, Target
from .evidence import Exchange
from .probes import Step

MAX_PAGES = 50
MAX_DEPTH = 3
FORM_TYPE = "application/x-www-form-urlencoded"
_METHODS = ("get", "head", "post", "put", "patch", "delete", "options")
_NUMERIC = re.compile(r"^\d+$")


@dataclass(frozen=True)
class Route:
    method: str
    template: str
    path_params: tuple[str, ...] = ()
    query_params: tuple[str, ...] = ()
    body_types: tuple[str, ...] = ()
    request_fields: tuple[str, ...] = ()
    response_fields: tuple[str, ...] = ()
    returns_list: bool = False
    auth: bool = False
    source: str = "openapi"

    @property
    def label(self) -> str:
        return f"{self.method} {self.template}"


@dataclass(frozen=True)
class Fetched:
    """One response recon captured, so passive checks can judge it without sending anything."""

    evidence: str
    template: str
    status: int
    content_type: str

    @property
    def route(self) -> str:
        return f"GET {self.template}"


@dataclass
class ReconResult:
    routes: list[Route] = field(default_factory=list)
    pages: list[str] = field(default_factory=list)  # evidence IDs of what recon fetched
    fetched: list[Fetched] = field(default_factory=list)  # the same fetches, with what passive checks need
    external_links: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # in-origin links not followed, with the reason
    logins: dict[str, str] = field(default_factory=dict)  # identity -> evidence ID of its sign-in
    objects: dict[str, dict[str, list[str]]] = field(default_factory=dict)  # identity -> collection -> ids

    def route(self, method: str, template: str) -> Route | None:
        return next((r for r in self.routes if (r.method, r.template) == (method, template)), None)

    def to_json(self) -> dict[str, Any]:
        return asdict(self)


class StepRunner(Protocol):
    """Runs a script through the executor; returns one exchange (or None) per step."""

    async def run(self, steps: Sequence[Step], impact: Impact, purpose: str) -> list[Exchange | None]: ...

    def logins(self) -> dict[str, str]: ...


def template_for(path: str) -> str:
    return "/".join("{id}" if _NUMERIC.match(seg) else seg for seg in path.split("/")) or "/"


def _resolve(doc: dict[str, Any], schema: Any, depth: int = 0) -> dict[str, Any]:
    if not isinstance(schema, dict):
        return {}
    ref = schema.get("$ref")
    if isinstance(ref, str) and ref.startswith("#/") and depth < 10:
        node: Any = doc
        for part in ref[2:].split("/"):
            node = node.get(part, {}) if isinstance(node, dict) else {}
        return _resolve(doc, node, depth + 1)
    return schema


def _fields(doc: dict[str, Any], schema: Any) -> tuple[list[str], bool]:
    schema = _resolve(doc, schema)
    if schema.get("type") == "array":
        return sorted(_resolve(doc, schema.get("items")).get("properties", {})), True
    return sorted(schema.get("properties", {})), False


def parse_openapi(doc: dict[str, Any]) -> list[Route]:
    routes = []
    global_security = doc.get("security", [])
    for template, item in sorted((doc.get("paths") or {}).items()):
        if not isinstance(item, dict) or not str(template).startswith("/"):
            continue
        shared = item.get("parameters", [])
        for method in _METHODS:
            op = item.get(method)
            if not isinstance(op, dict):
                continue
            params = [p for p in [*shared, *op.get("parameters", [])] if isinstance(p, dict)]
            content = (op.get("requestBody") or {}).get("content") or {}
            request_fields = sorted(
                {f for media in content.values() for f in _fields(doc, (media or {}).get("schema"))[0]}
            )
            response_fields: list[str] = []
            returns_list = False
            for status, response in sorted((op.get("responses") or {}).items(), key=lambda kv: str(kv[0])):
                media = ((response or {}).get("content") or {}).get("application/json")
                if str(status).startswith("2") and media is not None:
                    response_fields, returns_list = _fields(doc, media.get("schema"))
                    break
            security = op.get("security", global_security)
            routes.append(
                Route(
                    method=method.upper(),
                    template=str(template),
                    path_params=tuple(str(p["name"]) for p in params if p.get("in") == "path"),
                    query_params=tuple(sorted(str(p["name"]) for p in params if p.get("in") == "query")),
                    body_types=tuple(sorted(content)),
                    request_fields=tuple(request_fields),
                    response_fields=tuple(response_fields),
                    returns_list=returns_list,
                    auth=isinstance(security, list) and any(bool(req) for req in security),
                )
            )
    return routes


class _LinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: v or "" for k, v in attrs}
        if tag in ("a", "link") and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "iframe") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").upper(), "fields": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None and a.get("name"):
            self._form["fields"].append(a["name"])

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._form = None


def extract_links(html: str) -> tuple[list[str], list[dict[str, Any]]]:
    parser = _LinkParser()
    parser.feed(html)
    parser.close()
    return parser.links, parser.forms


def skip_reason(target: Target, path: str, method: str = "GET") -> str | None:
    if path_ambiguity(path):
        return "ambiguous path"
    if method == "GET" and any_path_matches(target.unsafe_get, path):
        return "state-changing GET"
    if not target.permits(method, path):
        return "outside scope"
    return None


def _shape(template: str) -> str:
    """A template with its parameter names dropped, so `/notes/{id}` and `/notes/{noteId}` are the same route."""
    return re.sub(r"\{[^}/]*\}", "{}", template)


def recorded_routes(
    target: Target, recordings: Sequence[Catalog], known: dict[tuple[str, str], Route], result: ReconResult
) -> None:
    """Add the routes recordings show on the target's origin and in scope, unless recon already knows them."""
    origin = f"{target.scheme}://{target.host}:{target.port}"
    have = {(method, _shape(template)) for method, template in known}
    for catalog in recordings:
        for e in sorted(catalog.endpoints.values(), key=lambda e: (e.origin, e.template, e.method)):
            if e.origin != origin:
                result.external_links.append(f"{e.origin}{e.template}")
                continue
            reason = skip_reason(target, e.template, e.method)
            if reason:
                result.skipped.append(f"{e.method} {e.template} (recording, {reason})")
                continue
            if (e.method, _shape(e.template)) in have:
                continue
            have.add((e.method, _shape(e.template)))
            known[(e.method, e.template)] = Route(
                method=e.method,
                template=e.template,
                path_params=tuple(re.findall(r"\{([^}/]+)\}", e.template)),
                query_params=tuple(sorted(e.query)),
                body_types=tuple(sorted(e.request_types)),
                request_fields=tuple(sorted(e.request_fields)),
                response_fields=tuple(sorted(e.response_fields)),
                returns_list=e.returns_list,
                auth=bool(e.auth),
                source="recording",
            )


async def run_recon(
    runner: StepRunner, target: Target, identities: Sequence[Identity], recordings: Sequence[Catalog] = ()
) -> ReconResult:
    result = ReconResult()
    routes: dict[tuple[str, str], Route] = {}
    origin = (target.scheme, target.host, target.port)

    if target.openapi:
        (doc,) = await runner.run([Step("openapi", "GET", target.openapi)], Impact.PROBE, "recon: OpenAPI document")
        if doc is not None:
            result.pages.append(doc.id)
            body = doc.json()
            if doc.ok and isinstance(body, dict):
                routes.update({(r.method, r.template): r for r in parse_openapi(body)})

    seen, frontier, depth = {"/"}, ["/"], 0
    while frontier and depth < MAX_DEPTH and len(result.pages) < MAX_PAGES:
        steps = [Step(f"page-{i}", "GET", p) for i, p in enumerate(frontier[: MAX_PAGES - len(result.pages)])]
        found: list[str] = []
        for step, page in zip(steps, await runner.run(steps, Impact.PROBE, f"recon: crawl depth {depth}"), strict=True):
            if page is None:
                continue
            result.pages.append(page.id)
            template = template_for(step.path_only)
            result.fetched.append(Fetched(page.id, template, page.status, page.content_type))
            query = tuple(sorted(parse_qs(urlsplit(step.path).query)))
            routes.setdefault(("GET", template), Route("GET", template, query_params=query, source="crawl"))
            if "html" not in page.content_type:
                continue
            links, forms = extract_links(page.text)
            for href in links:
                parts = urlsplit(urljoin(target.base_url.rstrip("/") + step.path, href))
                host_port = ((parts.hostname or "").rstrip("."), parts.port or DEFAULT_PORTS.get(parts.scheme, 0))
                if (parts.scheme, *host_port) != origin:
                    result.external_links.append(parts.geturl())
                    continue
                path = parts.path or "/"
                reason = skip_reason(target, path)
                if reason:
                    result.skipped.append(f"{path} ({reason})")
                    continue
                full = path + (f"?{parts.query}" if parts.query else "")
                if full not in seen:
                    seen.add(full)
                    found.append(full)
            for form in forms:
                path = urlsplit(urljoin(target.base_url.rstrip("/") + step.path, form["action"])).path or "/"
                method, fields = form["method"], tuple(sorted(set(form["fields"])))
                if method == "GET":
                    routes.setdefault(
                        ("GET", template_for(path)),
                        Route("GET", template_for(path), query_params=fields, source="form"),
                    )
                else:
                    routes.setdefault(
                        (method, template_for(path)),
                        Route(
                            method, template_for(path), body_types=(FORM_TYPE,), request_fields=fields, source="form"
                        ),
                    )
        frontier, depth = sorted(found), depth + 1

    recorded_routes(target, recordings, routes, result)
    templates = {t for _, t in routes}
    collections = sorted(
        r.template
        for r in routes.values()
        if r.method == "GET"
        and r.auth
        and r.returns_list
        and not r.path_params
        and any(t.startswith(r.template + "/{") for t in templates)
    )
    for collection in collections:
        steps = [Step(i.id, "GET", collection, identity=i.id) for i in identities]
        listed = await runner.run(steps, Impact.PROBE, f"recon: list {collection} for each identity")
        for identity, page in zip(identities, listed, strict=True):
            items = page.json() if page is not None and page.ok else None
            ids = [str(x["id"]) for x in items if isinstance(x, dict) and "id" in x] if isinstance(items, list) else []
            result.objects.setdefault(identity.id, {})[collection] = ids

    result.logins = runner.logins()
    result.routes = sorted(routes.values(), key=lambda r: (r.template, r.method))
    result.external_links = sorted(set(result.external_links))
    result.skipped = sorted(set(result.skipped))
    return result
