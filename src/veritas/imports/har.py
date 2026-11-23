"""HAR 1.2 recordings (docs/architecture.md §8.3): an endpoint catalog with every secret value stripped.

A HAR file is a browser's record of real traffic, so it holds session cookies, bearer
tokens, and personal data. The catalog keeps the traffic's shape, never a value that could
authenticate or identify someone:

- request headers keep their names, and `Authorization` keeps only its scheme;
- cookies, query parameters, and form fields keep their names;
- JSON bodies keep field names and value types;
- path segments that look like IDs, email addresses, or tokens become placeholders;
- responses keep yes-or-no security facts (a CSP, framing protection, HSTS, nosniff, a
  stack trace in the body), and values only for `Server`, `X-Powered-By`, and CORS headers.

Bodies are read once, for their shape and those facts, then dropped. The file is hostile
input: it's size-capped, parsed by the standard library, and nothing in it is fetched.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, quote, unquote, urlsplit

MAX_HAR = 64 * 1024 * 1024
MAX_ENTRIES = 20_000
MAX_BODY = 2 * 1024 * 1024  # bodies larger than this keep no shape
MAX_FIELDS = 200
MAX_NAME = 64
DEFAULT_PORTS = {"http": 80, "https": 443}
_ID = re.compile(r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$", re.I)
_EMAIL = re.compile(r"^[^@\s/]+@[^@\s/]+\.[^@\s/]+$")
_TOKEN = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9_\-.~+=]{20,}$")
_NAME = re.compile(r"^[A-Za-z_$][\w$.\-\[\]]{0,63}$")
_AUTH_SCHEMES = {"bearer", "basic", "digest", "negotiate", "ntlm", "token", "apikey", "hoba", "mutual"}
_KEY_HEADER = re.compile(r"api[-_]?key|token|secret|session|auth", re.I)
SESSION_COOKIE = re.compile(r"sess|^sid$|_sid$|auth|jwt|token|login|remember", re.I)
NOT_SESSION = re.compile(r"csrf|xsrf", re.I)
_STACK = re.compile(
    r"\n\s+at [\w$.<>\[\] ]+ \(?[^\s()]+:\d+:\d+\)?|Traceback \(most recent call last\)|"
    r"\n\s+at [\w$.]+\([\w$]+\.java:\d+\)|Exception in thread \""
)
_CSP_META = re.compile(r"<meta[^>]+http-equiv\s*=\s*[\"']?content-security-policy", re.I)
_VERSION = re.compile(r"\d+\.\d+")


class HarError(Exception):
    """The file isn't a HAR recording Veritas can read."""


def _type(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int | float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object" if isinstance(value, dict) else "null"


def _shape_json(fields: dict[str, set[str]]) -> dict[str, list[str]]:
    return {name: sorted(kinds) for name, kinds in sorted(fields.items())}


def placeholder(segment: str) -> str | None:
    """The placeholder for a path segment or key that carries data rather than naming something."""
    text = unquote(segment)
    if _ID.match(text):
        return "{id}"
    if _EMAIL.match(text):
        return "{email}"
    if _TOKEN.match(text):
        return "{token}"
    return None


def template(path: str) -> str:
    """The path with data segments replaced, and every other segment percent-encoded the same way."""
    segments = (placeholder(s) or quote(unquote(s), safe="-._~!$&'()*+,;=:@") for s in (path or "/").split("/"))
    return "/".join(segments) or "/"


def _name(text: Any) -> str | None:
    """A field, parameter, or header name worth keeping: short, name-shaped, and not itself data."""
    if not isinstance(text, str) or not _NAME.match(text) or placeholder(text):
        return None
    return text


@dataclass
class Endpoint:
    method: str
    origin: str
    template: str
    count: int = 0
    statuses: set[int] = field(default_factory=set)
    query: set[str] = field(default_factory=set)
    request_types: set[str] = field(default_factory=set)
    request_fields: dict[str, set[str]] = field(default_factory=dict)
    response_types: set[str] = field(default_factory=set)
    response_fields: dict[str, set[str]] = field(default_factory=dict)
    returns_list: bool = False
    auth: set[str] = field(default_factory=set)
    cookies: dict[str, dict[str, Any]] = field(default_factory=dict)  # Set-Cookie by name: attributes, no value
    html: int = 0  # 2xx HTML responses
    html_without_csp: int = 0
    html_without_framing: int = 0
    without_nosniff: int = 0  # 2xx responses with a body
    https: int = 0
    https_without_hsts: int = 0
    stack_traces: int = 0
    server: set[str] = field(default_factory=set)
    powered_by: set[str] = field(default_factory=set)
    cors: set[tuple[str, bool, bool]] = field(default_factory=set)  # (allow-origin, credentials, cross-origin)

    @property
    def label(self) -> str:
        return f"{self.method} {self.template}"

    def to_json(self) -> dict[str, Any]:
        return {
            "method": self.method, "origin": self.origin, "template": self.template, "count": self.count,
            "statuses": sorted(self.statuses), "query": sorted(self.query),
            "request": {"types": sorted(self.request_types), "fields": _shape_json(self.request_fields)},
            "response": {"types": sorted(self.response_types), "fields": _shape_json(self.response_fields),
                         "list": self.returns_list},
            "auth": sorted(self.auth),
            "cookies": [{"name": k, **v} for k, v in sorted(self.cookies.items())],
            "security": {"html": self.html, "html_without_csp": self.html_without_csp,
                         "html_without_framing": self.html_without_framing, "without_nosniff": self.without_nosniff,
                         "https": self.https, "https_without_hsts": self.https_without_hsts,
                         "stack_traces": self.stack_traces, "server": sorted(self.server),
                         "powered_by": sorted(self.powered_by),
                         "cors": [{"allow_origin": o, "credentials": c, "cross_origin": x}
                                  for o, c, x in sorted(self.cors)]},
        }  # fmt: skip


def _headers(items: Any) -> list[tuple[str, str]]:
    out = []
    for h in items if isinstance(items, list) else []:
        if isinstance(h, dict) and isinstance(h.get("name"), str) and isinstance(h.get("value"), str):
            out.append((h["name"].strip().lower(), h["value"]))
    return out


def _media(value: str | None) -> str | None:
    if not value:
        return None
    media = value.split(";")[0].strip().lower()
    return media if re.match(r"^[\w.+-]+/[\w.+-]+$", media) else None


def _body_text(content: dict[str, Any]) -> str | None:
    text = content.get("text")
    if not isinstance(text, str) or len(text) > MAX_BODY * 2:
        return None
    if content.get("encoding") == "base64":
        try:
            raw = base64.b64decode(text, validate=False)
        except (binascii.Error, ValueError):
            return None
        return raw[:MAX_BODY].decode("utf-8", errors="replace")
    return text[:MAX_BODY]


def _json_shape(text: str) -> tuple[dict[str, str], bool] | None:
    try:
        value = json.loads(text)
    except (ValueError, RecursionError):
        return None
    listed = isinstance(value, list)
    if listed:
        value = next((v for v in value if isinstance(v, dict)), {})
    if not isinstance(value, dict):
        return {}, listed
    fields = {}
    for key, v in list(value.items())[:MAX_FIELDS]:
        name = _name(key)
        if name:
            fields[name] = _type(v)
    return fields, listed


def _merge(target: dict[str, set[str]], fields: dict[str, str]) -> None:
    for name, kind in fields.items():
        if name in target or len(target) < MAX_FIELDS:
            target.setdefault(name, set()).add(kind)


def _cookie(header: str) -> tuple[str, dict[str, Any]] | None:
    pair, *attributes = header.split(";")
    name = _name(pair.partition("=")[0].strip())
    if not name:
        return None
    attrs = {a.strip().partition("=")[0].lower(): a.strip().partition("=")[2].strip().lower() for a in attributes}
    clearing = attrs.get("max-age") == "0" or "1970" in attrs.get("expires", "")
    return name, {"httponly": "httponly" in attrs, "secure": "secure" in attrs,
                  "samesite": attrs.get("samesite") or None, "clearing": clearing}  # fmt: skip


@dataclass
class Catalog:
    creator: str | None = None
    entries: int = 0
    skipped: dict[str, int] = field(default_factory=dict)  # entries that couldn't be read: a gap in the catalog
    ignored: dict[str, int] = field(default_factory=dict)  # by URL scheme: entries that aren't HTTP traffic
    endpoints: dict[tuple[str, str, str], Endpoint] = field(default_factory=dict)

    def skip(self, why: str) -> None:
        self.skipped[why] = self.skipped.get(why, 0) + 1

    @property
    def first_party(self) -> list[str]:
        """Origins that served a page, or the busiest origin if none did: the app, not its CDNs and trackers."""
        pages = sorted({e.origin for e in self.endpoints.values() if e.html})
        if pages:
            return pages
        counts: dict[str, int] = {}
        for e in self.endpoints.values():
            counts[e.origin] = counts.get(e.origin, 0) + e.count
        return [max(sorted(counts), key=lambda o: counts[o])] if counts else []

    def to_json(self) -> dict[str, Any]:
        first = set(self.first_party)
        origins: dict[str, int] = {}
        for e in self.endpoints.values():
            origins[e.origin] = origins.get(e.origin, 0) + e.count
        ordered = sorted(self.endpoints.values(), key=lambda e: (e.origin, e.template, e.method))
        return {
            "kind": "har",
            "creator": self.creator,
            "entries": self.entries,
            "skipped": dict(sorted(self.skipped.items())),
            "ignored": dict(sorted(self.ignored.items())),
            "origins": [{"origin": o, "requests": n, "first_party": o in first} for o, n in sorted(origins.items())],
            "endpoints": [{**e.to_json(), "first_party": e.origin in first} for e in ordered],
        }


def _record(catalog: Catalog, entry: Any) -> None:
    request = entry.get("request") if isinstance(entry, dict) else None
    response = entry.get("response") if isinstance(entry, dict) else None
    if not isinstance(request, dict) or not isinstance(response, dict):
        catalog.skip("malformed entry")
        return
    method, url = request.get("method"), request.get("url")
    if not isinstance(method, str) or not re.match(r"^[A-Z]{3,10}$", method) or not isinstance(url, str):
        catalog.skip("malformed entry")
        return
    try:
        parts = urlsplit(url)
    except ValueError:
        catalog.skip("malformed entry")
        return
    if parts.scheme not in DEFAULT_PORTS:  # data:, blob:, ws:, extensions: not HTTP traffic the catalog describes
        scheme = re.sub(r"[^a-z0-9+.-]", "", parts.scheme.lower())[:20] or "none"
        catalog.ignored[scheme] = catalog.ignored.get(scheme, 0) + 1
        return
    origin = _origin(url)
    if origin is None:
        catalog.skip("malformed entry")
        return
    key = (origin, template(parts.path), method)
    e = catalog.endpoints.get(key) or catalog.endpoints.setdefault(key, Endpoint(method, origin, key[1]))
    e.count += 1
    status = response.get("status")
    if isinstance(status, int) and 100 <= status <= 599:
        e.statuses.add(status)
    for name, _ in parse_qsl(parts.query, keep_blank_values=True):
        if (n := _name(name)) and len(e.query) < MAX_FIELDS:
            e.query.add(n)

    sent = _headers(request.get("headers"))
    request_origin = None
    for name, value in sent:
        if name == "authorization":
            scheme = value.strip().split(" ")[0].lower()
            e.auth.add(scheme if scheme in _AUTH_SCHEMES else "other")
        elif name == "cookie":
            for pair in value.split(";"):
                cookie = _name(pair.partition("=")[0].strip())
                if cookie and SESSION_COOKIE.search(cookie) and not NOT_SESSION.search(cookie):
                    e.auth.add(f"cookie:{cookie}")
        elif name == "origin":
            request_origin = value.strip().lower()
        elif _KEY_HEADER.search(name) and (n := _name(name)):
            e.auth.add(f"header:{n}")
    post = request.get("postData")
    if isinstance(post, dict):
        media = _media(post.get("mimeType"))
        if media:
            e.request_types.add(media)
        params = post.get("params")
        if isinstance(params, list) and params:
            _merge(
                e.request_fields, {n: "string" for p in params if isinstance(p, dict) and (n := _name(p.get("name")))}
            )
        elif isinstance(post.get("text"), str) and len(post["text"]) <= MAX_BODY:
            if media == "application/x-www-form-urlencoded":
                _merge(e.request_fields, {n: "string" for k, _ in parse_qsl(post["text"]) if (n := _name(k))})
            elif media and media.endswith("json") and (shape := _json_shape(post["text"])):
                _merge(e.request_fields, shape[0])

    got = _headers(response.get("headers"))
    names = {n for n, _ in got}
    values = dict(got)
    raw = response.get("content")
    content: dict[str, Any] = raw if isinstance(raw, dict) else {}
    media = _media(values.get("content-type")) or _media(content.get("mimeType"))
    if media:
        e.response_types.add(media)
    for name, value in got:
        if name == "set-cookie" and (set_cookie := _cookie(value)):
            e.cookies[set_cookie[0]] = set_cookie[1]
    ok = isinstance(status, int) and 200 <= status < 300
    body = _body_text(content)
    csp = values.get("content-security-policy", "")
    if ok and media == "text/html":
        e.html += 1
        if not csp and not (body and _CSP_META.search(body)):
            e.html_without_csp += 1
        if "x-frame-options" not in names and "frame-ancestors" not in csp.lower():
            e.html_without_framing += 1
    if ok and media and values.get("x-content-type-options", "").strip().lower() != "nosniff":
        e.without_nosniff += 1
    if parts.scheme == "https":
        e.https += 1
        if "strict-transport-security" not in names:
            e.https_without_hsts += 1
    if body and _STACK.search(body):
        e.stack_traces += 1
    if body and ok and media and media.endswith("json") and (shape := _json_shape(body)):
        _merge(e.response_fields, shape[0])
        e.returns_list = e.returns_list or shape[1]
    for header, bucket in (("server", e.server), ("x-powered-by", e.powered_by)):
        if header in values and len(bucket) < 10:
            bucket.add(re.sub(r"[^\w .,;:/()+\-]", "", values[header]).strip()[:100])
    allow = values.get("access-control-allow-origin")
    if allow is not None and len(e.cors) < 10:
        credentials = values.get("access-control-allow-credentials", "").strip().lower() == "true"
        sender = _origin(request_origin) if request_origin else None
        allowed = re.sub(r"[^\w.:/*\-]", "", allow)[:200]
        e.cors.add((allowed, credentials, sender is not None and sender != origin))


def _origin(text: str) -> str | None:
    """`scheme://host:port` with the port spelled out, so origins compare exactly."""
    try:
        parts = urlsplit(text.strip())
        port = parts.port or DEFAULT_PORTS.get(parts.scheme, 0)
    except ValueError:
        return None
    if parts.scheme not in DEFAULT_PORTS or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.hostname.rstrip('.').lower()}:{port}"


def read_har(path: Path) -> Catalog:
    if path.stat().st_size > MAX_HAR:
        raise HarError(f"larger than {MAX_HAR // 2**20} MiB")
    return parse_har(path.read_bytes())


def parse_har(data: bytes) -> Catalog:
    if len(data) > MAX_HAR:
        raise HarError(f"larger than {MAX_HAR // 2**20} MiB")
    try:
        doc = json.loads(data)
    except (ValueError, RecursionError) as exc:
        raise HarError(f"not valid JSON: {str(exc)[:120]}") from exc
    log = doc.get("log") if isinstance(doc, dict) else None
    if not isinstance(log, dict) or not isinstance(log.get("entries"), list):
        raise HarError("no log.entries list, so not a HAR recording")
    catalog = Catalog()
    creator = log.get("creator")
    if isinstance(creator, dict) and isinstance(creator.get("name"), str):
        catalog.creator = creator["name"][:100]
    for entry in log["entries"][:MAX_ENTRIES]:
        catalog.entries += 1
        _record(catalog, entry)
    if len(log["entries"]) > MAX_ENTRIES:
        catalog.skipped["past the entry limit"] = len(log["entries"]) - MAX_ENTRIES
    return catalog


def version_disclosed(value: str) -> bool:
    return bool(_VERSION.search(value))
