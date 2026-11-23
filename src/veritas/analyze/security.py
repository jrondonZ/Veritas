"""Security findings in code (docs/architecture.md §8.3 and §12): candidates from Program Model facts.

Rules read what the engines recorded and turn it into candidate findings. Each has a
location, a CWE, typed claims citing the engine record, a fix, its severity if confirmed,
and, where one exists, the Assess check that can prove it on a running target. This is
where reverse engineering meets the pentest: Analyze points at the code, and Assess
proves the control failure live.

A candidate is not a confirmed vulnerability. The rules are deliberately narrow, and
precision comes before recall. Whole classes need a running target and are named in
`DYNAMIC_ONLY`, so the report says what static analysis did not cover instead of
implying it found everything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .. import __version__
from ..core.canonical import sha256_hex
from ..findings.cvss import base_score, severity
from ..imports.har import NOT_SESSION, SESSION_COOKIE, version_disclosed
from ..models.redact import PATTERNS
from .program import FileModel

PRODUCER = f"rule:veritas.analyze.security@{__version__}"
RESPONSE_CALL = ("send", "write", "end", "json", "respond", "reply", "render")
SECURITY_NAMES = ("token", "secret", "session", "password", "nonce", "salt", "key", "otp", "csrf")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    cwe: tuple[str, ...]
    cvss: str  # the score it would have if confirmed
    remediation: str
    confirms_with: str | None = None  # the Assess check that proves it on a running target


_WEB_XSS = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
_ELECTRON = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H"
_HEADER = "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:N"  # a missing defense-in-depth header
_HARDENING = "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N"  # it makes another flaw easier to exploit
RULES = {
    r.id: r
    for r in (
        Rule("html-from-input", "Request input written into HTML without encoding", ("CWE-79",), _WEB_XSS,
             "Encode untrusted values for the HTML context they're written into, or render through a template engine "
             "that escapes by default.", "veritas.check.reflected-html"),
        Rule("sql-from-input", "SQL text built from request input", ("CWE-89",),
             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
             "Pass request values as bound parameters through placeholders; never build SQL text from them.",
             "veritas.check.sql-string-built"),
        Rule("stack-in-response", "Error stack written into a response", ("CWE-209",),
             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N",
             "Log the error on the server and send the client a generic message with a correlation ID.",
             "veritas.check.error-disclosure"),
        Rule("cookie-attributes", "Cookie set without HttpOnly or SameSite", ("CWE-1004", "CWE-1275"),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
             "Set HttpOnly and SameSite=Lax (or Strict) on session cookies, and Secure once the site uses https.",
             "veritas.check.cookie-attributes"),
        Rule("dynamic-code", "Code built at run time is executed", ("CWE-95",),
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "Don't evaluate strings as code; use data and a fixed dispatch table instead."),
        Rule("shell-command", "Shell command built from a variable", ("CWE-78",),
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "Run programs with execFile or spawn and an argument array, without a shell; allowlist the values.",
             "veritas.check.command-from-input"),
        Rule("path-from-input", "File path built from request input", ("CWE-22",),
             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
             "Resolve paths against a fixed base directory and refuse results outside it; prefer IDs mapped to files.",
             "veritas.check.path-from-input"),
        Rule("request-from-input", "Outbound request URL taken from request input", ("CWE-918",),
             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N",
             "Request only hosts on an allowlist, or map a key to fixed URLs; refuse private and loopback addresses.",
             "veritas.check.request-from-input"),
        Rule("redirect-from-input", "Redirect target taken from request input", ("CWE-601",), _WEB_XSS,
             "Redirect only to relative paths or to an allowlist of destinations.", "veritas.check.open-redirect"),
        Rule("dom-html", "Markup written into the page from a variable", ("CWE-79",), _WEB_XSS,
             "Set textContent instead of innerHTML, or sanitize with a vetted library before inserting markup."),
        Rule("weak-hash", "MD4, MD5, or SHA-1 used", ("CWE-328",), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "Use SHA-256 or better for integrity, and scrypt, Argon2, or bcrypt for passwords."),
        Rule("weak-random", "Math.random used for a security value", ("CWE-338",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
             "Use crypto.randomBytes or crypto.getRandomValues for tokens, IDs, and secrets."),
        Rule("tls-unverified", "TLS certificate verification turned off", ("CWE-295",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N",
             "Keep certificate verification on; trust a private CA explicitly instead of disabling checks."),
        Rule("hardcoded-secret", "Secret embedded in the code", ("CWE-798",),
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
             "Move the secret to the environment or a secret store, and rotate it."),
        Rule("electron-node-integration", "Electron window with Node.js integration in the page", ("CWE-693",),
             _ELECTRON, "Set nodeIntegration: false and expose only what the page needs through a preload script."),
        Rule("electron-context-isolation", "Electron window without context isolation", ("CWE-693",), _ELECTRON,
             "Keep contextIsolation: true so page scripts can't reach the preload script's privileges."),
        Rule("electron-sandbox", "Electron window without the renderer sandbox", ("CWE-693",), _ELECTRON,
             "Keep sandbox: true for every window that loads content."),
        Rule("electron-web-security", "Electron window with web security turned off", ("CWE-693",), _ELECTRON,
             "Keep webSecurity: true and allowRunningInsecureContent: false."),
        Rule("open-external", "shell.openExternal called with a variable", ("CWE-20",), _ELECTRON,
             "Open only URLs that match an allowlist of https origins."),
        Rule("electron-page-csp", "Electron page without a Content-Security-Policy", ("CWE-693",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:N",
             "Add a restrictive Content-Security-Policy meta tag (default-src 'self') to every page the app loads."),
        # From compiled code: .NET metadata and IL, and native headers and imports.
        Rule("insecure-deserialization", "Binary formatter deserializes data", ("CWE-502",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
             "Don't use BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter, or "
             "ObjectStateFormatter. Use a serializer bound to known types, such as System.Text.Json."),
        Rule("sql-concatenation", "SQL text built by joining strings", ("CWE-89",),
             "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
             "Pass values as command parameters (SqlParameter, AddWithValue) instead of joining them into the text.",
             "veritas.check.sql-string-built"),
        Rule("weak-cipher", "DES or RC2 used", ("CWE-327",), "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "Use AES-GCM with keys from a vetted key-management API."),
        Rule("dangerous-function", "Function that can't be used safely is imported", ("CWE-242",),
             "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
             "Replace gets with fgets (or getline) and a bounded buffer."),
        Rule("banned-api", "Unbounded string function imported", ("CWE-676",), _HARDENING,
             "Use the bounded forms (snprintf, strncpy_s, strlcpy) and check lengths."),
        Rule("binary-no-aslr", "Executable without address space layout randomization", ("CWE-693",), _HARDENING,
             "Build with ASLR: /DYNAMICBASE for PE, -fPIE -pie for ELF, and position-independent linking on macOS."),
        Rule("binary-no-dep", "Executable stack, or no data execution prevention", ("CWE-693",), _HARDENING,
             "Link with /NXCOMPAT for PE or -z noexecstack for ELF, and don't allow stack execution on macOS."),
        Rule("binary-wx-memory", "Memory mapped both writable and executable", ("CWE-693",), _HARDENING,
             "Keep code and data in separate sections, and never map one writable and executable."),
        Rule("binary-no-safeseh", "32-bit Windows executable without SafeSEH", ("CWE-693",), _HARDENING,
             "Link with /SAFESEH, or build for 64-bit."),
        Rule("insecure-rpath", "Library search path that isn't absolute", ("CWE-426",),
             "CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H",
             "Use absolute RPATH and RUNPATH entries, or ones relative to $ORIGIN or @loader_path."),
        # From recorded traffic: what the app's own responses show.
        Rule("cookie-secure", "Session cookie without Secure on an https site", ("CWE-614",),
             "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
             "Set Secure on every cookie an https site sets, so it never travels over plain http."),
        Rule("csp-missing", "Page served without a Content-Security-Policy", ("CWE-693",), _HEADER,
             "Send a Content-Security-Policy header with a restrictive default-src on every page.",
             "veritas.check.csp"),
        Rule("framing-unprotected", "Page can be framed by another site", ("CWE-1021",), _HEADER,
             "Send Content-Security-Policy: frame-ancestors 'self', or X-Frame-Options: DENY.",
             "veritas.check.framing"),
        Rule("nosniff-missing", "Response without X-Content-Type-Options: nosniff", ("CWE-693",), _HEADER,
             "Send X-Content-Type-Options: nosniff with every response.", "veritas.check.content-type-options"),
        Rule("hsts-missing", "https site without Strict-Transport-Security", ("CWE-319",),
             "CVSS:3.1/AV:A/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
             "Send Strict-Transport-Security with a max-age of at least six months.", "veritas.check.hsts"),
        Rule("version-disclosure", "Server software named in response headers", ("CWE-497",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "Remove X-Powered-By, and the version from Server.", "veritas.check.server-banner"),
        Rule("credential-in-url", "Credential sent in a URL query string", ("CWE-598",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
             "Send credentials in a header or a request body. URLs end up in logs, history, and Referer headers."),
        Rule("cors-null-origin", "CORS allows credentialed reads from the null origin", ("CWE-942",),
             "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
             "Never allow the null origin. List the exact origins that may read responses.", "veritas.check.cors"),
        # From the inventory of bundled packages and the operator's imported advisories (analyze/dependencies.py).
        # The vector is the default for an advisory without a CVSS 3 vector of its own.
        Rule("vulnerable-dependency", "Bundled dependency with a known vulnerability", ("CWE-1395",),
             "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L",
             "Update the package to a version outside the advisory's affected ranges, rebuild, and analyze again."),
    )
}  # fmt: skip
# What static rules don't claim: these need a running target, where Assess proves them.
DYNAMIC_ONLY = (
    "Object-level authorization (who may read or change whose data)",
    "Cross-site request forgery, which depends on cookies and request handling together",
    "Mass assignment, which depends on what the data store accepts",
    "Business logic and multi-step flows",
)


@dataclass
class _Finder:
    file: FileModel
    found: list[dict[str, Any]]

    def add(self, rule_id: str, function: str | None, line: int, text: str, path: str | None = None) -> None:
        """One candidate.

        `function` is the function it's in, or for recorded traffic the endpoint or origin. `path` names a file
        inside this one (a page in an archive). Line 0 means the whole file.
        """
        rule = RULES[rule_id]
        path = path or self.file.path
        at = f"{path}:{line}" if line else path
        where = f"`{function}` ({at})" if function else at
        claims = [
            {"kind": "observed", "text": f"In {where}, {text}", "evidence": [self.file.evidence]},
            {
                "kind": "limitation",
                "text": "Found by static analysis; not yet confirmed on a running target."
                + (f" Assess can confirm it live with {rule.confirms_with}." if rule.confirms_with else ""),
                "evidence": [],
            },
            {"kind": "guidance", "text": rule.remediation, "evidence": []},
        ]
        score = base_score(rule.cvss)
        self.found.append(
            {
                "id": "",
                "rule": rule_id,
                "title": rule.title,
                "status": "candidate",
                "cwe": list(rule.cwe),
                "if_confirmed": {"severity": severity(score), "cvss": {"vector": rule.cvss, "score": score}},
                "file": path,
                "line": line,
                "function": function,
                "confirms_with": rule.confirms_with,
                "fingerprint": sha256_hex(f"{rule_id}|{path}|{function}|{text}".encode())[:16],
                "claims": [{**c, "id": "", "based_on": [], "producer": PRODUCER} for c in claims],
            }
        )


def _templates(f: _Finder) -> None:
    for t in f.file.items("templates"):
        fn, line = t.get("function"), t["line"]
        if t.get("html") and t.get("tainted"):
            f.add("html-from-input", fn, line, "a string writes request input into HTML without encoding it.")
        if t.get("sql") and t.get("tainted"):
            f.add("sql-from-input", fn, line, "a string builds SQL text from request input.")
        call = (t.get("in_call") or "").split(".")[-1].lower()
        if t.get("stack") and call.startswith(RESPONSE_CALL):
            f.add("stack-in-response", fn, line, f"an error's stack is written into the response (`{t['in_call']}`).")


def _cookies(f: _Finder) -> None:
    for c in f.file.items("cookies"):
        missing = [name for name, present in (("HttpOnly", c.get("httponly")), ("SameSite", c.get("samesite")))
                   if not present]  # fmt: skip
        if missing and not c.get("clearing"):
            f.add("cookie-attributes", c.get("function"), c["line"],
                  f"a cookie is set without {' or '.join(missing)}.")  # fmt: skip


SINKS = {
    "eval": ("dynamic-code", "`eval` runs a string built at run time"),
    "function-constructor": ("dynamic-code", "the Function constructor compiles a string built at run time"),
    "eval-string": ("dynamic-code", "a timer is given code as a string"),
    "vm": ("dynamic-code", "`vm` compiles code built at run time"),
    "exec": ("shell-command", "a shell command is built from a variable"),
    "shell": ("shell-command", "a process is started through a shell with a variable command"),
    "fs-path": ("path-from-input", "a file path comes from request input"),
    "request": ("request-from-input", "an outbound request's URL comes from request input"),
    "deserialize": ("insecure-deserialization", "a binary formatter rebuilds objects of whatever types the data names"),
    "sql-concat": ("sql-concatenation", "SQL text is joined with other strings before a command runs it"),
    "redirect": ("redirect-from-input", "a redirect target comes from request input"),
    "dom-html": ("dom-html", "markup from a variable is written into the page"),
    "open-external": ("open-external", "`shell.openExternal` opens a URL from a variable"),
}
NEEDS_TAINT = ("fs-path", "redirect", "request")


def _sinks(f: _Finder) -> None:
    for s in f.file.items("sinks"):
        rule, text = SINKS.get(s.get("sink", ""), (None, ""))
        if rule is None or not s.get("dynamic"):
            continue
        if s["sink"] in NEEDS_TAINT and not s.get("tainted"):
            continue
        suffix = " (the value comes from request input)" if s.get("tainted") and s["sink"] not in NEEDS_TAINT else ""
        f.add(rule, s.get("function"), s["line"], f"{text}{suffix}.")


def _crypto_and_tls(f: _Finder) -> None:
    for c in f.file.items("crypto"):
        fn = c.get("function")
        if c.get("algorithm") in ("md4", "md5", "sha1"):
            f.add("weak-hash", fn, c["line"], f"`{c['algorithm'].upper()}` is used.")
        elif c.get("algorithm") in ("des", "rc2"):
            f.add("weak-cipher", fn, c["line"], f"`{c['algorithm'].upper()}` is used.")
        elif c.get("algorithm") == "Math.random" and fn and any(n in fn.lower() for n in SECURITY_NAMES):
            f.add("weak-random", fn, c["line"], "`Math.random` produces a value used for security.")
    for t in f.file.items("tls"):
        how = "`rejectUnauthorized: false`" if t.get("kind") == "rejectUnauthorized" else "NODE_TLS_REJECT_UNAUTHORIZED"
        f.add("tls-unverified", t.get("function"), t["line"], f"certificate verification is turned off with {how}.")


def _secrets(f: _Finder) -> None:
    for s in f.file.items("strings"):
        for kind, pattern in PATTERNS:
            if pattern.search(s["value"]):
                prefix = sha256_hex(s["value"].encode())[:8]
                text = f"a string literal matches the {kind} format (value withheld; sha256 prefix {prefix})."
                f.add("hardcoded-secret", s.get("function"), s["line"], text)
                break


ELECTRON = (
    ("nodeIntegration", True, "electron-node-integration"),
    ("contextIsolation", False, "electron-context-isolation"),
    ("sandbox", False, "electron-sandbox"),
    ("webSecurity", False, "electron-web-security"),
    ("allowRunningInsecureContent", True, "electron-web-security"),
)


def _electron(f: _Finder) -> None:
    for w in f.file.items("webpreferences"):
        prefs = w.get("prefs") or {}
        for key, risky, rule in ELECTRON:
            if prefs.get(key) is risky:
                line = w.get("line") or 0
                f.add(rule, w.get("function"), line, f"a window is created with `{key}: {str(risky).lower()}`.")


def _pages(f: _Finder) -> None:
    """Pages inside an Electron archive: a CSP (unless the app's code sets one some other way), and <webview> tags."""
    for page in f.file.items("pages"):
        where = f"{f.file.path}!/{page['path']}"
        if not page.get("csp") and not f.file.facts.get("csp_in_code"):
            text = "the page has no Content-Security-Policy, and the app's code doesn't set one."
            f.add("electron-page-csp", None, 0, text, path=where)
        if page.get("webview_node"):
            text = "a `<webview>` tag turns on Node.js integration for its guest page."
            f.add("electron-node-integration", None, 0, text, path=where)
        if page.get("webview_websecurity"):
            f.add("electron-web-security", None, 0, "a `<webview>` tag turns off web security.", path=where)


CREDENTIAL_PARAM = re.compile(
    r"^(password|passwd|pwd|pass|secret|token|access_token|refresh_token|id_token|api[_-]?key|session(_?id)?|sid|jwt)$",
    re.I,
)


# (count, out of, rule, what was missing): header checks judged across an origin's recorded responses
PER_ORIGIN = (
    ("html_without_csp", "html", "csp-missing", "page(s) had no Content-Security-Policy"),
    ("html_without_framing", "html", "framing-unprotected", "page(s) had no frame-ancestors or X-Frame-Options"),
    ("without_nosniff", None, "nosniff-missing", "successful response(s) lacked X-Content-Type-Options: nosniff"),
    ("https_without_hsts", "https", "hsts-missing", "https response(s) had no Strict-Transport-Security"),
)


def _session(name: str) -> bool:
    return bool(SESSION_COOKIE.search(name)) and not NOT_SESSION.search(name)


def _traffic(f: _Finder) -> None:
    """Recorded traffic, judged from the app's own responses. Other origins (CDNs, trackers) aren't judged."""
    by_origin: dict[str, list[dict[str, Any]]] = {}
    for e in f.file.items("endpoints"):
        if not e.get("first_party"):
            continue
        by_origin.setdefault(e["origin"], []).append(e)
        label, sec = f"{e['method']} {e['template']}", e.get("security") or {}
        for c in e.get("cookies") or []:
            if c.get("clearing") or not _session(c["name"]):
                continue
            missing = [n for n, ok in (("HttpOnly", c.get("httponly")),
                                       ("SameSite", c.get("samesite") in ("lax", "strict"))) if not ok]  # fmt: skip
            if missing:
                text = f"a response sets the `{c['name']}` cookie without {' or '.join(missing)}."
                f.add("cookie-attributes", label, 0, text)
            if e["origin"].startswith("https:") and not c.get("secure"):
                f.add("cookie-secure", label, 0, f"an https response sets the `{c['name']}` cookie without Secure.")
        if sec.get("stack_traces"):
            f.add("stack-in-response", label, 0, f"{sec['stack_traces']} recorded response(s) contain a stack trace.")
        for q in e.get("query") or []:
            if CREDENTIAL_PARAM.match(q):
                f.add("credential-in-url", label, 0, f"the query parameter `{q}` puts a credential in the URL.")
        if any(c.get("allow_origin") == "null" and c.get("credentials") for c in sec.get("cors") or []):
            f.add("cors-null-origin", label, 0, "responses let the `null` origin read them with credentials.")
    for origin, group in sorted(by_origin.items()):

        def count(key: str, group: list[dict[str, Any]] = group) -> int:
            return sum((e.get("security") or {}).get(key, 0) for e in group)

        def example(key: str, group: list[dict[str, Any]] = group) -> str:
            return next(f"{e['method']} {e['template']}" for e in group if (e.get("security") or {}).get(key))

        for key, total, rule, what in PER_ORIGIN:
            if n := count(key):
                of = f" of {count(total)}" if total else ""
                f.add(rule, origin, 0, f"{n}{of} recorded {what}, for example `{example(key)}`.")
        security = [e.get("security") or {} for e in group]
        banners = {v for s in security for v in s.get("server", []) if version_disclosed(v)}
        banners |= {f"X-Powered-By: {v}" for s in security for v in s.get("powered_by", [])}
        if banners:
            f.add("version-disclosure", origin, 0, f"responses name the server software: {'; '.join(sorted(banners))}.")


SAFE_RPATH = ("/", "$ORIGIN", "${ORIGIN}", "@loader_path", "@executable_path", "@rpath")


def _binary(f: _Finder) -> None:
    """A compiled file's header facts and imports. Hardening counts only for code that runs: executables and
    libraries, not object files."""
    facts = f.file.facts
    if facts.get("format") not in ("pe", "elf", "macho") or facts.get("kind") not in ("executable", "library"):
        return
    h = facts.get("hardening") or {}
    if h.get("aslr") is False:
        f.add("binary-no-aslr", None, 0, "the PE header doesn't opt into ASLR (no DYNAMIC_BASE, or no relocations).")
    if h.get("pie") is False:
        f.add("binary-no-aslr", None, 0, "the executable isn't position-independent, so it loads at a fixed address.")
    if h.get("dep") is False:
        f.add("binary-no-dep", None, 0, "the PE header doesn't opt into DEP (no NX_COMPAT).")
    if h.get("nx") is False:
        f.add("binary-no-dep", None, 0, "the stack is marked executable.")
    if h.get("safeseh") is False:
        f.add("binary-no-safeseh", None, 0, "the 32-bit image has no SafeSEH handler table and doesn't declare NO_SEH.")
    if h.get("wx_sections"):
        f.add("binary-wx-memory", None, 0, f"{', '.join(h['wx_sections'][:4])} is mapped writable and executable.")
    for entry in (e for p in [*(h.get("rpath") or []), *(h.get("runpath") or [])] for e in p.split(":")):
        if not entry.startswith(SAFE_RPATH):
            f.add(
                "insecure-rpath",
                None,
                0,
                f"the library search path includes `{entry or '(empty)'}`, which isn't absolute.",
            )
    for b in facts.get("banned") or []:
        rule, why = (
            ("dangerous-function", "which can't bound its input")
            if b.get("kind") == "dangerous"
            else ("banned-api", "an unbounded string function")
        )
        f.add(rule, None, 0, f"it imports `{b['name']}`, {why}.")


def code_findings(files: list[FileModel], extra: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    """Candidates in a fixed order (file, line, rule, then as found), with S- and C- IDs assigned.

    `extra` holds candidates made elsewhere in the same shape (vulnerable dependencies), numbered with these. An
    inferred claim rests on the observed claims before it in its finding.
    """
    found: list[dict[str, Any]] = []
    for file in files:
        finder = _Finder(file, found)
        for scan in (_templates, _cookies, _sinks, _crypto_and_tls, _secrets, _electron, _pages, _traffic, _binary):
            scan(finder)
    found += extra or []
    found.sort(key=lambda x: (x["file"], x["line"], x["rule"]))
    claim = 0
    for n, finding in enumerate(found, 1):
        finding["id"] = f"S-{n:04d}"
        observed: list[str] = []
        for c in finding["claims"]:
            claim += 1
            c["id"] = f"C-{claim:04d}"
            if c["kind"] == "observed":
                observed.append(c["id"])
            elif c["kind"] == "inferred":
                c["based_on"] = list(observed)
    return found


def summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    by_rule: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for f in findings:
        by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
        level = f["if_confirmed"]["severity"]
        by_severity[level] = by_severity.get(level, 0) + 1
    return {"candidates": len(findings), "by_rule": dict(sorted(by_rule.items())),
            "by_severity_if_confirmed": dict(sorted(by_severity.items())), "rules": len(RULES),
            "not_covered": list(DYNAMIC_ONLY)}  # fmt: skip
