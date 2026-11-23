"""The spec gate (docs/architecture.md §8.3, boundary B5): automated filters, then a person approves one version.

Every filter must pass before a claim can cross into a clean-room context:

- identifiers: the subject's distinctive internal names (camelCase, snake_case,
  CONSTANT_CASE, or containing digits), unless they're on the interface allowlist:
  exported names and their members, error codes, platform APIs, and what a recording
  shows on the wire (routes, parameter and field names, media types);
- assets: the subject's own string literals (messages, UI text) beyond error codes;
- secrets: any secret-scanner hit;
- excluded: text touching license, DRM, or anti-tamper logic, which becomes a limitation;
- similarity: claim text whose token fingerprints match the subject's source.

What crosses is the clean view: claim text and structured facts, never evidence IDs or
anything else from the dirty side, plus the operator-owned conformance vectors. A person
approves the clean view's digest (`veritas spec approve`); nothing else can.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from ..core.canonical import digest
from ..models.redact import redact
from .program import FileModel
from .similarity import fingerprints, overlap, tokens

EXCLUDE = re.compile(r"licen[cs]e|serial.?(key|number)|activation|trial.?period|\bdrm\b|tamper|keygen|crack", re.I)
WORD = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*")
PLATFORM = frozenset(
    {
        *("Error", "TypeError", "RangeError", "SyntaxError", "DataView", "ArrayBuffer", "TextDecoder", "TextEncoder"),
        *("Uint8Array", "Uint16Array", "Uint32Array", "JSON", "Object", "Array", "String", "Number", "Boolean"),
        *("Promise", "Buffer", "Map", "Set", "fetch", "XMLHttpRequest", "WebSocket", "EventSource", "navigator"),
        *("localStorage", "sessionStorage", "indexedDB", "document", "http", "https", "net", "fs", "axios"),
        *("ipcMain", "ipcRenderer", "contextBridge", "webContents", "webPreferences", "nodeIntegration"),
        "contextIsolation",
    }
)
SIMILARITY_LIMIT = 0.5  # share of a claim's fingerprints found in the subject's source
MIN_ASSET = 6  # shorter strings are too generic to be an asset
BARE_WORD = re.compile(r"^[a-z]+$")
# The words endpoint claims are written in: JSON types and kinds of credential.
WIRE_WORDS = frozenset(
    {"string", "number", "boolean", "object", "array", "null", "cookie", "bearer", "basic", "header"}
)


def wire_names(endpoint: dict[str, Any]) -> set[str]:
    """What a recording shows on the wire for one endpoint. It's interface by definition, like an exported name:
    routes, their literal segments, parameter and field names, media types, and credential names."""
    out = {endpoint["method"], endpoint["template"], *endpoint.get("query", [])}
    out |= {seg for seg in endpoint["template"].split("/") if seg and not seg.startswith("{")}
    for side in ("request", "response"):
        part = endpoint.get(side) or {}
        out |= set(part.get("types") or []) | set((part.get("fields") or {}).keys())
    for label in endpoint.get("auth") or []:
        out |= {label, label.partition(":")[2]} - {""}
    return out


def distinctive(name: str) -> bool:
    """Names that identify code rather than being ordinary words."""
    if len(name) < 4:
        return False
    return bool(re.search(r"[a-z][A-Z]|_|\d", name)) or (name.isupper() and name.isalpha())


@dataclass
class GateResult:
    passed: list[dict[str, Any]] = field(default_factory=list)
    blocked: list[dict[str, Any]] = field(default_factory=list)  # {claim, filter, reason}

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for b in self.blocked:
            counts[b["filter"]] = counts.get(b["filter"], 0) + 1
        return {"passed": len(self.passed), "blocked": len(self.blocked), "by_filter": counts}


class Gate:
    def __init__(self, files: list[FileModel], sources: list[str]):
        allow = set(PLATFORM)
        wire: set[str] = set()
        for f in files:
            for e in f.exports:
                allow.add(e["name"])
                allow.update((e.get("members") or {}).keys())
            allow.update(t["code"] for t in f.items("throws") if t.get("code"))
            # A compiled file's links to the platform are public: imported functions, libraries, framework members.
            allow.update(i["name"] for i in f.items("imports") if i.get("name"))
            allow.update(f.facts.get("libraries") or [])
            managed = f.facts.get("dotnet") or {}
            allow.update(n for ref in managed.get("member_refs") or [] for n in re.split(r"[.:/]+", ref) if n)
            allow.update(r["name"] for r in managed.get("references") or [])
            if managed.get("assembly"):
                allow.add(managed["assembly"]["name"])
            for endpoint in f.items("endpoints"):
                if endpoint.get("first_party"):
                    wire |= wire_names(endpoint)
        allow |= wire | (WIRE_WORDS if wire else set())
        self.allow = allow
        self.internal = {i for f in files for i in f.identifiers if distinctive(i)} - allow
        # A string that's part of something seen on the wire is already public, wherever else the code uses it. A
        # bare lowercase word ("request", "status") is ordinary language, too common to identify the subject.
        self.assets = {s for f in files for s in f.strings
                       if len(s) >= MIN_ASSET and s not in allow and not BARE_WORD.match(s)
                       and not any(s in w for w in wire)}  # fmt: skip
        self.reference = set().union(*(fingerprints(tokens(src)) for src in sources)) if sources else set()

    def _problems(self, claim: dict[str, Any]) -> list[tuple[str, str]]:
        text = claim["text"]
        fact_text = json.dumps(claim.get("fact") or {}, sort_keys=True)
        found = []
        leaked = sorted({w for w in WORD.findall(f"{text} {fact_text}") if w in self.internal})
        if leaked:
            found.append(("identifiers", f"internal names: {', '.join(leaked[:5])}"))
        assets = sorted(a for a in self.assets if a in text)
        if assets:
            found.append(("assets", f"subject strings: {', '.join(repr(a[:40]) for a in assets[:3])}"))
        _, secrets = redact(f"{text}\n{fact_text}")
        if secrets:
            found.append(("secrets", f"secret-scanner hits: {', '.join(sorted(secrets))}"))
        kind = (claim.get("fact") or {}).get("kind")
        if EXCLUDE.search(text) and kind not in ("export", "excluded"):
            found.append(("excluded", "touches license, DRM, or anti-tamper logic"))
        share = overlap(text, self.reference)
        if share >= SIMILARITY_LIMIT and len(tokens(text)) >= 8:
            found.append(("similarity", f"{share:.0%} of its fingerprints occur in the subject's source"))
        return found

    def run(self, claims: list[dict[str, Any]]) -> GateResult:
        result = GateResult()
        for claim in claims:
            problems = self._problems(claim)
            if not problems:
                result.passed.append(claim)
                continue
            for flt, reason in problems:
                result.blocked.append({"claim": claim["id"], "filter": flt, "reason": reason})
            if any(flt == "excluded" for flt, _ in problems):
                result.passed.append({**claim, "kind": "limitation", "fact": {"kind": "withheld"},
                                      "text": "A claim touching logic excluded by policy was withheld.",
                                      "evidence": []})  # fmt: skip
        return result


def clean_view(
    spec: dict[str, Any], passed: list[dict[str, Any]], vectors: list[dict[str, Any]], call: str | None = None
) -> dict[str, Any]:
    """What may cross B5: claim text and facts by interface, plus the operator's vectors. No evidence IDs."""
    keep = {c["id"]: c for c in passed}
    interfaces = []
    for interface in spec["interfaces"]:
        claims = [
            {k: keep[cid][k] for k in ("id", "kind", "text", "fact")} for cid in interface["claims"] if cid in keep
        ]
        if claims:
            interfaces.append({"id": interface["id"], "title": interface["title"], "claims": claims})
    return {
        "schema": "veritas/spec/v1alpha1",
        "interfaces": interfaces,
        "conformance": {"call": call, "vectors": vectors},
    }


def spec_digest(clean: dict[str, Any]) -> str:
    return digest(clean)
