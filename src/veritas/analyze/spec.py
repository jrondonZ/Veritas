"""The mechanical behavior spec (docs/architecture.md §8.3): typed claims straight from Program Model facts.

It needs no model. Each observed claim carries a structured `fact` (what the ground truth
is compared against) and cites the engine record it came from. Claim text names only the
public surface (exported names, platform APIs, file-format values, error codes), so
internal identifiers stay dirty-side. The spec gate checks that again before anything
crosses into a clean-room context.

Reads and writes are claimed only where their meaning is certain: reads from a buffer an
exported function receives (its input), and writes to a buffer it returns (its output).
Offsets inside a record a helper builds are stated relative to that record.
"""

from __future__ import annotations

from typing import Any

from .. import __version__
from .program import FileModel

PRODUCER = f"mechanical:veritas.analyze@{__version__}"
INTERFACES = {
    "IF-api": "Public API",
    "IF-binary": "Binary format",
    "IF-platform": "Platform use",
    "IF-http": "HTTP endpoints",
    "IF-format": "File format",
    "IF-errors": "Errors",
    "IF-network": "Network use",
    "IF-storage": "Storage use",
    "IF-ipc": "IPC channels",
    "IF-electron": "Electron windows",
}


def type_name(width: int, kind: str) -> str:
    return f"{kind}{width * 8}"


def endian(entry: dict[str, Any]) -> str | None:
    little = entry.get("little_endian")
    return None if little is None else ("le" if little else "be")


def describe(type_: str, order: str | None) -> str:
    sign = {"u": "an unsigned", "i": "a signed", "f": "a"}[type_[0]]
    noun = "floating-point number" if type_[0] == "f" else "integer"
    word = {"le": " little-endian", "be": " big-endian", None: ""}[order]
    return f"{sign} {type_[1:]}-bit{word} {noun}"


def layout(fields: list[list[Any]]) -> str:
    return ", ".join(f"{t}{' ' + e.upper() if e else ''} at +{d}" for d, t, e in fields)


def hexbyte(value: int) -> str:
    return f"0x{value:02X}"


def byte_text(values: list[int]) -> str:
    return " ".join(f"{v:02X}" for v in values)


class _Builder:
    def __init__(self, file: FileModel):
        self.file = file
        self.claims: list[dict[str, Any]] = []

    def add(self, kind: str, interface: str, fact: dict[str, Any], text: str) -> None:
        self.claims.append(
            {
                "id": "",
                "kind": kind,
                "interface": interface,
                "fact": fact,
                "text": text,
                "evidence": [self.file.evidence] if kind == "observed" else [],
                "based_on": [],
                "producer": PRODUCER,
            }
        )

    def exports(self) -> None:
        for e in self.file.exports:
            name, kind = e["name"], e.get("kind")
            if kind == "function":
                n = e.get("params", 0)
                fact = {"kind": "export", "name": name, "type": "function", "params": n}
                self.add("observed", "IF-api", fact, f"`{name}` is exported as a function taking {n} argument(s).")
            elif kind == "class":
                base = e.get("extends")
                fact = {"kind": "export", "name": name, "type": "class", "extends": base}
                tail = f" extending `{base}`" if base else ""
                self.add("observed", "IF-api", fact, f"`{name}` is exported as a class{tail}.")
            elif kind == "object":
                members = e.get("members") or {}
                listed = ", ".join(f"{k} = {hexbyte(v) if isinstance(v, int) else repr(v)}" for k, v in members.items())
                fact = {"kind": "export", "name": name, "type": "object", "members": members}
                self.add("observed", "IF-api", fact, f"`{name}` is exported as an object of constants: {listed}.")
            else:
                self.add(
                    "observed", "IF-api", {"kind": "export", "name": name, "type": "value"}, f"`{name}` is exported."
                )

    def io(self, fn: str) -> None:
        record = self.file.functions[fn]
        params, returns = set(record.get("param_names") or []), set(record.get("returns") or [])
        groups: dict[tuple[str, str], list[list[Any]]] = {}
        for op, buffers, where in (("read", params, "input"), ("write", returns, "output")):
            for entry in self.file.items(f"{op}s"):
                if entry.get("function") == fn and entry.get("over") in buffers:
                    self._access(fn, op, where, entry, groups)
        for (op, _), fields in sorted(groups.items()):
            fields.sort(key=lambda f: f[0])
            fact = {"kind": f"record-{op}", "function": fn, "via": "self", "fields": fields}
            verb, where = ("reads", "input") if op == "read" else ("writes", "output")
            text = f"`{fn}` {verb} records at a moving position of its {where}, laid out as {layout(fields)}."
            self.add("observed", "IF-format", fact, text)
        for helper in self.file.reachable(fn)[1:]:
            self._helper_record(fn, helper)

    def _access(
        self, fn: str, op: str, where: str, entry: dict[str, Any], groups: dict[tuple[str, str], list[list[Any]]]
    ) -> None:
        """One read from the input or write to the output; moving-position accesses are grouped into records."""
        at = entry.get("at") or {}
        if entry.get("api") == "TypedArray.set":
            values = self.file.constants.get(entry["constant"], {}).get("value")
            if "absolute" in at and isinstance(values, list):
                offset = at["absolute"]
                fact = {
                    "kind": "byte-write",
                    "function": fn,
                    "bytes": byte_text(values).replace(" ", ""),
                    "offset": offset,
                }
                text = f"`{fn}` writes the byte sequence {byte_text(values)} at offset {offset} of its output."
                self.add("observed", "IF-format", fact, text)
            return
        t, e = type_name(entry["width"], entry["kind"]), endian(entry)
        if "absolute" in at:
            verb = "reads" if op == "read" else "writes"
            fact = {"kind": op, "function": fn, "type": t, "endian": e, "offset": at["absolute"]}
            text = f"`{fn}` {verb} {describe(t, e)} at offset {at['absolute']} of its {where}."
            self.add("observed", "IF-format", fact, text)
        elif "from_end" in at and op == "read":
            fact = {"kind": "read", "function": fn, "type": t, "endian": e, "from_end": at["from_end"]}
            text = f"`{fn}` reads {describe(t, e)} {at['from_end']} bytes before the end of its input."
            self.add("observed", "IF-format", fact, text)
        elif "relative" in at:
            field = [at["relative"]["delta"], t, e]
            bucket = groups.setdefault((op, at["relative"]["base"]), [])
            if field not in bucket:
                bucket.append(field)

    def _helper_record(self, fn: str, helper: str) -> None:
        """Writes a helper makes into a buffer it returns: a record, with offsets relative to that record."""
        own = set(self.file.functions[helper].get("returns") or [])
        fields: list[list[Any]] = []
        for entry in self.file.items("writes"):
            at = entry.get("at") or {}
            if entry.get("function") == helper and entry.get("over") in own and "absolute" in at and "width" in entry:
                field = [at["absolute"], type_name(entry["width"], entry["kind"]), endian(entry)]
                if field not in fields:
                    fields.append(field)
        if fields:
            fields.sort(key=lambda f: f[0])
            fact = {"kind": "record-write", "function": fn, "via": "helper", "fields": fields}
            text = f"`{fn}` builds records, through internal code, laid out as {layout(fields)}."
            self.add("observed", "IF-format", fact, text)

    def logic(self, fn: str) -> None:
        reach = set(self.file.reachable(fn))
        self._compares(fn, reach)
        self._dispatch(fn, reach)
        self._errors(fn, reach)

    def _compares(self, fn: str, reach: set[str]) -> None:
        for compare in self.file.items("byte_compares"):
            values = self.file.constants.get(compare["constant"], {}).get("value")
            if compare.get("function") not in reach or not isinstance(values, list):
                continue
            fact: dict[str, Any] = {"kind": "byte-compare", "function": fn, "bytes": byte_text(values).replace(" ", "")}
            if fact not in [c["fact"] for c in self.claims]:
                text = f"`{fn}` compares input bytes with the byte sequence {byte_text(values)}."
                self.add("observed", "IF-format", fact, text)

    def _dispatch(self, fn: str, reach: set[str]) -> None:
        excluded = set(self.file.excluded)
        for switch in self.file.items("switches"):
            if switch.get("function") not in reach:
                continue
            values = sorted(c["value"] for c in switch["cases"] if isinstance(c.get("value"), int))
            if not values:
                continue
            default = next((c for c in switch["cases"] if c.get("value") == "default"), None)
            codes = sorted(set(default.get("throws") or [])) if default else []
            fact: dict[str, Any] = {"kind": "dispatch", "function": fn, "values": values}
            tail = ""
            if len(codes) == 1:
                fact["default_error"] = codes[0]
                tail = f"; other values fail with `{codes[0]}`"
            listed = ", ".join(hexbyte(v) for v in values)
            self.add("observed", "IF-format", fact, f"`{fn}` selects behavior on the values {listed}{tail}.")
            for case in switch["cases"]:
                if isinstance(case.get("value"), int) and excluded.intersection(case.get("calls") or []):
                    value = case["value"]
                    limit: dict[str, Any] = {"kind": "excluded", "value": value, "reached_from": [fn]}
                    text = (
                        f"For the value {hexbyte(value)}, `{fn}` reaches logic excluded by policy (license-like); "
                        "how it is handled was not analyzed."
                    )
                    self.add("limitation", "IF-format", limit, text)

    def _errors(self, fn: str, reach: set[str]) -> None:
        by_ctor: dict[str, set[str]] = {}
        for throw in self.file.items("throws"):
            if throw.get("function") in reach:
                found = by_ctor.setdefault(throw["ctor"], set())
                if throw.get("code"):
                    found.add(throw["code"])
        for ctor, codes in sorted(by_ctor.items()):
            fact: dict[str, Any] = {"kind": "errors", "function": fn, "ctor": ctor, "codes": sorted(codes)}
            listed = ", ".join(f"`{c}`" for c in sorted(codes))
            text = f"`{fn}` can fail with `{ctor}` codes {listed}." if codes else f"`{fn}` can throw `{ctor}`."
            self.add("observed", "IF-errors", fact, text)

    def algorithms(self, exported: list[str]) -> None:
        seen: dict[int, dict[str, Any]] = {}
        for number in self.file.items("numbers"):
            if not number.get("known"):
                continue
            entry = seen.setdefault(number["value"], {"name": number["known"], "in": set()})
            entry["in"].add(number.get("function"))
        for value, entry in sorted(seen.items()):
            users = [fn for fn in exported if entry["in"] & set(self.file.reachable(fn))]
            if not users:
                continue
            constant = f"0x{value:08X}"
            fact = {"kind": "algorithm", "functions": users, "constant": constant, "name": entry["name"]}
            names = " and ".join(f"`{u}`" for u in users)
            self.add(
                "observed", "IF-format", fact, f"Code reachable from {names} uses {constant}, the {entry['name']}."
            )

    def platform(self) -> None:
        for n in self.file.items("network"):
            fact = {"kind": "network", "api": n["api"], "target": n.get("target")}
            where = f"`{n['target']}`" if n.get("target") else "a computed address"
            self.add("observed", "IF-network", fact, f"The code calls `{n['api']}` with {where}.")
        for s in self.file.items("storage"):
            fact = {"kind": "storage", "api": s["api"], "key": s.get("key")}
            key = f" with `{s['key']}`" if s.get("key") else ""
            self.add("observed", "IF-storage", fact, f"The code calls `{s['api']}`{key}.")
        for i in self.file.items("ipc"):
            fact = {"kind": "ipc", "api": i["api"], "channel": i.get("channel")}
            channel = f"channel `{i['channel']}`" if i.get("channel") else "a computed channel"
            self.add("observed", "IF-ipc", fact, f"The code uses {channel} with `{i['api']}`.")
        for w in self.file.items("webpreferences"):
            prefs = ", ".join(f"{k} = {str(v).lower()}" for k, v in sorted(w["prefs"].items()))
            self.add("observed", "IF-electron", {"kind": "webpreferences", "prefs": w["prefs"]},
                     f"A window is created with webPreferences {prefs}.")  # fmt: skip

    def endpoints(self) -> None:
        """What a recording shows the app serving, in the shapes its reader kept: names and types, never values."""
        for e in self.file.items("endpoints"):
            if not e.get("first_party"):
                continue
            keys = ("method", "origin", "template", "statuses", "query", "request", "response", "auth")
            fact = {"kind": "endpoint", **{k: e.get(k) for k in keys}}
            response, request = e.get("response") or {}, e.get("request") or {}
            text = f"`{e['method']} {e['template']}` answered {', '.join(map(str, e.get('statuses') or [])) or '-'}"
            if response.get("types"):
                text += f" with {', '.join(response['types'])}"
            parts = [text]
            if response.get("fields"):
                lead = "each item has fields " if response.get("list") else "fields "
                parts.append(lead + _shape(response["fields"]))
            if e.get("query"):
                parts.append("query parameters " + ", ".join(f"`{q}`" for q in e["query"]))
            if request.get("fields"):
                parts.append(f"request fields {_shape(request['fields'])}")
            if e.get("auth"):
                parts.append("credentials " + ", ".join(e["auth"]))
            self.add("observed", "IF-http", fact, "; ".join(parts) + f" (recorded {e.get('count', 0)} time(s)).")

    def binary(self) -> None:
        """A compiled file: what it is, what it links, what platform services it uses, and for .NET, what it
        references. Names here are public by nature: libraries, imported platform functions, framework members."""
        facts = self.file.facts
        if facts.get("format") not in FORMATS:
            return
        what = {"kind": "binary", "format": facts["format"], "type": facts.get("kind"), "arch": facts.get("arch"),
                "bits": facts.get("bits")}  # fmt: skip
        self.add("observed", "IF-binary", what, f"The file is a {facts.get('bits')}-bit {facts.get('arch')} "
                 f"{FORMATS[facts['format']]} {facts.get('kind')}.")  # fmt: skip
        imports = facts.get("imports") or []
        for library in facts.get("libraries") or []:
            names = sorted({i["name"] for i in imports if i.get("library") == library})
            fact = {"kind": "library", "name": library, "imports": names}
            listed = f", importing {len(names)} function(s): {', '.join(f'`{n}`' for n in names[:8])}" if names else ""
            more = ", and others" if len(names) > 8 else ""
            self.add("observed", "IF-binary", fact, f"It loads `{library}`{listed}{more}.")
        for kind, names in sorted((facts.get("platform") or {}).items()):
            fact = {"kind": "platform", "use": kind, "functions": names}
            self.add("observed", "IF-platform", fact,
                     f"It imports {kind} functions: {', '.join(f'`{n}`' for n in names[:8])}.")  # fmt: skip
        managed = facts.get("dotnet") or {}
        if managed.get("assembly"):
            a = managed["assembly"]
            self.add("observed", "IF-binary", {"kind": "assembly", **a, "runtime": managed.get("runtime")},
                     f"It's the .NET assembly `{a['name']}` version {a['version']}, for runtime "
                     f"{managed.get('runtime')}.")  # fmt: skip
        for ref in managed.get("references") or []:
            self.add("observed", "IF-platform", {"kind": "reference", **ref},
                     f"It references the assembly `{ref['name']}` version {ref['version']}.")  # fmt: skip


FORMATS = {"pe": "PE (Windows)", "elf": "ELF", "macho": "Mach-O"}


def _shape(fields: dict[str, list[str]], limit: int = 20) -> str:
    listed = [f"`{name}` ({'|'.join(kinds)})" for name, kinds in list(fields.items())[:limit]]
    more = f", and {len(fields) - limit} more" if len(fields) > limit else ""
    return ", ".join(listed) + more


def mechanical_claims(file: FileModel) -> list[dict[str, Any]]:
    builder = _Builder(file)
    builder.binary()
    builder.endpoints()
    builder.exports()
    exported = file.exported_functions
    for fn in exported:
        builder.io(fn)
        builder.logic(fn)
    builder.algorithms(exported)
    builder.platform()
    return builder.claims


def build_spec(files: list[FileModel]) -> dict[str, Any]:
    """The draft spec: claims numbered in a fixed order, grouped by interface."""
    claims = [c for f in files for c in mechanical_claims(f)]
    for n, claim in enumerate(claims, 1):
        claim["id"] = f"C-{n:04d}"
    interfaces = [
        {"id": iid, "title": title, "claims": [c["id"] for c in claims if c["interface"] == iid]}
        for iid, title in INTERFACES.items()
        if any(c["interface"] == iid for c in claims)
    ]
    excluded = [{"file": f.path, "function": name, "reason": why} for f in files for name, why in f.excluded.items()]
    return {"interfaces": interfaces, "claims": claims, "excluded": excluded}
