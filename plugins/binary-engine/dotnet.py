""".NET assemblies: CLI metadata and a light IL scan. Stdlib only; nothing is loaded or run.

Metadata gives the assembly, the assemblies it references, its types and methods, the members
it calls, its P/Invoke imports, and its string literals. The IL scan reads each method body
only far enough to know which strings it loads and which members it calls, in order. That's
enough for a few precise patterns:

- SQL text joined with other strings before a command runs it;
- a binary formatter deserializing;
- a shell started with a joined command line;
- weak hash and cipher classes.

Internal type and method names are identifiers, which never cross the spec gate. Public ones
are the assembly's interface.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

from binfmt import EXCLUDE, MAX_IDENTIFIERS, MAX_STRING, MAX_STRINGS, FormatError, Reader

MAX_ROWS = 1 << 24
MAX_BODY = 1 << 20
MAX_METHODS = 200_000
MAX_REFS = 4096
MAX_EXPORTS = 4096

# ECMA-335 II.22: the columns of every table an assembly can hold, so later tables can be found.
U2, U4, STR, GUID, BLOB = "u2", "u4", "str", "guid", "blob"
SCHEMA: dict[int, list[tuple[str, Any]]] = {
    0x00: [("Generation", U2), ("Name", STR), ("Mvid", GUID), ("EncId", GUID), ("EncBaseId", GUID)],
    0x01: [("ResolutionScope", ("c", "ResolutionScope")), ("TypeName", STR), ("TypeNamespace", STR)],
    0x02: [("Flags", U4), ("TypeName", STR), ("TypeNamespace", STR), ("Extends", ("c", "TypeDefOrRef")),
           ("FieldList", ("t", 0x04)), ("MethodList", ("t", 0x06))],
    0x03: [("Field", ("t", 0x04))],
    0x04: [("Flags", U2), ("Name", STR), ("Signature", BLOB)],
    0x05: [("Method", ("t", 0x06))],
    0x06: [("RVA", U4), ("ImplFlags", U2), ("Flags", U2), ("Name", STR), ("Signature", BLOB),
           ("ParamList", ("t", 0x08))],
    0x07: [("Param", ("t", 0x08))],
    0x08: [("Flags", U2), ("Sequence", U2), ("Name", STR)],
    0x09: [("Class", ("t", 0x02)), ("Interface", ("c", "TypeDefOrRef"))],
    0x0A: [("Class", ("c", "MemberRefParent")), ("Name", STR), ("Signature", BLOB)],
    0x0B: [("Type", U2), ("Parent", ("c", "HasConstant")), ("Value", BLOB)],
    0x0C: [("Parent", ("c", "HasCustomAttribute")), ("Type", ("c", "CustomAttributeType")), ("Value", BLOB)],
    0x0D: [("Parent", ("c", "HasFieldMarshal")), ("NativeType", BLOB)],
    0x0E: [("Action", U2), ("Parent", ("c", "HasDeclSecurity")), ("PermissionSet", BLOB)],
    0x0F: [("PackingSize", U2), ("ClassSize", U4), ("Parent", ("t", 0x02))],
    0x10: [("Offset", U4), ("Field", ("t", 0x04))],
    0x11: [("Signature", BLOB)],
    0x12: [("Parent", ("t", 0x02)), ("EventList", ("t", 0x14))],
    0x13: [("Event", ("t", 0x14))],
    0x14: [("EventFlags", U2), ("Name", STR), ("EventType", ("c", "TypeDefOrRef"))],
    0x15: [("Parent", ("t", 0x02)), ("PropertyList", ("t", 0x17))],
    0x16: [("Property", ("t", 0x17))],
    0x17: [("Flags", U2), ("Name", STR), ("Type", BLOB)],
    0x18: [("Semantics", U2), ("Method", ("t", 0x06)), ("Association", ("c", "HasSemantics"))],
    0x19: [("Class", ("t", 0x02)), ("MethodBody", ("c", "MethodDefOrRef")),
           ("MethodDeclaration", ("c", "MethodDefOrRef"))],
    0x1A: [("Name", STR)],
    0x1B: [("Signature", BLOB)],
    0x1C: [("MappingFlags", U2), ("MemberForwarded", ("c", "MemberForwarded")), ("ImportName", STR),
           ("ImportScope", ("t", 0x1A))],
    0x1D: [("RVA", U4), ("Field", ("t", 0x04))],
    0x1E: [("Token", U4), ("FuncCode", U4)],
    0x1F: [("Token", U4)],
    0x20: [("HashAlgId", U4), ("MajorVersion", U2), ("MinorVersion", U2), ("BuildNumber", U2),
           ("RevisionNumber", U2), ("Flags", U4), ("PublicKey", BLOB), ("Name", STR), ("Culture", STR)],
    0x21: [("Processor", U4)],
    0x22: [("OSPlatformID", U4), ("OSMajorVersion", U4), ("OSMinorVersion", U4)],
    0x23: [("MajorVersion", U2), ("MinorVersion", U2), ("BuildNumber", U2), ("RevisionNumber", U2), ("Flags", U4),
           ("PublicKeyOrToken", BLOB), ("Name", STR), ("Culture", STR), ("HashValue", BLOB)],
    0x24: [("Processor", U4), ("AssemblyRef", ("t", 0x23))],
    0x25: [("OSPlatformId", U4), ("OSMajorVersion", U4), ("OSMinorVersion", U4), ("AssemblyRef", ("t", 0x23))],
    0x26: [("Flags", U4), ("Name", STR), ("HashValue", BLOB)],
    0x27: [("Flags", U4), ("TypeDefId", U4), ("TypeName", STR), ("TypeNamespace", STR),
           ("Implementation", ("c", "Implementation"))],
    0x28: [("Offset", U4), ("Flags", U4), ("Name", STR), ("Implementation", ("c", "Implementation"))],
    0x29: [("NestedClass", ("t", 0x02)), ("EnclosingClass", ("t", 0x02))],
    0x2A: [("Number", U2), ("Flags", U2), ("Owner", ("c", "TypeOrMethodDef")), ("Name", STR)],
    0x2B: [("Method", ("c", "MethodDefOrRef")), ("Instantiation", BLOB)],
    0x2C: [("Owner", ("t", 0x2A)), ("Constraint", ("c", "TypeDefOrRef"))],
}  # fmt: skip
# coded index -> (tag bits, tables by tag; None marks an unused tag)
CODED: dict[str, tuple[int, list[int | None]]] = {
    "TypeDefOrRef": (2, [0x02, 0x01, 0x1B]),
    "HasConstant": (2, [0x04, 0x08, 0x17]),
    "HasCustomAttribute": (5, [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B,
                               0x20, 0x23, 0x26, 0x27, 0x28, 0x2A, 0x2C, 0x2B]),
    "HasFieldMarshal": (1, [0x04, 0x08]),
    "HasDeclSecurity": (2, [0x02, 0x06, 0x20]),
    "MemberRefParent": (3, [0x02, 0x01, 0x1A, 0x06, 0x1B]),
    "HasSemantics": (1, [0x14, 0x17]),
    "MethodDefOrRef": (1, [0x06, 0x0A]),
    "MemberForwarded": (1, [0x04, 0x06]),
    "Implementation": (2, [0x26, 0x23, 0x27]),
    "CustomAttributeType": (3, [None, None, 0x06, 0x0A, None]),
    "ResolutionScope": (2, [0x00, 0x1A, 0x23, 0x01]),
    "TypeOrMethodDef": (1, [0x02, 0x06]),
}  # fmt: skip
KEEP = {0x01, 0x02, 0x06, 0x0A, 0x1A, 0x1B, 0x1C, 0x20, 0x23, 0x28, 0x29, 0x2B}  # the tables the facts need


def _one_byte_operands() -> list[int]:
    """Operand sizes of one-byte CIL opcodes (ECMA-335 III); -1 is undefined, -2 is `switch`."""
    t = [-1] * 256
    for op in [
        *range(0x00, 0x0E),
        0x14,
        *range(0x15, 0x1F),
        0x25,
        0x26,
        0x2A,
        *range(0x46, 0x6F),
        0x76,
        0x7A,
        *range(0x82, 0x8C),
        0x8E,
        *range(0x90, 0xA3),
        *range(0xB3, 0xBB),
        0xC3,
        *range(0xD1, 0xDD),
        0xDF,
        0xE0,
    ]:
        t[op] = 0
    for op in [*range(0x0E, 0x14), 0x1F, *range(0x2B, 0x38), 0xDE]:
        t[op] = 1
    for op in [
        0x20,
        0x22,
        0x27,
        0x28,
        0x29,
        *range(0x38, 0x45),
        *range(0x6F, 0x76),
        0x79,
        *range(0x7B, 0x82),
        0x8C,
        0x8D,
        0x8F,
        0xA3,
        0xA4,
        0xA5,
        0xC2,
        0xC6,
        0xD0,
        0xDD,
    ]:
        t[op] = 4
    t[0x21] = t[0x23] = 8
    t[0x45] = -2
    return t  # fmt: skip


ONE_BYTE = _one_byte_operands()
TWO_BYTE = {0x00: 0, 0x01: 0, 0x02: 0, 0x03: 0, 0x04: 0, 0x05: 0, 0x06: 4, 0x07: 4, 0x09: 2, 0x0A: 2, 0x0B: 2,
            0x0C: 2, 0x0D: 2, 0x0E: 2, 0x0F: 0, 0x11: 0, 0x12: 1, 0x13: 0, 0x14: 0, 0x15: 4, 0x16: 4, 0x17: 0,
            0x18: 0, 0x19: 1, 0x1A: 0, 0x1C: 4, 0x1D: 0, 0x1E: 0}  # fmt: skip
CALLS = {0x28, 0x6F, 0x73}  # call, callvirt, newobj

SQL_TEXT = re.compile(r"\b(select|insert|update|delete)\b[\s\S]*\b(from|into|set|where|values)\b", re.I)
JOINS = re.compile(r"^System\.String::(Concat|Format|Join)$|^System\.Text\.StringBuilder::Append(Format)?$")
COMMANDS = re.compile(
    r"(SqlCommand|OleDbCommand|OdbcCommand|SQLiteCommand|SqliteCommand|NpgsqlCommand|MySqlCommand|"
    r"OracleCommand|DbCommand|IDbCommand)::(\.ctor|set_CommandText)$|SqlDataAdapter::\.ctor$"
)
DESERIALIZE = re.compile(
    r"(BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|"
    r"ObjectStateFormatter)::(Deserialize|UnsafeDeserialize|ReadObject)$"
)
PROCESS = re.compile(r"^System\.Diagnostics\.(Process::Start|ProcessStartInfo::(\.ctor|set_FileName|set_Arguments))$")
SHELL = re.compile(r"^\s*((cmd|powershell|pwsh)(\.exe)?|/bin/(ba)?sh|bash|sh)\s*$|^\s*(/c|-c|-command)(\s|$)", re.I)
WEAK = {"MD5": "md5", "MD5CryptoServiceProvider": "md5", "SHA1": "sha1", "SHA1CryptoServiceProvider": "sha1",
        "SHA1Managed": "sha1", "SHA1Cng": "sha1", "DES": "des", "DESCryptoServiceProvider": "des", "RC2": "rc2",
        "RC2CryptoServiceProvider": "rc2"}  # fmt: skip


def _compressed(r: Reader, at: int) -> tuple[int, int]:
    """An ECMA-335 compressed unsigned integer and the offset after it."""
    b = r.u8(at)
    if b & 0x80 == 0:
        return b, at + 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | r.u8(at + 1), at + 2
    if b & 0xE0 == 0xC0:
        return ((b & 0x1F) << 24) | (r.u8(at + 1) << 16) | (r.u8(at + 2) << 8) | r.u8(at + 3), at + 4
    raise FormatError("a malformed compressed integer in the metadata")


class Metadata:
    def __init__(self, r: Reader, root: int):
        if r.u32(root) != 0x424A5342:
            raise FormatError("the CLI metadata root has no BSJB signature")
        self.r = r
        length = r.u32(root + 12)
        self.version = r.raw(root + 16, min(length, 255)).split(b"\0")[0].decode("ascii", "replace")
        at = root + 16 + ((length + 3) & ~3)
        count = r.u16(at + 2)
        at += 4
        self.streams: dict[str, tuple[int, int]] = {}
        for _ in range(min(count, 16)):
            offset, size = r.u32(at), r.u32(at + 4)
            name = r.cstr(at + 8, 32)
            self.streams[name] = (root + offset, size)
            at += 8 + ((len(name) + 4) & ~3)
        tables = self.streams.get("#~") or self.streams.get("#-")
        if tables is None:
            raise FormatError("the metadata has no table stream")
        self.rows, self.tables = self._tables(*tables)

    def _tables(self, start: int, size: int) -> tuple[dict[int, int], dict[int, list[dict[str, int]]]]:
        r = self.r
        heaps, valid = r.u8(start + 6), r.u64(start + 8)
        at = start + 24
        rows: dict[int, int] = {}
        for t in range(64):
            if valid >> t & 1:
                rows[t] = r.u32(at)
                at += 4
        if heaps & 0x40:
            at += 4
        unknown = sorted(t for t in rows if t not in SCHEMA)
        if unknown:
            raise FormatError(f"metadata table {unknown[0]:#x} isn't one this reader knows")
        widths = {U2: 2, U4: 4, STR: 4 if heaps & 1 else 2, GUID: 4 if heaps & 2 else 2, BLOB: 4 if heaps & 4 else 2}

        def width(column: Any) -> int:
            if isinstance(column, str):
                return widths[column]
            if column[0] == "t":
                return 2 if rows.get(column[1], 0) < 0x10000 else 4
            bits, targets = CODED[column[1]]
            largest = max((rows.get(t, 0) for t in targets if t is not None), default=0)
            return 2 if largest < 1 << (16 - bits) else 4

        out: dict[int, list[dict[str, int]]] = {}
        end = start + size
        for t in sorted(rows):
            columns = SCHEMA[t]
            sizes = [width(c) for _, c in columns]
            row_size, n = sum(sizes), rows[t]
            if n > MAX_ROWS or at + n * row_size > end:
                raise FormatError("the metadata tables run past their stream")
            if t in KEEP:
                parsed = []
                for i in range(n):
                    row, p = {}, at + i * row_size
                    for (name, _), w in zip(columns, sizes, strict=True):
                        row[name] = r.u16(p) if w == 2 else r.u32(p)
                        p += w
                    parsed.append(row)
                out[t] = parsed
            at += n * row_size
        return rows, out

    def string(self, index: int) -> str:
        heap = self.streams.get("#Strings")
        if heap is None or index >= heap[1]:
            return ""
        return self.r.cstr(heap[0] + index, 1024)

    def blob(self, index: int) -> bytes:
        heap = self.streams.get("#Blob")
        if heap is None or index >= heap[1]:
            return b""
        n, at = _compressed(self.r, heap[0] + index)
        return self.r.raw(at, min(n, heap[0] + heap[1] - at))

    def user_string(self, index: int) -> str | None:
        heap = self.streams.get("#US")
        if heap is None or not 0 < index < heap[1]:
            return None
        n, at = _compressed(self.r, heap[0] + index)
        return self.r.raw(at, max(0, min(n, heap[0] + heap[1] - at) - 1)).decode("utf-16-le", "replace")

    def user_strings(self) -> list[tuple[int, str]]:
        heap = self.streams.get("#US")
        out: list[tuple[int, str]] = []
        if heap is None:
            return out
        index = 1
        while index < heap[1] and len(out) < MAX_STRINGS * 4:
            n, at = _compressed(self.r, heap[0] + index)
            if n:
                out.append(
                    (index, self.r.raw(at, max(0, min(n, heap[0] + heap[1] - at) - 1)).decode("utf-16-le", "replace"))
                )
            index = at - heap[0] + n
        return out

    def coded(self, kind: str, value: int) -> tuple[int, int] | None:
        bits, targets = CODED[kind]
        tag, row = value & ((1 << bits) - 1), value >> bits
        if row == 0 or tag >= len(targets) or targets[tag] is None:
            return None
        return int(targets[tag]), row  # type: ignore[arg-type]

    def row(self, table: int, index: int) -> dict[str, int] | None:
        rows = self.tables.get(table) or []
        return rows[index - 1] if 0 < index <= len(rows) else None


def read(r: Reader, offset: Callable[[int], int], cli_rva: int, cli_size: int) -> dict[str, Any]:
    head = offset(cli_rva)
    flags = r.u32(head + 16)
    md = Metadata(r, offset(r.u32(head + 8)))
    nested = {row["NestedClass"]: row["EnclosingClass"] for row in md.tables.get(0x29, [])}

    def type_name(table: int, index: int, depth: int = 0) -> str:
        row = md.row(table, index)
        if row is None or depth > 8:
            return "?"
        name, space = md.string(row["TypeName"]), md.string(row["TypeNamespace"])
        if table == 0x01:
            scope = md.coded("ResolutionScope", row["ResolutionScope"])
            if scope and scope[0] == 0x01:
                return f"{type_name(0x01, scope[1], depth + 1)}/{name}"
        elif index in nested:
            return f"{type_name(0x02, nested[index], depth + 1)}/{name}"
        return f"{space}.{name}" if space else name

    def spec_name(index: int) -> str:
        blob = md.blob((md.row(0x1B, index) or {}).get("Signature", 0))
        if len(blob) > 2 and blob[0] == 0x15 and blob[1] in (0x11, 0x12):  # GENERICINST of a class or value type
            value, _ = _compressed(Reader(blob), 2)
            table = {0: 0x02, 1: 0x01}.get(value & 3)
            if table is not None:
                return type_name(table, value >> 2)
        return "?"

    types = md.tables.get(0x02, [])
    methods = md.tables.get(0x06, [])
    owner: dict[int, int] = {}
    for t, row in enumerate(types, 1):
        last = types[t]["MethodList"] if t < len(types) else len(methods) + 1
        for m in range(row["MethodList"], min(last, len(methods) + 1)):
            owner[m] = t

    def method_name(index: int) -> str:
        row = md.row(0x06, index)
        return f"{type_name(0x02, owner.get(index, 0))}::{md.string(row['Name'])}" if row else "?"

    def member_name(table: int, index: int) -> str:
        if table == 0x06:
            return method_name(index)
        if table == 0x2B:
            spec = md.coded("MethodDefOrRef", (md.row(0x2B, index) or {}).get("Method", 0))
            return member_name(*spec) if spec else "?"
        row = md.row(0x0A, index) if table == 0x0A else None
        if row is None:
            return "?"
        parent = md.coded("MemberRefParent", row["Class"])
        if parent is None:
            where = "?"
        elif parent[0] in (0x01, 0x02):
            where = type_name(*parent)
        elif parent[0] == 0x1B:
            where = spec_name(parent[1])
        elif parent[0] == 0x1A:
            where = md.string((md.row(0x1A, parent[1]) or {}).get("Name", 0))
        else:
            where = method_name(parent[1])
        return f"{where}::{md.string(row['Name'])}"

    def public_type(index: int, depth: int = 0) -> bool:
        row = md.row(0x02, index)
        if row is None or depth > 8:
            return False
        visibility = row["Flags"] & 7
        return visibility == 1 or (visibility == 2 and public_type(nested.get(index, 0), depth + 1))

    def params(signature: int) -> int:
        blob = md.blob(signature)
        if not blob:
            return 0
        at = 1 + (1 if blob[0] & 0x10 and len(blob) > 1 else 0)  # a generic method's parameter count comes first
        return _compressed(Reader(blob), at)[0] if at < len(blob) else 0

    exports: list[dict[str, Any]] = []
    identifiers: set[str] = set()
    for t in range(1, len(types) + 1):
        name = type_name(0x02, t)
        if name in ("<Module>", "?"):
            continue
        if public_type(t):
            exports.append({"name": name, "kind": "class", "extends": None})
        else:
            identifiers.update(p for p in re.split(r"[./]", name) if p)
    for m, row in enumerate(methods, 1):
        name = md.string(row["Name"])
        if row["Flags"] & 7 == 6 and public_type(owner.get(m, 0)) and len(exports) < MAX_EXPORTS:
            if not name.startswith((".ctor", ".cctor", "get_", "set_", "add_", "remove_")):
                exports.append({"name": method_name(m), "kind": "function", "params": params(row["Signature"])})
        elif not name.startswith("."):
            identifiers.add(name)

    # The IL scan: which strings each method loads and which members it calls, in order.
    loaded_by: dict[int, str] = {}
    sinks: list[dict[str, Any]] = []
    crypto: list[dict[str, Any]] = []
    called: set[str] = set()
    undecoded = decoded = 0
    for m, row in enumerate(methods[:MAX_METHODS], 1):
        if not row["RVA"]:
            continue
        events = _scan(r, offset, row["RVA"])
        if events is None:
            undecoded += 1
            continue
        decoded += 1
        here = method_name(m)
        sequence: list[tuple[str, str]] = []
        for kind, value in events:
            if kind == "str":
                text = md.user_string(value) or ""
                loaded_by.setdefault(value, here)
                sequence.append(("str", text))
            else:
                target = member_name(value >> 24, value & 0xFFFFFF)
                called.add(target)
                sequence.append(("call", target))
        sinks += _patterns(here, sequence)
        for _, target in (s for s in sequence if s[0] == "call"):
            algorithm = WEAK.get(target.split("::")[0].rsplit(".", 1)[-1])
            if algorithm and target.startswith("System.Security.Cryptography."):
                crypto.append({"function": here, "line": 0, "algorithm": algorithm})
    crypto = [dict(c) for c in {(c["function"], c["algorithm"]): c for c in crypto}.values()]

    found, withheld = [], 0
    for index, text in md.user_strings():
        value = text[:MAX_STRING]
        if len(value) < 4:
            continue
        if EXCLUDE.search(value):
            withheld += 1
            continue
        if len(found) < MAX_STRINGS:
            found.append({"value": value, "offset": index, "line": 0, "function": loaded_by.get(index)})

    pinvoke = []
    for row in md.tables.get(0x1C, []):
        scope = md.row(0x1A, row["ImportScope"])
        pinvoke.append({"library": md.string(scope["Name"]) if scope else None, "name": md.string(row["ImportName"])})
    assembly = md.row(0x20, 1)

    def version(row: dict[str, int]) -> str:
        return ".".join(str(row[k]) for k in ("MajorVersion", "MinorVersion", "BuildNumber", "RevisionNumber"))

    return {
        "runtime": md.version,
        "assembly": {"name": md.string(assembly["Name"]), "version": version(assembly)} if assembly else None,
        "references": [{"name": md.string(a["Name"]), "version": version(a)} for a in md.tables.get(0x23, [])],
        "types": len(types), "methods": len(methods),
        "member_refs": sorted(c for c in called if not c.startswith("?"))[:MAX_REFS],
        "member_refs_total": sum(1 for c in called if not c.startswith("?")),
        "resources": [md.string(row["Name"]) for row in md.tables.get(0x28, [])][:256],
        "pinvoke": pinvoke[:MAX_REFS],
        "il": {"decoded": decoded, "undecoded": undecoded},
        "flags": {"il_only": bool(flags & 1), "requires_32bit": bool(flags & 2), "strong_name_signed": bool(flags & 8)},
        "exports": exports, "identifiers": sorted(identifiers)[:MAX_IDENTIFIERS], "strings": found,
        "withheld": withheld, "sinks": sinks, "crypto": crypto,
    }  # fmt: skip


def _scan(r: Reader, offset: Callable[[int], int], rva: int) -> list[tuple[str, int]] | None:
    """The ldstr operands and called-member tokens of one method body, or None if it can't be decoded."""
    try:
        at = offset(rva)
        head = r.u8(at)
        if head & 3 == 2:  # a tiny header: the size is in the top six bits
            size, code = head >> 2, at + 1
        elif head & 3 == 3:
            size, code = r.u32(at + 4), at + (r.u16(at) >> 12) * 4
        else:
            return None
        body = r.raw(code, min(size, MAX_BODY))
    except FormatError:
        return None
    events: list[tuple[str, int]] = []
    i = 0
    while i < len(body):
        op = body[i]
        i += 1
        if op == 0xFE:
            if i >= len(body) or body[i] not in TWO_BYTE:
                return None
            second = body[i]
            i += 1
            if second in (0x06, 0x07) and i + 4 <= len(body):  # ldftn, ldvirtftn: a method used as a delegate
                events.append(("call", int.from_bytes(body[i : i + 4], "little")))
            i += TWO_BYTE[second]
            continue
        n = ONE_BYTE[op]
        if n == -1:
            return None
        if n == -2:  # switch: a count, then that many 4-byte targets
            if i + 4 > len(body):
                return None
            i += 4 + 4 * int.from_bytes(body[i : i + 4], "little")
            continue
        if i + n > len(body):
            return None
        if op == 0x72:
            events.append(("str", int.from_bytes(body[i : i + 4], "little") & 0xFFFFFF))
        elif op in CALLS:
            events.append(("call", int.from_bytes(body[i : i + 4], "little")))
        i += n
    return events


def _patterns(method: str, sequence: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """Sinks a method's ordered strings and calls show. Each needs every step, in order, so a look-alike stays quiet."""
    out = []

    def sink(kind: str) -> None:
        out.append({"function": method, "line": 0, "sink": kind, "dynamic": True, "tainted": False})

    calls = [(i, t) for i, (k, t) in enumerate(sequence) if k == "call"]
    if any(DESERIALIZE.search(t) for _, t in calls):
        sink("deserialize")
    sql = next((i for i, (k, t) in enumerate(sequence) if k == "str" and SQL_TEXT.search(t)), None)
    if sql is not None:
        join = next((i for i, t in calls if i > sql and JOINS.search(t)), None)
        if join is not None and any(i > join and COMMANDS.search(t) for i, t in calls):
            sink("sql-concat")
    shell = next((i for i, (k, t) in enumerate(sequence) if k == "str" and SHELL.search(t)), None)
    if shell is not None:
        join = next((i for i, t in calls if i > shell and JOINS.search(t)), None)
        if join is not None and any(i > join and PROCESS.search(t) for i, t in calls):
            sink("shell")
    return out
