"""Native executables (PE, ELF, Mach-O): headers, sections, imports, exports, strings, and hardening.

Stdlib only. Nothing is executed or disassembled. Every offset is checked against the file
before it's read, and every count is capped, so a hostile file can only fail to parse. The
facts say what was left out.
"""

from __future__ import annotations

import math
import re
import struct
from collections import Counter
from collections.abc import Callable
from typing import Any

MAX_SECTIONS = 256
MAX_SEGMENTS = 512
MAX_COMMANDS = 4096
MAX_LIBRARIES = 256
MAX_IMPORTS = 4096
MAX_EXPORTS = 4096
MAX_SYMBOLS = 200_000
MAX_IDENTIFIERS = 10_000
MAX_STRINGS = 2000
MAX_STRING = 200
MIN_STRING = 6
MAX_SCAN = 32 * 1024 * 1024  # bytes searched for strings
ENTROPY_SAMPLE = 256 * 1024
# License, DRM, and anti-tamper text becomes no fact; only a count of what was withheld (docs/architecture.md §5.4).
EXCLUDE = re.compile(r"licen[cs]e|serial.?(key|number)|activation|trial.?period|\bdrm\b|tamper|keygen|crack", re.I)
ASCII = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_STRING)
UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_STRING)

# Imports worth naming. `gets` can't be used safely; the others are on Microsoft's SDL banned list.
DANGEROUS = {"gets"}
BANNED = {"strcpy", "strcat", "sprintf", "vsprintf", "wcscpy", "wcscat", "lstrcpy", "lstrcpyA", "lstrcpyW",
          "lstrcat", "lstrcatA", "lstrcatW", "StrCpy", "StrCpyA", "StrCpyW", "StrCat", "StrCatA", "StrCatW",
          "_mbscpy", "_mbscat", "_tcscpy", "_tcscat"}  # fmt: skip
PLATFORM = {
    "process": {"system", "popen", "execve", "execl", "execlp", "execv", "execvp", "fork", "posix_spawn",
                "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA", "ShellExecuteW", "ShellExecuteExW"},
    "network": {"socket", "connect", "bind", "listen", "accept", "getaddrinfo", "gethostbyname", "WSAStartup",
                "InternetOpenA", "InternetOpenW", "InternetOpenUrlA", "InternetOpenUrlW", "WinHttpOpen",
                "URLDownloadToFileA", "URLDownloadToFileW", "curl_easy_perform"},
    "dynamic-code": {"dlopen", "dlsym", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExA", "LoadLibraryExW",
                     "GetProcAddress", "VirtualProtect", "VirtualAlloc", "mprotect"},
    "registry": {"RegOpenKeyExA", "RegOpenKeyExW", "RegSetValueExA", "RegSetValueExW", "RegCreateKeyExA",
                 "RegCreateKeyExW"},
}  # fmt: skip
WEAK_HASHES = {"MD4_Init": "md4", "MD4": "md4", "MD5_Init": "md5", "MD5": "md5", "SHA1_Init": "sha1", "SHA1": "sha1"}
CANARY = {"__stack_chk_fail", "__stack_chk_guard", "__intel_security_cookie"}
PE_MACHINES = {0x14C: "x86", 0x8664: "x86-64", 0x1C0: "arm", 0x1C4: "arm", 0xAA64: "arm64", 0x200: "ia64"}
ELF_MACHINES = {3: "x86", 0x3E: "x86-64", 0x28: "arm", 0xB7: "arm64", 0xF3: "riscv", 8: "mips", 0x14: "ppc",
                0x15: "ppc64", 0x2B: "sparc", 0x16: "s390"}  # fmt: skip
MACHO_CPUS = {7: "x86", 0x01000007: "x86-64", 12: "arm", 0x0100000C: "arm64", 0x0200000C: "arm64_32", 18: "ppc"}


class FormatError(Exception):
    """The file isn't a well-formed executable of the format it claims."""


class Reader:
    """Bounds-checked little- or big-endian reads from bytes or a memory map."""

    def __init__(self, data: Any, big: bool = False):
        self.data, self.size, self.big = data, len(data), big

    def _get(self, fmt: str, off: int) -> int:
        n = struct.calcsize(fmt)
        if off < 0 or off + n > self.size:
            raise FormatError(f"a field at offset {off} lies outside the file")
        return int(struct.unpack_from((">" if self.big else "<") + fmt, self.data, off)[0])

    def u8(self, off: int) -> int:
        return self._get("B", off)

    def u16(self, off: int) -> int:
        return self._get("H", off)

    def u32(self, off: int) -> int:
        return self._get("I", off)

    def u64(self, off: int) -> int:
        return self._get("Q", off)

    def raw(self, off: int, n: int) -> bytes:
        if off < 0 or n < 0 or off + n > self.size:
            raise FormatError(f"{n} bytes at offset {off} lie outside the file")
        return bytes(self.data[off : off + n])

    def cstr(self, off: int, limit: int = 1024) -> str:
        if off < 0 or off >= self.size:
            raise FormatError(f"a string at offset {off} lies outside the file")
        end = self.data.find(b"\0", off, min(self.size, off + limit))
        return bytes(self.data[off : end if end >= 0 else min(self.size, off + limit)]).decode("utf-8", "replace")


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    return round(-sum(c / len(data) * math.log2(c / len(data)) for c in counts.values()), 2)


def strings(r: Reader, ranges: list[tuple[int, int]], known: set[str]) -> tuple[list[dict[str, Any]], int, bool]:
    """Printable ASCII and UTF-16LE runs in the given file ranges. Names the format tables already give (imports,
    libraries) are structure, not literals, so they're left out, and so is license-like text."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    withheld, budget, truncated = 0, MAX_SCAN, False
    for start, end in ranges:
        end = min(end, r.size, start + budget)
        if end <= start:
            continue
        budget -= end - start
        found = [(m.start(), m.group().decode("ascii")) for m in ASCII.finditer(r.data, start, end)]
        found += [(m.start(), m.group().decode("utf-16-le")) for m in UTF16.finditer(r.data, start, end)]
        for offset, text in sorted(found):
            value = text[:MAX_STRING]
            if value in seen or value in known:
                continue
            seen.add(value)
            if EXCLUDE.search(value):
                withheld += 1
                continue
            if len(out) >= MAX_STRINGS:
                truncated = True
                break
            out.append({"value": value, "offset": offset, "line": 0, "function": None})
        if budget <= 0:
            truncated = True
            break
    return out, withheld, truncated


def summarize(facts: dict[str, Any], underscored: bool = False) -> dict[str, Any]:
    """Facts every format shares: dangerous and banned imports, platform use, and weak hashes.

    `underscored`: the format prefixes C symbol names with one underscore (Mach-O), which comparisons drop.
    """
    plain = (lambda n: n[1:] if n.startswith("_") else n) if underscored else (lambda n: n)
    names = {plain(i["name"]): i for i in facts["imports"]}
    facts["banned"] = sorted(
        ({"name": n, "kind": "dangerous" if n in DANGEROUS else "banned"} for n in names if n in DANGEROUS | BANNED),
        key=lambda b: b["name"],
    )
    facts["platform"] = {kind: sorted(n for n in names if n in members) for kind, members in PLATFORM.items()}
    facts["platform"] = {k: v for k, v in facts["platform"].items() if v}
    native = [{"function": None, "line": 0, "algorithm": WEAK_HASHES[n]} for n in sorted(names) if n in WEAK_HASHES]
    facts["crypto"] = [c for c in facts.get("crypto") or [] if c.get("function")] + native  # keep what IL showed
    facts["hardening"]["canary"] = bool(set(names) & CANARY) or bool(facts["hardening"].get("canary"))
    return facts


# ---------------------------------------------------------------- PE


def pe(r: Reader, dotnet: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    lfanew = r.u32(0x3C)
    if r.raw(lfanew, 4) != b"PE\0\0":
        raise FormatError("there's no PE signature")
    coff = lfanew + 4
    machine, nsections = r.u16(coff), r.u16(coff + 2)
    opt_size, characteristics = r.u16(coff + 16), r.u16(coff + 18)
    opt = coff + 20
    magic = r.u16(opt)
    if magic not in (0x10B, 0x20B):
        raise FormatError(f"unknown optional header magic {magic:#x}")
    plus = magic == 0x20B
    entry = r.u32(opt + 16)
    headers_size = r.u32(opt + 60)
    subsystem, dll_flags = r.u16(opt + 68), r.u16(opt + 70)
    count = min(r.u32(opt + (108 if plus else 92)), 16)
    base = opt + (112 if plus else 96)
    dirs = [(r.u32(base + 8 * i), r.u32(base + 8 * i + 4)) for i in range(count)] + [(0, 0)] * (16 - count)
    image_base = r.u64(opt + 24) if plus else r.u32(opt + 28)

    sections = []
    table = opt + opt_size
    for i in range(min(nsections, MAX_SECTIONS)):
        s = table + 40 * i
        flags = r.u32(s + 36)
        raw_size, raw_ptr = r.u32(s + 16), r.u32(s + 20)
        sample = r.raw(raw_ptr, min(raw_size, ENTROPY_SAMPLE, max(0, r.size - raw_ptr))) if raw_ptr < r.size else b""
        sections.append({
            "name": r.raw(s, 8).rstrip(b"\0").decode("latin-1"), "va": r.u32(s + 12), "virtual_size": r.u32(s + 8),
            "size": raw_size, "offset": raw_ptr, "executable": bool(flags & 0x20000000),
            "writable": bool(flags & 0x80000000), "entropy": entropy(sample),
        })  # fmt: skip

    def offset(rva: int) -> int:
        if rva < headers_size:
            return rva
        for sec in sections:
            span = max(sec["virtual_size"], sec["size"])
            if sec["va"] <= rva < sec["va"] + span:
                off = rva - sec["va"] + sec["offset"]
                if off < sec["offset"] + sec["size"] and off < r.size:
                    return off
        raise FormatError(f"address {rva:#x} isn't backed by the file")

    truncated: dict[str, int] = {}
    imports: list[dict[str, Any]] = []
    libraries: list[str] = []

    def thunks(at: int, library: str, delay: bool) -> None:
        width, high = (8, 1 << 63) if plus else (4, 1 << 31)
        for k in range(MAX_IMPORTS):
            value = r.u64(at + width * k) if plus else r.u32(at + width * k)
            if value == 0:
                return
            if len(imports) >= MAX_IMPORTS:
                truncated["imports"] = truncated.get("imports", 0) + 1
                return
            name = f"#{value & 0xFFFF}" if value & high else r.cstr(offset(value & 0x7FFFFFFF) + 2, 256)
            imports.append({"library": library, "name": name, **({"delay": True} if delay else {})})

    if dirs[1][0]:
        at = offset(dirs[1][0])
        for n in range(MAX_LIBRARIES):
            d = at + 20 * n
            lookup, name_rva, first = r.u32(d), r.u32(d + 12), r.u32(d + 16)
            if not (lookup or name_rva or first):
                break
            library = r.cstr(offset(name_rva), 256)
            libraries.append(library)
            thunks(offset(lookup or first), library, False)
    if dirs[13][0]:  # delay-loaded imports
        at = offset(dirs[13][0])
        for n in range(MAX_LIBRARIES):
            d = at + 32 * n
            attributes, name_rva, names_rva = r.u32(d), r.u32(d + 4), r.u32(d + 16)
            if not (name_rva or names_rva):
                break
            fix = 0 if attributes & 1 else image_base  # old-style descriptors hold addresses, not RVAs
            library = r.cstr(offset(name_rva - fix), 256)
            libraries.append(library)
            thunks(offset(names_rva - fix), library, True)

    exports: list[dict[str, Any]] = []
    if dirs[0][0]:
        at = offset(dirs[0][0])
        names, table_rva = r.u32(at + 24), r.u32(at + 32)
        for i in range(min(names, MAX_EXPORTS)):
            exports.append({"name": r.cstr(offset(r.u32(offset(table_rva) + 4 * i)), 256), "kind": "symbol"})
        if names > MAX_EXPORTS:
            truncated["exports"] = names - MAX_EXPORTS

    cookie, seh_handlers = 0, 0
    if dirs[10][0]:
        at = offset(dirs[10][0])
        size = r.u32(at)
        if plus and size >= 96:
            cookie = r.u64(at + 88)
        elif not plus and size >= 72:
            cookie, seh_handlers = r.u32(at + 60), r.u32(at + 68)

    managed = None
    if dirs[14][0] and dotnet is not None:
        managed = dotnet(r, offset, dirs[14][0], dirs[14][1])
    il_only = bool(managed and managed.get("flags", {}).get("il_only"))
    no_seh = bool(dll_flags & 0x400)
    hardening = {
        "aslr": bool(dll_flags & 0x40) and not characteristics & 0x0001,  # relocations stripped defeats it
        "high_entropy_va": bool(dll_flags & 0x20) if plus else None,
        "dep": bool(dll_flags & 0x100),
        "cfg": bool(dll_flags & 0x4000),
        "safeseh": None if plus or il_only or machine != 0x14C else (no_seh or seh_handlers > 0),
        "gs_cookie": None if il_only else cookie != 0,
        "force_integrity": bool(dll_flags & 0x80),
        "wx_sections": [s["name"] for s in sections if s["executable"] and s["writable"]],
    }
    known = set(libraries) | {i["name"] for i in imports} | {e["name"] for e in exports}
    ranges = [(s["offset"], s["offset"] + s["size"]) for s in sections if not s["executable"]]
    found, withheld, cut = ([], 0, False) if managed else strings(r, ranges or [(0, r.size)], known)
    if cut:
        truncated["strings"] = 1
    facts = {
        "format": "pe", "kind": "library" if characteristics & 0x2000 else "executable",
        "arch": PE_MACHINES.get(machine, f"{machine:#x}"), "bits": 64 if plus else 32, "entry": entry,
        "subsystem": subsystem,
        "sections": [{k: v for k, v in s.items() if k not in ("va", "offset")} for s in sections],
        "libraries": sorted(set(libraries), key=str.lower), "imports": imports, "exports": exports,
        "strings": found, "withheld": withheld, "signed": dirs[4][1] > 0, "hardening": hardening,
        "dotnet": managed, "identifiers": [], "truncated": truncated,
    }  # fmt: skip
    return summarize(facts)


# ---------------------------------------------------------------- ELF


def elf(r: Reader) -> dict[str, Any]:
    klass, order = r.u8(4), r.u8(5)
    if klass not in (1, 2) or order not in (1, 2):
        raise FormatError("unknown ELF class or byte order")
    r.big, b64 = order == 2, klass == 2
    e_type, machine = r.u16(16), r.u16(18)
    if b64:
        entry, phoff, shoff = r.u64(24), r.u64(32), r.u64(40)
        phentsize, phnum, shentsize, shnum, shstrndx = r.u16(54), r.u16(56), r.u16(58), r.u16(60), r.u16(62)
    else:
        entry, phoff, shoff = r.u32(24), r.u32(28), r.u32(32)
        phentsize, phnum, shentsize, shnum, shstrndx = r.u16(42), r.u16(44), r.u16(46), r.u16(48), r.u16(50)

    segments = []
    for i in range(min(phnum, MAX_SEGMENTS) if phoff else 0):
        p = phoff + phentsize * i
        if b64:
            seg = {"type": r.u32(p), "flags": r.u32(p + 4), "offset": r.u64(p + 8), "vaddr": r.u64(p + 16),
                   "filesz": r.u64(p + 32), "memsz": r.u64(p + 40)}  # fmt: skip
        else:
            seg = {"type": r.u32(p), "offset": r.u32(p + 4), "vaddr": r.u32(p + 8), "filesz": r.u32(p + 16),
                   "memsz": r.u32(p + 20), "flags": r.u32(p + 24)}  # fmt: skip
        segments.append(seg)

    def file_offset(vaddr: int) -> int:
        for s in segments:
            if s["type"] == 1 and s["vaddr"] <= vaddr < s["vaddr"] + s["filesz"]:
                return vaddr - s["vaddr"] + s["offset"]
        raise FormatError(f"address {vaddr:#x} isn't in a loaded segment")

    sections = []
    for i in range(min(shnum, MAX_SECTIONS * 16) if shoff else 0):
        s = shoff + shentsize * i
        if b64:
            sec = {"name_at": r.u32(s), "type": r.u32(s + 4), "flags": r.u64(s + 8), "offset": r.u64(s + 24),
                   "size": r.u64(s + 32), "link": r.u32(s + 40), "entsize": r.u64(s + 56)}  # fmt: skip
        else:
            sec = {"name_at": r.u32(s), "type": r.u32(s + 4), "flags": r.u32(s + 8), "offset": r.u32(s + 16),
                   "size": r.u32(s + 20), "link": r.u32(s + 24), "entsize": r.u32(s + 36)}  # fmt: skip
        sections.append(sec)
    names_at = sections[shstrndx]["offset"] if shstrndx < len(sections) else None
    for sec in sections:
        sec["name"] = r.cstr(names_at + sec["name_at"], 128) if names_at is not None else ""

    dynamic: list[tuple[int, int]] = []
    dyn = next((s for s in segments if s["type"] == 2), None)
    if dyn:
        width = 16 if b64 else 8
        for k in range(min(dyn["filesz"] // width, 4096)):
            at = dyn["offset"] + width * k
            tag, value = (r.u64(at), r.u64(at + 8)) if b64 else (r.u32(at), r.u32(at + 4))
            if tag == 0:
                break
            dynamic.append((tag, value))
    tags: dict[int, list[int]] = {}
    for tag, value in dynamic:
        tags.setdefault(tag, []).append(value)
    dynstr = file_offset(tags[5][0]) if 5 in tags else None

    def dynstring(value: int) -> str:
        return r.cstr(dynstr + value, 512) if dynstr is not None else ""

    def symbols(table: dict[str, Any] | None, strtab: int | None) -> list[dict[str, Any]]:
        if table is None or strtab is None:
            return []
        size = 24 if b64 else 16
        out = []
        for k in range(1, min(table["size"] // size, MAX_SYMBOLS)):
            at = table["offset"] + size * k
            if b64:
                name_at, info, other, shndx = r.u32(at), r.u8(at + 4), r.u8(at + 5), r.u16(at + 6)
            else:
                name_at, info, other, shndx = r.u32(at), r.u8(at + 12), r.u8(at + 13), r.u16(at + 14)
            name = r.cstr(strtab + name_at, 256) if name_at else ""
            if name:
                out.append({"name": name, "bind": info >> 4, "type": info & 0xF, "visibility": other & 3,
                            "defined": shndx != 0})  # fmt: skip
        return out

    dynsym = next((s for s in sections if s["type"] == 11), None)
    if dynsym is not None and dynsym["link"] < len(sections):
        dynamic_symbols = symbols(dynsym, sections[dynsym["link"]]["offset"])
    elif 6 in tags and dynstr is not None:  # no section headers: the symbol table runs up to the string table
        start = file_offset(tags[6][0])
        dynamic_symbols = symbols({"offset": start, "size": max(0, dynstr - start)}, dynstr)
    else:
        dynamic_symbols = []
    symtab = next((s for s in sections if s["type"] == 2), None)
    local_symbols = (
        symbols(symtab, sections[symtab["link"]]["offset"]) if symtab and symtab["link"] < len(sections) else []
    )

    imports = [{"library": None, "name": s["name"]} for s in dynamic_symbols if not s["defined"]][:MAX_IMPORTS]
    exports = [{"name": s["name"], "kind": "symbol"} for s in dynamic_symbols
               if s["defined"] and s["bind"] in (1, 2) and s["type"] in (1, 2)
               and s["visibility"] in (0, 3)]  # fmt: skip
    public = {e["name"] for e in exports}
    identifiers = sorted(
        {s["name"] for s in local_symbols if s["defined"] and s["type"] == 2 and s["name"] not in public}
    )

    interp = next((r.cstr(s["offset"], 256) for s in segments if s["type"] == 3), None)
    flags, flags_1 = (tags.get(30) or [0])[0], (tags.get(0x6FFFFFFB) or [0])[0]
    executable = e_type == 2 or (e_type == 3 and (interp is not None or bool(flags_1 & 0x08000000)))
    stack = next((s for s in segments if s["type"] == 0x6474E551), None)
    relro = any(s["type"] == 0x6474E552 for s in segments)
    bind_now = 24 in tags or bool(flags & 0x8) or bool(flags_1 & 0x1)
    names = {s["name"] for s in dynamic_symbols} | {s["name"] for s in local_symbols}
    hardening = {
        "pie": e_type == 3 if executable else None,
        "nx": (not stack["flags"] & 1) if stack else None,  # no PT_GNU_STACK: the loader's default for the arch
        "relro": ("full" if bind_now else "partial") if relro else "none",
        "canary": bool(names & CANARY),
        "fortify": any(n.startswith("__") and n.endswith("_chk") for n in names),
        "wx_sections": [f"segment {i}" for i, s in enumerate(segments) if s["type"] == 1 and s["flags"] & 3 == 3],
        "rpath": [dynstring(v) for v in tags.get(15, [])],
        "runpath": [dynstring(v) for v in tags.get(29, [])],
    }
    libraries = [dynstring(v) for v in tags.get(1, [])][:MAX_LIBRARIES]
    soname = [dynstring(v) for v in tags.get(14, [])]
    known = set(libraries) | names | set(hardening["rpath"]) | set(hardening["runpath"]) | set(soname) | {interp or ""}
    data_sections = [(s["offset"], s["offset"] + s["size"]) for s in sections
                     if s["type"] != 8 and s["flags"] & 2 and not s["flags"] & 4]  # fmt: skip
    found, withheld, cut = strings(r, data_sections or [(0, r.size)], known)
    kind = {1: "object", 2: "executable", 4: "core"}.get(e_type, "executable" if executable else "library")
    facts = {
        "format": "elf", "kind": kind, "arch": ELF_MACHINES.get(machine, f"{machine:#x}"), "bits": 64 if b64 else 32,
        "entry": entry, "interpreter": interp,
        "sections": [{"name": s["name"], "size": s["size"], "executable": bool(s["flags"] & 4),
                      "writable": bool(s["flags"] & 1)} for s in sections if s["name"]][:MAX_SECTIONS],
        "libraries": libraries, "imports": imports, "exports": exports[:MAX_EXPORTS], "strings": found,
        "withheld": withheld, "signed": None, "hardening": hardening, "dotnet": None,
        "identifiers": identifiers[:MAX_IDENTIFIERS], "truncated": {"strings": 1} if cut else {},
    }  # fmt: skip
    return summarize(facts)


# ---------------------------------------------------------------- Mach-O

MACHO_MAGIC = {0xFEEDFACE: (False, False), 0xFEEDFACF: (False, True), 0xCEFAEDFE: (True, False),
               0xCFFAEDFE: (True, True)}  # fmt: skip
MACHO_CODE = {"__text", "__stubs", "__stub_helper", "__symbol_stub", "__picsymbolstub", "__auth_stubs"}


def macho(r: Reader) -> dict[str, Any]:
    head = struct.unpack_from(">I", r.data, 0)[0]
    slices: list[str] = []
    base = 0
    if head in (0xCAFEBABE, 0xCAFEBABF):  # a universal binary: analyze the first slice
        r.big = True
        count = r.u32(4)
        if not 0 < count < 32:
            raise FormatError("not a universal binary (perhaps a Java class file)")
        width = 32 if head == 0xCAFEBABF else 20
        for i in range(count):
            cpu = r.u32(8 + width * i)
            slices.append(MACHO_CPUS.get(cpu, f"{cpu:#x}"))
        base = r.u64(8 + 8) if head == 0xCAFEBABF else r.u32(8 + 8)
    magic = struct.unpack_from("<I", r.data, base)[0] if base + 4 <= r.size else 0
    if magic not in MACHO_MAGIC:
        raise FormatError("there's no Mach-O header")
    r.big, b64 = MACHO_MAGIC[magic]
    cpu, filetype, ncmds, flags = r.u32(base + 4), r.u32(base + 12), r.u32(base + 16), r.u32(base + 24)
    at = base + (32 if b64 else 28)
    sections, libraries, rpaths = [], [], []
    symtab = None
    signed = encrypted = False
    wx = []
    for _ in range(min(ncmds, MAX_COMMANDS)):
        cmd, size = r.u32(at), r.u32(at + 4)
        if size < 8:
            raise FormatError("a load command is shorter than its header")
        kind = cmd & ~0x80000000
        if kind in (0x1, 0x19):  # LC_SEGMENT, LC_SEGMENT_64
            segname = r.raw(at + 8, 16).rstrip(b"\0").decode("latin-1")
            initprot = r.u32(at + (60 if b64 else 44))
            nsects = r.u32(at + (64 if b64 else 48))
            if initprot & 2 and initprot & 4:
                wx.append(segname)
            first, width = at + (72 if b64 else 56), (80 if b64 else 68)
            for k in range(min(nsects, MAX_SECTIONS)):
                s = first + width * k
                sec_size = r.u64(s + 40) if b64 else r.u32(s + 36)
                sec_off = r.u32(s + (48 if b64 else 40))
                sectname = r.raw(s, 16).rstrip(b"\0").decode("latin-1")
                sections.append({"name": f"{segname},{sectname}", "size": sec_size, "offset": base + sec_off,
                                 "executable": bool(initprot & 4), "writable": bool(initprot & 2)})  # fmt: skip
        elif kind == 0x2:  # LC_SYMTAB
            symtab = (base + r.u32(at + 8), r.u32(at + 12), base + r.u32(at + 16))
        elif kind in (0xC, 0x18, 0x1F, 0x20):  # LC_LOAD_DYLIB and its weak, re-export, and lazy variants
            libraries.append(r.cstr(at + r.u32(at + 8), 512))
        elif kind == 0x1C:  # LC_RPATH
            rpaths.append(r.cstr(at + r.u32(at + 8), 512))
        elif kind == 0x1D:  # LC_CODE_SIGNATURE
            signed = True
        elif kind in (0x21, 0x2C):  # LC_ENCRYPTION_INFO(_64)
            encrypted = encrypted or r.u32(at + 16) != 0
        at += size
    imports, exports, identifiers = [], [], []
    if symtab:
        symoff, nsyms, stroff = symtab
        width = 16 if b64 else 12
        for k in range(min(nsyms, MAX_SYMBOLS)):
            s = symoff + width * k
            strx, ntype = r.u32(s), r.u8(s + 4)
            if ntype & 0xE0 or not strx:  # debugging entries
                continue
            name = r.cstr(stroff + strx, 256)
            external, undefined = bool(ntype & 1), ntype & 0xE == 0
            if undefined and external and len(imports) < MAX_IMPORTS:
                imports.append({"library": None, "name": name})
            elif external and not undefined and len(exports) < MAX_EXPORTS:
                exports.append({"name": name, "kind": "symbol"})
            elif not external and not undefined and len(identifiers) < MAX_IDENTIFIERS:
                identifiers.append(name)
    executable = filetype == 2
    hardening = {
        "pie": bool(flags & 0x200000) if executable else None,
        "nx": not flags & 0x20000,  # MH_ALLOW_STACK_EXECUTION
        "canary": False,
        "wx_sections": wx,
        "rpath": rpaths,
    }
    known = set(libraries) | set(rpaths) | {i["name"] for i in imports} | {e["name"] for e in exports}
    # Constant strings live in __TEXT, which is executable, so data sections are chosen by name, not protection.
    ranges = [(s["offset"], s["offset"] + s["size"]) for s in sections
              if s["offset"] and s["name"].split(",")[1] not in MACHO_CODE]  # fmt: skip
    found, withheld, cut = strings(r, ranges or [(base, r.size)], known)
    facts = {
        "format": "macho", "kind": {1: "object", 2: "executable", 6: "library", 8: "bundle"}.get(filetype, "other"),
        "arch": MACHO_CPUS.get(cpu, f"{cpu:#x}"), "bits": 64 if b64 else 32, "entry": None, "slices": slices,
        "sections": [{k: v for k, v in s.items() if k != "offset"} for s in sections],
        "libraries": libraries[:MAX_LIBRARIES], "imports": imports, "exports": exports, "strings": found,
        "withheld": withheld, "signed": signed, "encrypted": encrypted, "hardening": hardening, "dotnet": None,
        "identifiers": sorted(set(identifiers)), "truncated": {"strings": 1} if cut else {},
    }  # fmt: skip
    return summarize(facts, underscored=True)


def analyze(data: Any, dotnet: Callable[..., dict[str, Any]] | None = None) -> dict[str, Any]:
    r = Reader(data)
    if r.size < 64:
        raise FormatError("too small to be an executable")
    head = bytes(data[:4])
    if head[:2] == b"MZ":
        return pe(r, dotnet)
    if head == b"\x7fELF":
        return elf(r)
    if struct.unpack("<I", head)[0] in MACHO_MAGIC or head in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
        return macho(r)
    raise FormatError("not a PE, ELF, or Mach-O file")
