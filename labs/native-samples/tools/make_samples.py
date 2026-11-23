"""Writes the native sample binaries: `python labs/native-samples/tools/make_samples.py`.

The lab owner's tooling, stdlib only. Each sample is a small, well-formed ELF, PE, or Mach-O
file with known headers, imports, strings, and hardening flags. The samples hold no runnable
code: Veritas reads their structure and never executes them. A weak sample and its hardened
twin are built the same way, so a correct look-alike differs only in what it should.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

FAKE_KEY = "AKIAVRTFAKEKEY000002"  # a made-up value in the documented access-key format


def _align(buf: bytearray, n: int) -> None:
    buf.extend(b"\0" * (-len(buf) % n))


# ---------------------------------------------------------------- ELF64, x86-64, little-endian


def elf(*, pie: bool, nx: bool | None, relro: bool, canary: bool, wx: bool, rpath: str | None,
        imports: tuple[str, ...], strings: tuple[str, ...]) -> bytes:  # fmt: skip
    base = 0 if pie else 0x400000
    dynstr = bytearray(b"\0")

    def name(text: str) -> int:
        offset = len(dynstr)
        dynstr.extend(text.encode() + b"\0")
        return offset

    needed = name("libc.so.6")
    rpath_at = name(rpath) if rpath is not None else None
    symbols = [(name(n), 0x12, 0, 0) for n in (*imports, *(["__stack_chk_fail"] if canary else []))]
    exported = name("lab_main")

    segments = 3 + (nx is not None) + relro  # INTERP, LOAD, DYNAMIC, [GNU_STACK], [GNU_RELRO]
    body = bytearray(64 + 56 * segments)
    interp_at = len(body)
    body.extend(b"/lib64/ld-linux-x86-64.so.2\0")
    _align(body, 8)
    dynsym_at = len(body)
    text_at_placeholder = len(body) + 24 * (len(symbols) + 2) + len(dynstr)  # recomputed below
    del text_at_placeholder
    sym_count = len(symbols) + 2  # the null symbol, the imports, and one export
    body.extend(b"\0" * (24 * sym_count))
    dynstr_at = len(body)
    body.extend(dynstr)
    _align(body, 16)
    text_at = len(body)
    body.extend(b"\xc3" + b"\0" * 15)  # one `ret`, never run
    rodata_at = len(body)
    for s in strings:
        body.extend(s.encode() + b"\0")
    rodata_end = len(body)
    _align(body, 8)
    entries = [(1, needed), (5, base + dynstr_at), (6, base + dynsym_at), (10, len(dynstr)), (11, 24)]
    if rpath_at is not None:
        entries.append((15, rpath_at))
    if relro:
        entries.append((30, 0x8))  # DF_BIND_NOW
    entries.append((0x6FFFFFFB, (0x08000000 if pie else 0) | (1 if relro else 0)))
    entries.append((0, 0))
    dynamic_at = len(body)
    for tag, value in entries:
        body.extend(struct.pack("<qQ", tag, value))
    shstr = b"\0.interp\0.dynsym\0.dynstr\0.text\0.rodata\0.dynamic\0.shstrtab\0"
    shstr_at = len(body)
    body.extend(shstr)
    _align(body, 8)
    sh_at = len(body)

    # the symbols, now that the text address is known
    rows = [struct.pack("<IBBHQQ", 0, 0, 0, 0, 0, 0)]
    rows += [struct.pack("<IBBHQQ", at, info, 0, shndx, 0, 0) for at, info, shndx, _ in symbols]
    rows.append(struct.pack("<IBBHQQ", exported, 0x12, 0, 4, base + text_at, 1))
    body[dynsym_at : dynsym_at + 24 * sym_count] = b"".join(rows)

    names = {n: shstr.index(n.encode() + b"\0") for n in
             (".interp", ".dynsym", ".dynstr", ".text", ".rodata", ".dynamic", ".shstrtab")}  # fmt: skip
    sections = [
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
        (names[".interp"], 1, 2, base + interp_at, interp_at, 28, 0, 0, 1, 0),
        (names[".dynsym"], 11, 2, base + dynsym_at, dynsym_at, 24 * sym_count, 3, 1, 8, 24),
        (names[".dynstr"], 3, 2, base + dynstr_at, dynstr_at, len(dynstr), 0, 0, 1, 0),
        (names[".text"], 1, 6, base + text_at, text_at, 16, 0, 0, 16, 0),
        (names[".rodata"], 1, 2, base + rodata_at, rodata_at, rodata_end - rodata_at, 0, 0, 1, 0),
        (names[".dynamic"], 6, 3, base + dynamic_at, dynamic_at, 16 * len(entries), 3, 0, 8, 16),
        (names[".shstrtab"], 3, 0, 0, shstr_at, len(shstr), 0, 0, 1, 0),
    ]
    for s in sections:
        body.extend(struct.pack("<IIQQQQIIQQ", *s))
    size = len(body)

    rx, rw, rwx = 5, 6, 7
    program = [(3, 4, interp_at, 28), (1, rwx if wx else rx, 0, size), (2, rw, dynamic_at, 16 * len(entries))]
    if nx is not None:
        program.append((0x6474E551, rw if nx else rwx, 0, 0))
    if relro:
        program.append((0x6474E552, 4, dynamic_at, 16 * len(entries)))
    for i, (kind, flags, offset, length) in enumerate(program):
        body[64 + 56 * i : 64 + 56 * (i + 1)] = struct.pack("<IIQQQQQQ", kind, flags, offset, base + offset,
                                                             base + offset, length, length, 8)  # fmt: skip
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8
    body[:64] = ident + struct.pack("<HHIQQQIHHHHHH", 3 if pie else 2, 0x3E, 1, base + text_at, 64, sh_at, 0, 64, 56,
                                    len(program), 64, len(sections), len(sections) - 1)  # fmt: skip
    return bytes(body)


# ---------------------------------------------------------------- PE32+, x86-64


def pe(*, aslr: bool, dep: bool, wx: bool, imports: dict[str, tuple[str, ...]], strings: tuple[str, ...]) -> bytes:
    text_rva, rdata_rva, file_align = 0x1000, 0x2000, 0x200
    rdata = bytearray()
    dlls = list(imports)
    descriptors_size = 20 * (len(dlls) + 1)
    rdata.extend(b"\0" * descriptors_size)
    thunk_at = {}
    for dll in dlls:
        thunk_at[dll] = len(rdata)
        rdata.extend(b"\0" * (8 * (len(imports[dll]) + 1) * 2))  # lookup table, then address table
    hints = {}
    for dll in dlls:
        for fn in imports[dll]:
            _align(rdata, 2)
            hints[(dll, fn)] = len(rdata)
            rdata.extend(b"\0\0" + fn.encode() + b"\0")
    names = {}
    for dll in dlls:
        names[dll] = len(rdata)
        rdata.extend(dll.encode() + b"\0")
    for s in strings:
        rdata.extend(s.encode() + b"\0")
    for i, dll in enumerate(dlls):
        lookup = thunk_at[dll]
        address = lookup + 8 * (len(imports[dll]) + 1)
        for k, fn in enumerate(imports[dll]):
            entry = struct.pack("<Q", rdata_rva + hints[(dll, fn)])
            rdata[lookup + 8 * k : lookup + 8 * k + 8] = entry
            rdata[address + 8 * k : address + 8 * k + 8] = entry
        rdata[20 * i : 20 * i + 20] = struct.pack("<IIIII", rdata_rva + lookup, 0, 0, rdata_rva + names[dll],
                                                  rdata_rva + address)  # fmt: skip
    rdata_size = len(rdata)
    _align(rdata, file_align)
    text = bytearray(b"\xc3" + b"\0" * (file_align - 1))  # one `ret`, never run

    headers = bytearray(0x400)
    headers[:2] = b"MZ"
    headers[0x3C:0x40] = struct.pack("<I", 0x80)
    headers[0x80:0x84] = b"PE\0\0"
    characteristics = 0x0022 | (0 if aslr else 0x0001)  # executable, large-address-aware; relocations stripped
    headers[0x84:0x98] = struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, characteristics)
    dll_flags = 0x8000 | ((0x0060 | 0x4000) if aslr else 0) | (0x0100 if dep else 0)
    image_size = rdata_rva + 0x1000 * (1 + rdata_size // 0x1000)
    opt = struct.pack("<HBBIIIII", 0x20B, 14, 0, len(text), len(rdata), 0, text_rva, text_rva)
    opt += struct.pack("<QIIHHHHHHIIIIHH", 0x140000000, 0x1000, file_align, 6, 0, 0, 0, 6, 0, 0, image_size, 0x400,
                       0, 3, dll_flags)  # fmt: skip
    opt += struct.pack("<QQQQII", 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    dirs = [(0, 0)] * 16
    dirs[1] = (rdata_rva, descriptors_size)
    opt += b"".join(struct.pack("<II", *d) for d in dirs)
    headers[0x98 : 0x98 + 240] = opt
    text_flags = 0x60000020 | (0x80000000 if wx else 0)  # code, read, execute (and write, if asked)
    sections = struct.pack("<8sIIIIIIHHI", b".text", len(text), text_rva, len(text), 0x400, 0, 0, 0, 0, text_flags)
    sections += struct.pack("<8sIIIIIIHHI", b".rdata", rdata_size, rdata_rva, len(rdata), 0x400 + len(text), 0, 0, 0,
                            0, 0x40000040)  # fmt: skip
    headers[0x188 : 0x188 + 80] = sections
    return bytes(headers + text + rdata)


# ---------------------------------------------------------------- Mach-O 64, x86-64


def macho(*, pie: bool, exec_stack: bool, canary: bool, rpath: str | None, imports: tuple[str, ...],
          strings: tuple[str, ...]) -> bytes:  # fmt: skip
    names = bytearray(b"\0")
    entries = []
    for n in (*imports, *(["___stack_chk_fail"] if canary else [])):
        entries.append((len(names), 0x01, 0, 0))  # undefined, external
        names.extend(n.encode() + b"\0")
    entries.append((len(names), 0x0F, 1, 0x100000000))  # _main, defined in section 1
    names.extend(b"_main\0")
    cstring = b"".join(s.encode() + b"\0" for s in strings)

    def segment(segname: bytes, prot: int, sections: list[tuple[bytes, int, int]]) -> bytes:
        body = struct.pack("<II16sQQQQIIII", 0x19, 72 + 80 * len(sections), segname, 0, 0, 0, 0, prot, prot,
                           len(sections), 0)  # fmt: skip
        for sectname, offset, size in sections:
            body += struct.pack("<16s16sQQIIIIIIII", sectname, segname, 0, size, offset, 0, 0, 0, 0, 0, 0, 0)
        return body

    def dylib(path: str) -> bytes:
        raw = path.encode() + b"\0"
        raw += b"\0" * (-(24 + len(raw)) % 8)
        return struct.pack("<IIIIII", 0xC, 24 + len(raw), 24, 2, 0x10000, 0x10000) + raw

    def rpath_command(path: str) -> bytes:
        raw = path.encode() + b"\0"
        raw += b"\0" * (-(12 + len(raw)) % 8)
        return struct.pack("<III", 0x8000001C, 12 + len(raw), 12) + raw

    fixed = [dylib("/usr/lib/libSystem.B.dylib")] + ([rpath_command(rpath)] if rpath is not None else [])
    commands_size = (72 + 80 * 2) + sum(len(c) for c in fixed) + 24  # __TEXT with two sections, fixed, LC_SYMTAB
    text_at = 32 + commands_size
    text_at += -text_at % 16
    cstring_at = text_at + 16
    symoff = cstring_at + len(cstring)
    symoff += -symoff % 8
    stroff = symoff + 16 * len(entries)
    commands = segment(b"__TEXT", 5, [(b"__text", text_at, 16), (b"__cstring", cstring_at, len(cstring))])
    commands += b"".join(fixed)
    commands += struct.pack("<IIIIII", 0x2, 24, symoff, len(entries), stroff, len(names))
    flags = 0x85 | (0x200000 if pie else 0) | (0x20000 if exec_stack else 0)  # NOUNDEFS off; DYLDLINK, TWOLEVEL
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 3, 2, len(fixed) + 2, len(commands), flags, 0)
    body = bytearray(header + commands)
    body.extend(b"\0" * (text_at - len(body)))
    body.extend(b"\xc3" + b"\0" * 15)  # one `ret`, never run
    body.extend(cstring)
    body.extend(b"\0" * (symoff - len(body)))
    for strx, ntype, sect, value in entries:
        body.extend(struct.pack("<IBBhQ", strx, ntype, sect, 0, value))
    body.extend(names)
    return bytes(body)


SAMPLES = {
    "weak-elf": lambda: elf(pie=False, nx=False, relro=False, canary=False, wx=True, rpath="lib",
                            imports=("gets", "strcpy", "system", "puts"),
                            strings=("Usage: weak-elf <name>", f"export key {FAKE_KEY}")),
    "hardened-elf": lambda: elf(pie=True, nx=True, relro=True, canary=True, wx=False, rpath="$ORIGIN/lib",
                                imports=("fgets", "snprintf", "puts"), strings=("Usage: hardened-elf <name>",)),
    "weak.exe": lambda: pe(aslr=False, dep=False, wx=True,
                           imports={"msvcrt.dll": ("gets", "strcpy", "printf"), "KERNEL32.dll": ("WinExec",)},
                           strings=("Usage: weak <name>",)),
    "hardened.exe": lambda: pe(aslr=True, dep=True, wx=False,
                               imports={"msvcrt.dll": ("fgets", "strcpy_s", "printf"),
                                        "KERNEL32.dll": ("CreateFileW",)},
                               strings=("Usage: hardened <name>",)),
    "weak-macho": lambda: macho(pie=False, exec_stack=True, canary=False, rpath=None,
                                imports=("_gets", "_strcpy", "_printf"), strings=("Usage: weak-macho <name>",)),
    "hardened-macho": lambda: macho(pie=True, exec_stack=False, canary=True, rpath="@loader_path/../lib",
                                    imports=("_fgets", "_printf"), strings=("Usage: hardened-macho <name>",)),
}  # fmt: skip


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    for name, build in SAMPLES.items():
        (out / name).write_bytes(build())
        print(f"dist/{name}: {len((out / name).read_bytes())} bytes")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parents[1] / "dist")
