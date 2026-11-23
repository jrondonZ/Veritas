# 0014. Read compiled code with a stdlib binary engine: .NET metadata and IL, and native headers, without Ghidra

- Status: Accepted
- Date: 2026-11-20

## Context

Much of what teams own and ship is compiled: Windows tools, .NET services, Linux daemons, macOS apps. Ghidra reads all of it, but it's about 1 GB and needs a JVM. The reference laptop has a few hundred megabytes free, and the project avoids downloads it doesn't need (ADR 0007). Most of what a first security pass needs doesn't require a disassembler: the hardening flags, what a file imports, what it embeds, and for .NET, the metadata and which methods call what.

## Decision

- **One stdlib Python engine** reads PE, ELF, and Mach-O files. It shares the Python base image with the sensors, so it adds no download. It runs in the `engine` sandbox: no network, inputs read-only. It hashes each file as it streams, then memory-maps it, so memory stays small. Every read is bounds-checked and every count capped, so hostile input fails to parse. It never crashes the engine.
- **Native facts:**
  - **structure:** format, architecture, sections and their entropy, linked libraries, imports, and exports;
  - **strings:** printable ASCII and UTF-16 strings from data sections;
  - **hardening:** ASLR or PIE, DEP or NX, writable and executable memory, RELRO, stack protector, SafeSEH, and RPATH;
  - **signing:** whether a signature is present (it isn't verified).

  Names the format tables already give aren't counted as string literals. License and copy-protection text becomes a count, never a fact (§5.4).
- **.NET facts come from the CLI metadata,** parsed table by table to ECMA-335. They cover:
  - the assembly and the assemblies it references;
  - public types and methods, which form the interface, and internal names, which are identifiers that never cross the gate;
  - member references, P/Invoke imports, and string literals.

  A light IL scan decodes each method body only far enough to list the strings it loads and the members it calls, in order. Its rules need every step in order:
  - SQL text, then a string join, then a command that runs it;
  - a binary formatter's `Deserialize`;
  - a shell name, then a join, then `Process.Start`;
  - MD5, SHA-1, DES, and RC2 classes.
- **Rules stay precise.** Hardening gaps are reported only for executables and libraries, and only when the header says so. A missing `PT_GNU_STACK`, for example, is left unknown. Stack-protector and RELRO gaps are recorded but not reported, because memory-safe languages don't need them. Banned functions are SDL's list, plus `gets`.
- **Compiled subjects have no source text,** so the clean-room similarity audit can't compare against them. Every analysis of one says so as a limitation.
- **Demo subjects are owned and honest.** `labs/notes-cli` is a C# tool compiled by the compiler that ships with Windows, then committed. `labs/native-samples` holds six ELF, PE, and Mach-O files that a Python script builds byte by byte. They have real structure but no runnable code, and each weak sample has a hardened twin.

## Consequences

- On real files, the engine reads `System.dll`, 3.5 MB with 18,170 methods, in under a second, with every IL body decoded. It also reads `notepad.exe` and `kernel32.dll`. On the labs, findings match the ground truth exactly, and every look-alike and hardened twin stays quiet.
- Without disassembly there's no data flow in native code: a banned import is a candidate, not proof that input reaches it. Packed or encrypted sections hide facts, and the report says so.
- Ghidra remains the opt-in path for decompilation and native data flow, when the operator has room for it.
