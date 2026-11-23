# native-samples lab

Six small native executables, two each for Linux (ELF), Windows (PE), and macOS (Mach-O). The Veritas project owns them. They exist so the binary engine can be demonstrated and regression-tested without a compiler and without Ghidra. In each pair, one sample is weak on purpose and its twin is hardened. The twin differs only in what it should.

They're built byte by byte by `tools/make_samples.py`, which needs only Python. Each file is well-formed: its headers, sections, import tables, symbols, and strings are real. **None of them holds runnable code**, apart from a single `ret` instruction. Veritas reads their structure and never runs them.

## Authorization

The Veritas project owns these files. They may be analyzed by Veritas for regression tests and demonstrations. `veritas.charter.yaml` references this file, so its contents are hashed into the charter digest.

## What each sample contains

| Sample | Weak on purpose | Hardened twin |
|---|---|---|
| `weak-elf` / `hardened-elf` | not position-independent, executable stack, a writable and executable segment, no RELRO, no stack protector, a relative RPATH (`lib`), imports `gets` and `strcpy`, a made-up access key in its strings | PIE, a non-executable stack, full RELRO, a stack protector, an `$ORIGIN` RPATH, bounded functions only |
| `weak.exe` / `hardened.exe` | no ASLR (relocations stripped), no DEP, a writable code section, imports `gets` and `strcpy` | ASLR with high entropy, DEP, Control Flow Guard, `strcpy_s` instead of `strcpy` |
| `weak-macho` / `hardened-macho` | not position-independent, stack execution allowed, imports `gets` and `strcpy` | PIE, a stack protector, an `@loader_path` RPATH |

`expected-code-findings.yaml` is the ground truth. The weak samples must produce exactly the findings it lists, and the hardened twins must produce none. After changing the generator, run it again and update the pins in `veritas.charter.yaml`. The unit tests check that the committed files match what the generator builds.
