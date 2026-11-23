# notes-cli lab

`notes-cli` is a small .NET command-line tool, written to be insecure. The Veritas project owns it. It exists so the binary engine's .NET reader can be demonstrated and regression-tested on a real compiled assembly. Veritas reads `dist/NotesCli.exe` (its metadata and IL) and never runs it. Don't run it either: the weaknesses are real, even though it does nothing on its own.

## Authorization

The Veritas project owns this code. It may be analyzed by Veritas for security testing and regression tests. `veritas.charter.yaml` references this file, so its contents are hashed into the charter digest.

## Contents

- `src/NotesCli.cs` is the source, written for C# 5, the language of the compiler that ships with Windows.
- `tools/build.ps1` compiles it with that compiler (`csc.exe` from .NET Framework 4). The compiler stamps a time and a module ID into every build, so a rebuild changes the hash. Put the sha256 it prints into `veritas.charter.yaml`.
- `dist/NotesCli.exe` is the subject, as compiled. It's committed, so the lab works on any platform.
- `expected-code-findings.yaml` is the ground truth.

## What the tool contains, on purpose

| ID | Method | Weakness | Look-alike that must stay quiet |
|---|---|---|---|
| D1 | `Store::Search` | the search term is joined into SQL text | `Store::SearchSafe` binds it as a parameter |
| D2 | `Store::Load` | `BinaryFormatter` deserializes a stream | `Store::LoadSafe` uses `XmlSerializer` bound to one type |
| D3 | `Store::Fingerprint` | MD5 | `Store::Checksum` uses SHA-256 |
| D4 | `Store::Sign` | an access key in the code (a made-up value in the documented format) | |
| D5 | `Store::Open` | a file name joined into a `cmd.exe /c` command line | `Store::OpenSafe` starts a program with the name as its argument |
