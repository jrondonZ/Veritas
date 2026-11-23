# lexfmt lab

`lexfmt` is a small reader and writer for `.lex` project files. The Veritas project owns it, and it exists so Analyze can be demonstrated and regression-tested end to end. Analyze reverse-engineers the shipped bundle, writes a behavior spec, and verifies a clean-room reimplementation against conformance vectors.

## Authorization

The Veritas project owns this code and its file format. It may be analyzed by Veritas and reimplemented clean-room for interoperability testing. `veritas.charter.yaml` references this file, so its contents are hashed into the charter digest.

## Contents

- `dist/lexfmt.js` is the subject: the library as shipped, a single-file ES module. The charter pins it by SHA-256.
- `tools/make-samples.mjs` is the lab owner's tooling. It writes `samples/*.lex` and `conformance.json` by running the library. Veritas never runs the subject.
- `conformance.json` holds the operator-owned conformance vectors: each sample file with its expected result or error code. They may cross the spec gate with an approved spec.
- `expected-facts.yaml` is the ground truth for the mechanical behavior spec. It lists every fact the spec may assert as observed, and what it must never assert.

## What the subject contains, on purpose

| Item | Why |
|---|---|
| A 4-byte magic number and fixed-offset header fields | file-format facts the spec should state exactly |
| Length-prefixed sections read relative to a moving position | a layout the spec states as a relative record |
| A CRC-32 trailer (reflected polynomial `0xEDB88320`) | a well-known constant the spec names |
| Error codes (`LEX_BAD_MAGIC` and others) | interface constants that may cross the gate, while error messages may not |
| Header flag bit `0x04`, preserved but never interpreted | a ground-truth unknown that must never be asserted as observed |
| A toy license-key check for section type `0x7F` | license logic that Analyze must exclude and report as a limitation (§5.4) |
