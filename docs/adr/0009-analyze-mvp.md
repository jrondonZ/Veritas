# 0009. Build Analyze around a mechanical spec, a hash-checked clean view, and a similarity audit

- Status: Accepted
- Date: 2026-11-19

## Context

Phase 3 makes Veritas a single pipeline. A team assesses software it owns, reverse-engineers how it behaves, and replicates that behavior clean-room. The work had to stay light on a 16 GB laptop and had to run with models off. It also had to give the clean-room boundary (B5) a mechanical guarantee, not only a policy statement.

## Decision

- **JavaScript first, on what's already there.** The engine is Node built-ins plus a vendored copy of acorn, checked against the registry's sha512 and covered by a test. It runs on the lab's pinned `node:24-alpine` base, so it adds no new download. It runs in the `engine` sandbox: no network, inputs read-only. .NET and native engines come later and are opt-in.
- **Exclusion happens in the engine.** A first pass marks license-like functions, by name or by the strings inside them. The second pass emits nothing from inside them, only the fact that they were excluded. The spec reports each one as a limitation (§5.4).
- **A mechanical spec needs no model.** Claims come straight from facts, and each carries a structured `fact` that a lab's ground truth is compared against. Reads count only from a buffer an exported function receives, and writes only to a buffer it returns; a helper's buffer is stated as a record. Claim text names only the public surface.
- **The gate checks what crosses.** It filters for internal identifiers, the subject's own strings, secrets, excluded logic, and winnowing similarity. What crosses is a clean view: claims and facts by interface, plus the operator's hash-pinned conformance vectors, with no evidence IDs. A person approves its digest at a terminal by typing the run ID.
- **The clean room recognizes dirt by location and by hash.** The context builder refuses the run's staged subjects, its dirty documents, and any file whose content hash matches a subject. It records the hash of every input it admits in the audit chain.
- **Verification has two parts.** First, a conformance harness runs the implementation, never the subject, against the vectors in a no-network sandbox. Then a normalized-token similarity audit compares it with the subject's source, using winnowing with k = 12 and a limit of 25%. A pass needs at least 90% of the vectors, a similarity under the limit, and an implementation that loads. Similarity results go to the operator only. A model implementer is told only which vectors failed.

## Consequences

- On `labs/lexfmt` the mechanical spec reaches precision and recall of 1.000 against a hand-written ground truth.
- A renamed or byte-altered copy of the subject passes every vector but fails the similarity audit. An independently written reader passes 12 of 12 vectors and is verified.
- A mechanical spec states structure, not intent. Narrative claims, unknowns that need judgment, and Electron and HAR coverage come with the model roles and later engines.
- The hash check catches only byte-identical copies. The similarity audit is the real defense against copying, and its threshold may need tuning on larger subjects.
