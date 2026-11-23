# 0006. Read app internals through network-less sensor plugins, and decide in the kernel

- Status: Accepted
- Date: 2026-11-19

## Context

Some missing controls can't be seen in HTTP responses. A string-built SQL query (lab L7) returns the same results as a parameterized one for every input that isn't an attack. The design's rule is to prove the control failure without attack input (§9.4). Where the operator owns the app, the app's own query log shows whether a request value became part of the SQL text or was bound as a parameter. Phase 2 has to decide how Veritas reads that log, and how far to trust what it reads.

## Decision

- **The scope declares each sensor.** A `sensors` entry names its kind, its target, and a volume in the environment's compose file. It's part of the scope digest, so the operator acknowledges it. Sensors are allowed only in `disposable` and `local-dev` compose environments.
- **Sensors run sandboxed.** A sensor runs in the `engine` profile, which has no network at all (`--network none`). It runs as a non-root user on a read-only root filesystem with every capability dropped, and the named volume is its only input, mounted read-only.
- **The protocol is mark and collect.** Before an attempt's requests, the kernel asks for the log's current end (`mark`). Afterwards it asks for entries written since then that mention the attempt's markers (`collect`). Each attempt uses its own canary, and a reset empties the log, so a leftover entry can't decide a later attempt.
- **Replies are evidence.** The kernel writes each reply as a canonical record, content-addressed like a gateway exchange (`E-…`). Its provenance is `sensor:<plugin>@<version>`, and the record holds the sensor's image ID. Replay re-reads the record and re-runs the oracle, and bundles carry it.
- **The kernel decides.** The sensor only selects entries. A kernel oracle reads them and confirms a finding only when the canary appears inside SQL statement text. Reports cite the record by ID and never quote target-derived SQL.
- **Selection is deterministic.** An entry keeps only its SQL text and parameters. Offsets and scan counts go to the audit log, so equal behavior yields equal evidence IDs across runs.

## Consequences

- Sensor evidence is weaker than gateway evidence. A gateway exchange is captured by the trusted gateway, but a sensor record is selected by a plugin. A compromised sensor could invent an entry. The finding still cites the gateway exchange that carried the canary. The record names the sensor's image, and the sensor runs with no network and read-only input. Phase 4 plugin signing applies to sensors as well.
- The oracle sees only what the app logs. A query issued outside the logged database layer is invisible, so every sensor finding carries that limitation claim.
- The check sends only letters, digits, and hyphens, which are plain text in any SQL context. Even a vulnerable route sees no metacharacters.
- Each run starts one sensor container, and only when a runnable probe needs it.
