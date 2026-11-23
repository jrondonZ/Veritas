# 0004. Organize packages by trust boundary and enforce layering with a test

- Status: Accepted
- Date: 2026-11-18

## Context

Phase 0 started as flat modules. The gateway image copied all of them, even though the gateway needs only a few. Without explicit boundaries, kernel code could drift into the trusted computing base, or a network client could slip in unnoticed.

## Decision

- Group packages by the components and trust boundaries in docs/architecture.md:
  - `core`: pure primitives
  - `gateway`
  - `scope`
  - `store`
  - `plugins`
  - `sandbox`
  - `environments`
  - `cli`: one module per command group
- `veritas.core` uses only the standard library and pydantic. `veritas.gateway` uses only `veritas.core`, pydantic, and h11.
- The gateway image copies only `veritas/__init__.py`, `veritas/core`, and `veritas/gateway`. A per-Dockerfile ignore file allowlists exactly those paths, and the image's Python dependencies are hash-pinned for linux/amd64 and linux/arm64.
- `tests/unit/test_architecture.py` checks the import rules statically. It also checks that only the CLI imports typer, that no module imports a network or hosted-model client, and that third-party imports match the declared dependencies.
- Tests mirror the package layout. Unit tests run without Docker, and integration tests are marked `docker` and rebuild images from the working tree.

## Consequences

- A change that widens the gateway's imports fails CI, instead of quietly enlarging the TCB.
- Adding a dependency takes two edits, `pyproject.toml` and the architecture test, and gateway dependencies need a lock refresh.
