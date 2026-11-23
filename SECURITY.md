# Security policy

## Acceptable use

Veritas is for assessing software you own or are authorized in writing to test, in local development environments, purpose-built labs, or isolated staging systems.

- The scope file records the authorization you are relying on. Veritas enforces the scope technically but cannot verify it legally; that responsibility stays with the operator.
- Veritas refuses production environments, targets outside the declared scope, and third-party reconnaissance sources.
- Validation shows that a security control is missing. It never demonstrates exploitation, extracts data, persists, or pivots.
- The labs under `labs/` are intentionally vulnerable. Keep them on the internal networks their compose files define.

## Reporting a vulnerability in Veritas

Report weaknesses in Veritas itself privately, especially any way to get past the gateway, a sandbox, the scope checks, or the audit chain. Don't open a public issue for them.

**Maintainers:** add a private contact address here before the repository is shared.

A useful report includes:

- the affected component and version or commit
- the steps to reproduce, ideally as a test against the bundled lab or the escape suite
- what you expected and what happened

## Supported versions

Veritas is pre-release, and only the latest commit on `main` is supported.

## Security-relevant design

- Trust zones and boundaries: [docs/architecture.md §4](docs/architecture.md#4-trust-boundaries-and-threat-model)
- Safety controls: [docs/architecture.md §9](docs/architecture.md#9-safety-controls)
- Containment tests: `tests/integration/test_escape_suite.py`
