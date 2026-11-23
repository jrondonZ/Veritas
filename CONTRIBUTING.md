# Contributing to Veritas

## Setup

You need Python 3.11 or later and a Docker engine.

```text
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"
```

## Checks

Every change must pass all four. CI runs the same commands (`.github/workflows/ci.yml`).

```text
ruff format --check .
ruff check .
mypy
pytest                # unit tests; no Docker needed
pytest -m docker      # rebuilds the images from your working tree, then runs the escape suite and the lab lifecycle
```

The Phase 1 acceptance test (`tests/integration/test_assess_lab.py`) runs real assessments against the lab. It skips until a person has acknowledged the lab scope once with `veritas scope check labs/vuln-notes/veritas.scope.yaml`. Tests never acknowledge scopes or charters, approve probes, or approve specs in your workspace.

The Analyze unit tests run the JavaScript engine and the conformance harness with a local Node.js, and skip when `node` isn't on the PATH. If you change `labs/lexfmt/dist/lexfmt.js`, rerun `node labs/lexfmt/tools/make-samples.mjs` and update the subject's `sha256` in `labs/lexfmt/veritas.charter.yaml`. If you change anything in `labs/notes-desktop/app/`, rerun `node labs/notes-desktop/tools/pack.mjs` and put the `sha256` it prints into `labs/notes-desktop/veritas.charter.yaml`. The same goes for `labs/vuln-notes/tools/make-recording.mjs` and the recording's pin in `labs/vuln-notes/veritas.charter.yaml`. Credentials in a lab recording must be fake and start with `vrt-fake-`, so the leak test can find them. After changing `labs/native-samples/tools/make_samples.py`, rerun it and update the pins in that lab's charter; a unit test checks that the committed samples match the generator. `labs/notes-cli/tools/build.ps1` rebuilds the .NET tool with the compiler that ships with Windows. Every build gets a new hash, so update its pin too.

The Docker tests take several minutes. Run them before merging any change to `veritas.core`, `veritas.gateway`, `veritas.sandbox`, `veritas.environments`, `plugins/`, `labs/`, or `docker/`.

## Project rules

These rules come from docs/architecture.md, and several are enforced by `tests/unit/test_architecture.py`.

1. **No third-party services at run time.** Veritas contacts only in-scope targets. Don't add HTTP clients, cloud SDKs, or hosted-model APIs; the architecture test fails if you do. Anything downloaded at build time (base images, Python packages, model weights) must be pinned by digest or hash.
2. **Keep the gateway small.** `veritas.gateway` may import only `veritas.core`, pydantic, h11, and the standard library. `veritas.core` may import only the standard library and pydantic. The gateway image contains nothing else.
3. **Prove control failures, never impact.** Validators use inert markers and synthetic identities (§9.4). Don't add payloads that read files, run commands, extract data, persist, pivot, or degrade service. Test only against the bundled labs or systems you own.
4. **Keep the clean room clean.** Nothing derived from a subject reaches a clean-room context except the approved spec. Implementations are replicated from the spec and vectors, never copied, and license, DRM, or anti-tamper logic is excluded, never analyzed (§5.4).
5. **Stay lightweight.** Heavy pieces, such as the model server or large analysis engines, are opt-in. They must never join the default build or run.
6. **Fail closed, with named states.** Missing approval, an exhausted budget, a tool failure, or an ambiguous oracle each produce an explicit state, never a silent drop or an upgraded verdict.
7. **Evidence over assertion.** Report statements are typed claims that cite evidence. Oracles decide finding status, and models never do.

## Code style

- `ruff format` with a 120-character line limit. The lint rules in `pyproject.toml` include the security (`S`) rules. A `noqa` must name its rule and give a reason on the same line.
- Full type hints; mypy runs in strict mode against a Linux target.
- Docstrings and comments explain why the code is the way it is.
- New dependencies go in `pyproject.toml` and in `DECLARED` in `tests/unit/test_architecture.py`. Gateway dependencies also go in `docker/gateway/requirements.in`; then run `python scripts/lock_gateway_requirements.py` to refresh the hashed lock.

## Tests

- `tests/unit/` mirrors `src/veritas/`. Shared fixtures live in `tests/conftest.py`.
- Tests that need Docker carry `@pytest.mark.docker` and go in `tests/integration/`. The `images` fixture builds images from the current source once per session, so these tests never run stale images.
- Warnings are errors, so fix resource leaks instead of silencing them.

## Decisions

Record significant design decisions as ADRs in `docs/adr/`; the format is in [docs/adr/README.md](docs/adr/README.md). When an ADR changes the design, update `docs/architecture.md` in the same change.
