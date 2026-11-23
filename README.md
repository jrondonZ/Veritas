# Veritas

Veritas is a local-first platform that joins three steps:
1. **Assess:** validate the security of software you own or are authorized to test.
2. **Analyze:** reverse-engineer how it behaves, with evidence for every claim.
3. **Replicate:** reimplement that behavior clean-room, verified against conformance vectors and a similarity audit.

It works only in local, lab, or isolated staging environments, and it relies on no third-party service at run time.

**Status:** Phases 0 and 1 (foundations, deterministic Assess) are done. Phase 2 (sensors, the claim linter, local models) is partly implemented. Phase 3 is implemented for JavaScript, Electron, HAR recordings, .NET, and native binaries, along with code findings and the clean room. The design and phased plan are in [docs/architecture.md](docs/architecture.md), and decisions made since then are in [docs/adr/](docs/adr/).

## What works today

- **Scope files:** schema, validation rules, address pinning, a digest over the file and its references, and interactive acknowledgment (`veritas scope check`).
- **Egress gateway:** the only network path from a sandbox to a target. It verifies per-task capability tokens, enforces each task's envelope, pins addresses, refuses ambiguous requests, captures evidence, and revokes in-flight requests immediately.
- **Sandboxes:** hardened containers (read-only root filesystem, no capabilities, no DNS, internal networks only). A Docker escape suite proves they hold.
- **Evidence and audit:** a content-addressed evidence store and a hash-linked audit log (`veritas audit verify`).
- **Plugin protocol:** an MCP-compatible JSON-RPC subset over stdio, with handshake enforcement.
- **Assess:** `veritas assess run`.
  - Recon imports the OpenAPI document, crawls in-scope links, and adds routes from any HAR recordings the scope names, without replaying them.
  - Seventeen deterministic checks decide findings from gateway evidence. They cover object authorization, HTML and SQL injection, session cookies, CSRF, error disclosure, mass assignment, CORS, open redirects, missing security headers, path traversal, command injection, and server-side request forgery. Header checks judge only what recon already fetched, and the CORS and redirect probes use `.invalid` hosts, so nothing leaves the lab.
  - Probes that need approval are batched and shown with their exact requests.
- **Sensors:** network-less sensors read an owned app's own logs, so flaws are confirmed without sending attack input.
  - A query-log sensor confirms SQL built from input.
  - An activity-log sensor confirms input reaching a file path, a shell command line, or the host of an outbound request.
- **Reports:** terminal, JSON, Markdown, and SARIF output, with every claim linted: each is typed and every reference resolves.
  - `veritas replay` re-decides findings offline.
  - `veritas reproduce` re-validates one live.
  - `veritas export` and `veritas verify` handle self-verifying evidence bundles.
- **Analyze:** `veritas charter check`, then `veritas analyze run`.
  - A sandboxed JavaScript engine turns a subject into Program Model facts. It reads JavaScript files and Electron `.asar` archives.
  - A sandboxed binary engine reads compiled code without Ghidra. For PE, ELF, and Mach-O files it reports hardening, imports, exports, and strings. For .NET assemblies it reads the metadata and does a light IL scan.
  - HAR recordings become an endpoint catalog. Only names, types, and yes-or-no security facts are kept, and the raw recording is never stored, because it holds live credentials.
  - A mechanical behavior spec states what was observed, citing evidence.
  - Security rules find weaknesses as candidates:
    - **In code:** injection, unsafe sinks, weak cookies, crypto, and TLS settings, embedded secrets, and Electron window and page settings.
    - **In compiled code:** insecure deserialization, SQL and shell command lines built by joining strings, missing ASLR or DEP, writable and executable memory, unsafe library search paths, and dangerous imports.
    - **In recordings:** missing security headers, weak cookies, exposed stack traces, credentials in URLs, server banners, and CORS that trusts the `null` origin. Each candidate names the Assess check that confirms it live, where one exists. Findings go to `code-findings.json` and SARIF.
  - Bundled dependencies are inventoried in `sbom.cdx.json` (CycloneDX).
  - License-like logic is excluded and reported.
- **Spec gate and clean room:**
  - `veritas spec show` and `veritas spec approve` (a person types the run ID).
  - `veritas cleanroom verify` runs an implementation against the operator's vectors in a no-network sandbox and audits its similarity to the subject.
  - `veritas cleanroom draft` asks a local model to write one from the approved spec alone. It uses the `code` route, so a small coding model of about 1 GB can do this work.
- **Patch drafts:** `veritas patch draft <run> <finding>` asks the local model for a fix to one code finding in code you own. The kernel applies the edits to a copy and writes a diff. It re-reads the copy with the same rules: the copy must parse, the finding must be gone, and nothing new may appear. You review the diff and apply it yourself.
- **Local models (optional):** `veritas models add/list/route/eval/doctor`. Weights come from your local files only, and the model server runs in a container with no network. `veritas models eval` scores each registered model on cases with known answers and recommends one per route.
- **Local UI:** `veritas ui` opens a read-only view of the workspace in your browser:
  - every run, with its findings and claims;
  - specs and their approval state, code findings, clean-room results, and patch diffs;
  - each run's audit-chain status.

  It's served on 127.0.0.1 with every asset bundled, and it can't run or approve anything.
- **Labs:**
  - `labs/vuln-notes` is an intentionally vulnerable web app with planted flaws, look-alikes that must never be flagged, and a ground truth (`veritas lab up|reset|down`).
  - `labs/lexfmt` is an owned file-format library for Analyze, with conformance vectors and a ground-truth spec.
  - `labs/notes-desktop` is an intentionally vulnerable Electron app, packed as an `.asar` archive, for code findings. Veritas reads it and never runs it.
  - `labs/notes-cli` is an intentionally vulnerable .NET tool, compiled with the C# compiler that ships with Windows.
  - `labs/native-samples` holds six ELF, PE, and Mach-O files built byte by byte, each weak sample with a hardened twin. They contain no runnable code.

## Requirements

- Python 3.11 or later
- A Docker engine (Docker Desktop, Docker Engine, or a Podman-compatible API) for sandboxes and labs

## Quick start

```text
python -m venv .venv
.venv\Scripts\activate              # macOS/Linux: source .venv/bin/activate
pip install -e ".[dev]"

veritas images build                # small core images; add --models for the local model server (~800 MB)

# Assess: test what you own
veritas lab up vuln-notes
veritas scope check labs/vuln-notes/veritas.scope.yaml    # review the targets, then acknowledge
veritas assess run --scope labs/vuln-notes/veritas.scope.yaml
veritas show r-0001                 # or: veritas report r-0001 --format sarif
veritas lab down vuln-notes

# Analyze, then replicate clean-room
veritas charter check labs/lexfmt/veritas.charter.yaml    # review the subjects and purpose, then acknowledge
veritas analyze run --charter labs/lexfmt/veritas.charter.yaml
veritas spec show r-0002            # exactly what may cross into the clean room
veritas spec approve r-0002
veritas cleanroom verify r-0002 --impl path/to/your/implementation

# Find weaknesses in a packed desktop app's code
veritas charter check labs/notes-desktop/veritas.charter.yaml
veritas analyze run --charter labs/notes-desktop/veritas.charter.yaml

# See it all in the browser (read-only, on this machine)
veritas ui
```

Models are optional. To use them, download a GGUF file yourself and register it with `veritas models add <file>`; Veritas never downloads weights. A general 3-4B model (for example Qwen3-4B-Instruct) serves `analysis`. A small coding model (for example Qwen2.5-Coder-1.5B-Instruct, Apache-2.0, about 1.1 GB at Q4_K_M) can serve `code`:

```text
veritas models add path/to/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf --name coder-1.5b
veritas models route code coder-1.5b
veritas models eval                 # score the registered models here, then: veritas models eval --apply
```

## Repository layout

```text
src/veritas/
  core/           pure primitives shared with the gateway image: canonical JSON, impact classes,
                  network policy, capability tokens
  gateway/        the egress gateway (runs in its own container)
  scope/          scope schema, validation, address pinning, digest
  store/          workspace, audit chain, content-addressed blobs, capture ingest
  plugins/        plugin manifests, stdio JSON-RPC client, plugin host
  sandbox/        Docker runner, per-run sandbox, image build and lock
  environments/   lab and replica providers
  assess/         recon, checks and oracles, sensors, policy and approvals, the Assess pipeline
  analyze/        charters, intake, Program Model, behavior spec, spec gate, clean room
  findings/       findings, typed claims, the claim linter, CVSS
  models/         local model routing: weights, profiles, the model-call contract
  agents/         model roles: triage, analyst, reviewer, implementer, patcher
  evals/          the routing eval: which local model should serve each route
  imports/        operator-supplied recordings (HAR), read for their shape only
  ui/             the local read-only UI: a stdlib server and one page
  reports/        terminal, Markdown, and SARIF reporters
  cli/            the `veritas` command, one module per command group
  documents.py    safe loading of operator-authored YAML
plugins/          first-party plugins: manifest, Dockerfile, and code per plugin
labs/             bundled, intentionally vulnerable labs
docker/           first-party images that are not plugins (the gateway)
scripts/          maintenance scripts
tests/unit/       mirrors src/veritas; runs without Docker
tests/integration/  Docker-backed tests (pytest -m docker)
docs/             architecture and decision records
```

## Safety and acceptable use

Run Veritas only against systems you own or are authorized in writing to test. It refuses production environments and anything outside the declared scope, and it never demonstrates exploitation. See [SECURITY.md](SECURITY.md) for acceptable use and for how to report a vulnerability in Veritas itself.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the checks every change must pass, and the project rules.

## License

No license has been chosen yet. Until one is added, all rights are reserved.
