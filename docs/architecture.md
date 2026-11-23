# Veritas — Architecture Proposal

**Status:** 2026-11-20 · Phases 0 and 1 are implemented. Phase 2 is partly implemented. Phase 3 is implemented for JavaScript, Electron, HAR, .NET, and native binaries (without Ghidra); [§14](#14-phased-mvp) records what shipped and what moved. Later phases are proposals. Open questions are in [§17](#17-open-questions).

Veritas is a local-first, plugin-based platform with two modes over one kernel:

- **Assess** validates the security of applications the operator owns or has written permission to test. It runs only against local development environments, purpose-built labs, and isolated staging systems.
- **Analyze** documents the observable behavior of software the operator is authorized to inspect, separating evidence from inference, and produces a clean-room plan for an original, compatible implementation.

## 1. Decisions in brief

1. **One small trusted kernel.** Models and plugins are untrusted. They request actions; the kernel decides; sandboxes execute; an egress gateway enforces scope on the wire.
2. **Code confirms findings.** A finding is `confirmed` only when a deterministic oracle passes over evidence the gateway captured. Models explain, prioritize, and draft fixes. They never set a finding's status.
3. **Typed claims.** Every report statement is `observed`, `inferred`, `unknown`, `limitation`, or `guidance`, and cites evidence or other claims. The renderer rejects anything else.
4. **Narrow first.** Until Phase 4, Assess accepts only loopback, private-range, and lab-network targets, and Analyze is static-only. Scope widens only after tests prove the enforcement layers.
5. **Python kernel, polyglot plugins.** Plugins run out-of-process in containers and speak an MCP-compatible JSON-RPC subset. They can be written in any language, and existing MCP tool servers can be wrapped.
6. **No third-party services at run time.** Models run locally on the operator's hardware, and Veritas ships no adapter for hosted model APIs. Model weights, plugin images, and standards data are installed ahead of time and pinned by digest. With models switched off, the core pipeline still produces complete, confirmed findings. Models add labeling, tailored explanations, patch drafts, and behavior specs.

## 2. Design principles

| # | Principle | Consequence |
|---|---|---|
| P1 | Scope is enforced by infrastructure, not prompts | Network topology, gateway allowlists, and mounts are generated from the scope file. A model that "decides" to leave scope gets a refused connection. |
| P2 | Models propose, the kernel disposes | Model output is schema-validated data. It becomes an action only through the policy engine. No model output runs as code on the host. |
| P3 | Oracles are code | Status comes from deterministic oracles: a canary is present, an identity differential holds, a parser builds an element, a sensor records an event. |
| P4 | Prove the control failure, not the impact | Validators show that a control is missing, using inert markers and synthetic identities. They never demonstrate harm. |
| P5 | Every claim carries provenance | Observed claims cite evidence IDs. Inferred claims cite the claims they rest on and state confidence. |
| P6 | Fail closed, fail loud | Missing approval, exhausted budget, tool crash, model refusal, and ambiguous oracles each produce a named state. Nothing is silently dropped or upgraded. |
| P7 | Deterministic by default | Declarative workflows, digest-pinned plugins, content-addressed caches, stable ordering, offline replay. |
| P8 | Cheapest sufficient method | Rules before models, small models before large ones, cached results before new calls. |
| P9 | Self-contained | Veritas contacts only in-scope targets. Nothing is downloaded at run time, and every result can be reproduced without an external service. |

## 3. System overview

```text
TZ0 OPERATOR       veritas CLI · scope/charter files · TTY approvals · reports
                                     │
──────────────────────────────────B1─┼──────────────────────────────────────────────────────
                                     ▼
TZ1 KERNEL (TCB)   ┌────────────────────────────────────────────────────────────┐
                   │ scope · policy · approvals · budgets · workflow engine     │
                   │ capability broker · plugin registry · model router         │
                   │ evidence store (content-addressed) · audit chain           │
                   └───────┬────────────────────────────────┬───────────────────┘
                           │ prompts / JSON                 │ JSON-RPC + capability token
────────────────────────B2─┼─────────────────────────────B3─┼───────────────────────────────
                           ▼                                ▼
TZ2 MODELS         ┌────────────────────┐  TZ3 SANDBOXES ┌─────────────────────────────┐
(untrusted output) │ local model server │  (untrusted    │ one container per task:     │
                   │ no network egress  │   code)        │ recon · checks · validators │
                   └────────────────────┘                │ sensors · engines · patcher │
                                                         │ no host FS · no secrets     │
                                                         └──────┬───────────────┬──────┘
                                                                │ HTTP(S)       │ read-only
                                                                ▼               │ mounts
                                                         ┌────────────────┐     │
─────────────────────────────────────────────────────B4──┤ EGRESS GATEWAY ├─────┼───────────
                                                         │ (TCB)          │     │
                                                         └──────┬─────────┘     │
                                                                ▼               ▼
TZ4 TARGETS & ARTIFACTS (hostile)                   lab · local-dev · staging artifacts
```

Models and sandboxes are untrusted. The gateway belongs to the TCB and is the only network path from a sandbox to a target. Artifacts reach engine sandboxes only through read-only mounts. The sandbox runner and env providers are the only components with Docker API access, and both run inside the kernel.

| Component | Responsibility | Trust |
|---|---|---|
| CLI | commands; rendering with control characters stripped; TTY approvals | TCB |
| Scope service | parse and validate scope and charter files; resolve and pin addresses; compute digests | TCB |
| Policy engine | map each `ActionRequest` to allow, deny, or needs_approval, citing rule IDs | TCB |
| Approval broker | digest-bound, single-use, expiring approvals on the operator's TTY | TCB |
| Workflow engine | run declarative DAGs; bounded fan-out; retries; resume | TCB |
| Capability broker | mint per-task tokens; set sandbox mounts, network, and limits | TCB |
| Egress gateway | enforce envelopes on the wire; inject identities; capture evidence | TCB, own container |
| Model router | route tasks to local models; budgets; redaction; response cache | TCB; its outputs are not |
| Model server | llama.cpp-compatible inference server in its own container, no network egress | untrusted output |
| Evidence store | content-addressed blobs and SQLite index; redacted views | TCB |
| Audit chain | append-only, hash-linked event log | TCB |
| Plugin registry | manifests, lockfile digests, protocol checks | TCB |
| Env providers | lab lifecycle: up, seed, snapshot, reset, down | first-party, in the kernel |
| Plugins | recon, checks, validators, sensors, engines, patcher | untrusted, sandboxed |

| Command | Purpose |
|---|---|
| `veritas lab up/reset/down <lab>` | manage bundled labs |
| `veritas scope check <file>` | validate, resolve, digest, acknowledge |
| `veritas assess plan/run --scope <file>` | show the plan, or execute it |
| `veritas analyze run --charter <file>` | run the Analyze pipeline |
| `veritas approve <run> [A-id]` | review pending approvals |
| `veritas show <F-id or run>` | claims, evidence, reproduction steps |
| `veritas reproduce <F-id>` | live re-validation under the current scope and policy |
| `veritas replay <run>` | offline re-evaluation of oracles over recorded evidence |
| `veritas patch draft/show <F-id>` | patch proposals, never applied |
| `veritas report <run> --format json/sarif/md/html/junit` | outputs |
| `veritas audit verify <run>`, `veritas export/verify` | integrity checks, evidence bundles |
| `veritas stop/resume <run>` | kill switch; resume after an auto-pause |
| `veritas models add/list/doctor` | register local weight files by hash; check hardware and pick a profile |

## 4. Trust boundaries and threat model

### 4.1 Trust zones

| Zone | Contains | Treated as | Reason |
|---|---|---|---|
| TZ0 Operator | the person running Veritas, scope files, approvals | authority | the only source of authorization |
| TZ1 Kernel and gateway | first-party deterministic code | trusted (TCB) | small, tested, no dynamic code loading |
| TZ2 Models | local model server on the operator's machine | untrusted output | outputs are shaped by target-controlled text |
| TZ3 Sandboxes | plugins, third-party tools | untrusted code | third-party code processing hostile input |
| TZ4 Targets and artifacts | apps under test, binaries, bundles, HAR files | hostile | may try to exploit the toolchain or inject instructions |

### 4.2 Boundaries

| Boundary | What crosses it | Controls |
|---|---|---|
| B1 Operator ↔ kernel | scope and charter files, approvals, reports | Strict schemas. The scope digest and resolved addresses are shown and acknowledged. Approvals come only from the TTY, are bound to an action digest, and are single-use and expiring. Nothing a plugin or model writes counts as an approval. |
| B2 Kernel ↔ models | prompts out, JSON in | Out: redacted, token-bounded context with provenance labels, sent over loopback to a server with no network egress. In: structured-output schemas, reference integrity (every ID must resolve), and policy evaluation of any requested action. |
| B3 Kernel ↔ sandboxes | task arguments and a capability token in; results and files out | JSON-RPC over stdio only. Operations must match the manifest. Results are schema-validated. Files are ingested from a size-capped output directory. No Docker socket, host filesystem, credentials, or model access inside a sandbox. |
| B4 Sandboxes ↔ targets | network traffic, artifact reads | Gateway: default-deny allowlist, DNS pinning, per-hop redirect checks, envelope enforcement, identity injection, rate and volume limits, full capture. Artifacts are mounted read-only into sandboxes that have no network. |
| B5 Dirty room ↔ clean room (Analyze) | approved behavior specs only | Separate contexts and mounts; automated spec-gate filters plus human approval; every crossing recorded in the audit chain (§8.3). |

**Prompt injection.** Target responses, HTML comments, decompiled strings, and HAR files will contain text addressed to the model. Safety does not depend on the model ignoring it. Agents hold no tools that reach targets, scope, or policy. Anything an agent wants done becomes an `ActionRequest` that the policy engine evaluates against the scope. A denied agent request is logged as `policy.violation_attempt` and listed in the report as a possible injection signal.

### 4.3 Threats

| # | Threat | Primary control | Enforced at |
|---|---|---|---|
| T1 | Prompt injection in target data steers an agent | agents have no target-facing tools; every action passes policy; attempts are reported | B2, policy engine |
| T2 | Scope drift through redirects, DNS rebinding, absolute links, or CNAMEs to third parties | addresses pinned at scope check; every hop and resolved address re-checked; refusals audited | gateway |
| T3 | Hostile artifact exploits an analysis engine | engine sandboxes have no network, read-only input, seccomp, and limits; executing a subject requires the VM tier (Phase 4) | B3, B4 |
| T4 | Malicious or vulnerable plugin | digest-pinned lockfile, least-privilege tokens, no ambient credentials, quarantine after repeated violations | B3, gateway |
| T5 | Target data leaves the machine | no hosted model APIs; the model server binds to loopback with no egress; a LAN model server must be declared explicitly; redaction before prompt assembly | B2 |
| T6 | Service impact on shared staging | rate, concurrency, and volume caps; `mutate` needs a disposable environment or approval; auto-pause on anomalies | gateway, policy engine |
| T7 | Mis-scoping, such as a typo that points at a third party | MVP accepts only loopback, private, and lab addresses; resolved addresses shown for acknowledgment | scope service |
| T8 | Hallucinated or overstated findings | oracles set status; typed claims; reference integrity; reviewer pass on high and critical findings | kernel, reporters |
| T9 | Terminal or report injection from target-controlled strings | CLI strips control characters; HTML reports escape all evidence and ship a strict CSP with no inline script | CLI, reporters |
| T10 | Secrets or personal data in evidence | masking at capture, secret scanning, raw retention off outside labs, findings cite location and hash prefix only, discovered credentials never reused | gateway, evidence store |
| T11 | Approval fatigue | safe validators keep approvals rare; batch approvals capped by count and envelope; `sensitive` approvals require typing the approval ID | approval broker |
| T12 | Tampering with results | content-addressed evidence, hash-linked audit chain, signed run manifests (Phase 4) | evidence store, audit chain |

## 5. Scope and authorization

### 5.1 Assessment scope

```yaml
# labs/vuln-notes/veritas.scope.yaml
apiVersion: veritas/v1alpha1
kind: AssessmentScope
metadata:
  name: vuln-notes-lab
authorization:
  basis: owned                    # owned | written-permission
  reference: { file: README.md }  # or { id: SEC-1234 }; a file's contents are hashed into the digest
  window: { start: 2026-11-18T00:00:00Z, end: 2026-12-31T23:59:59Z }
environment:
  kind: disposable                # disposable | local-dev | staging   (production is rejected)
  provider: compose
  compose_file: compose.yaml      # relative paths resolve against this file's directory
  reset: snapshot                 # required before mutate can be auto-approved
targets:
  - id: web
    base_url: http://vuln-notes:8080
    addresses: [172.30.0.4]        # lab targets pin addresses; must match the compose file
    source: app                    # optional, mounted read-only: route-to-code mapping, patch drafts
    openapi: /openapi.json         # optional: an API description recon imports
    allow:
      paths: ["/", "/search", "/search2", "/api/**", "/static/**"]
      methods: [GET, HEAD, POST, PUT]
    deny:
      paths: ["/api/admin/**"]
    unsafe_get: ["/logout"]       # GETs here are treated as mutate
    limits: { rps: 10, concurrency: 4, max_requests: 5000 }
identities:                       # synthetic only; secrets by reference, never inline
  - id: alice
    kind: synthetic
    target: web
    login: { type: form, path: /api/login, username: alice@lab.test, username_field: email, password_field: password }
    secret: env:VRT_ALICE
    canary: vrt-seed-alice        # seeded into alice's records; authorization oracles look for it
  # bob is declared the same way
sensors:                          # disposable and local-dev compose environments only
  - id: queries
    kind: query-log               # the app's SQL statement log (ADR 0006)
    target: web
    volume: query-log             # declared in the compose file; the sensor mounts it read-only, with no network
policy:
  auto_approve: [observe, probe, mutate]   # mutate only because kind=disposable and reset is set
  models: on                               # off = rules-only run; finding status is unaffected
  prompt_redaction: on                     # may be turned off only for disposable labs
budgets: { wall_clock: 20m, model_tokens: 2000000 }
```

### 5.2 Validation rules

- Unknown keys are errors, and `apiVersion` is required.
- `environment.kind: production` is rejected. Veritas does not support production targets.
- Until Phase 4, every target must resolve only to loopback, RFC 1918 / IPv6 ULA, or a Veritas-managed lab network. Link-local addresses (including 169.254.169.254) are always rejected.
- Resolved addresses are shown, included in the digest, and pinned: the gateway connects only to them. Lab networks use fixed addresses, so digests stay stable across restarts.
- `mutate` can be auto-approved only for `disposable` environments with a `reset` method. `sensitive` is never auto-approved.
- Identities must be `kind: synthetic`. Secrets are references (`env:`, OS keychain), never values.
- The window is checked on every request. If it expires mid-run, the run pauses (`blocked: window_expired`).
- The scope digest is SHA-256 over the JCS (RFC 8785) canonical form of the parsed file, the hashes of referenced files, and the pinned address sets. A run is bound to one digest; any change starts a new run.
- The first use of a digest requires interactive acknowledgment of targets, addresses, limits, sensors, and auto-approved classes.
- A sensor must name a volume that the environment's compose file declares, and sensors are refused outside `disposable` and `local-dev` compose environments.

### 5.3 Analysis charter

```yaml
apiVersion: veritas/v1alpha1
kind: AnalysisCharter
metadata:
  name: lex-format-interop
subjects:
  - path: vendor/LegacyExporter/lexport.dll
    sha256: "<pinned digest>"
basis: interoperability     # owned | license-permits | interoperability | security-research
                            # | migration | accessibility | preservation | education
purpose: >
  Read and write .lex project files so our importer can open files customers created.
deliverables: [behavior-spec, clean-room-plan]   # an implementation is optional
constraints:
  execute_subject: false    # static only until the VM tier exists (Phase 4)
  network: none
  models: on                # local only; decompiler output never leaves the machine
```

Veritas records the stated basis and purpose but cannot verify them. Whether analysis is permitted depends on jurisdiction and license terms, and that judgment belongs to the operator. Clean-room separation (§8.3) is an engineering control against copying expression, not a legal determination.

### 5.4 Hard limits

No scope file, policy setting, plugin, or model output can change these:

1. No production environments, no targets outside the declared scope, and no third-party reconnaissance sources (search engines, certificate-transparency logs, passive DNS, internet-wide scan data).
2. No credentials other than declared synthetic identities. Discovered credentials are masked and never reused.
3. No validator that reads files, executes commands, extracts records beyond seeded canaries, persists, pivots, or degrades service (§9.4).
4. No analysis or modification of licensing, DRM, anti-tamper, or anti-debugging logic. Such code is identified only to exclude it, and the exclusion is reported as a limitation. Protection layers (packers, protectors, encrypted method bodies) are not unpacked.
5. No modified builds or binary patches of a subject. Subject assets (images, icons, fonts, UI text, branding) are inventoried by type, size, and hash only, never exported.
6. Patches are never applied automatically, and Veritas never commits or pushes.

The limits are structural. The registry has no impact class or plugin kind that expresses them, and the matching policy rules have no override.

## 6. Plugin architecture

### 6.1 Plugin kinds

| Kind | Purpose | Runs in | Max impact |
|---|---|---|---|
| `executor` | Send kernel-written request scripts through the gateway; return status codes and evidence IDs only | `tool` sandbox | set per script by its token |
| `recon` | Enumerate the in-scope surface: scope-bounded crawl, OpenAPI/GraphQL import, fingerprinting | `tool` sandbox | probe |
| `check` | Test one hypothesis against an observation; emit candidates | `tool` sandbox | probe, mutate |
| `validator` | Confirm one candidate with the least-impact demonstration; attach an oracle result | `tool` sandbox | probe, mutate, sensitive (approval) |
| `sensor` | Runtime signals from an owned app, such as its database query log | `engine` sandbox; lab or local-dev only | observe |
| `engine` | Wrap an analysis engine (Ghidra, IDA, ILSpy, JS parsers) and emit Program Model facts | `engine` sandbox | observe |
| `patcher` | Draft a fix and a regression test against a read-only copy of the operator's repo | `engine` sandbox | observe |
| `env` | Lab lifecycle: up, seed, snapshot, reset, down | kernel (first-party only) | n/a |
| `mapper`, `scorer`, `reporter` | Standards data packs, CVSS calculation, output formats | in-process (first-party, pure) | none |

Every `check` ships a default CVSS vector and a curated remediation template with standards references. Reports are therefore complete with models off; models only tailor those defaults to the evidence and the code.

### 6.2 Manifest

```yaml
# plugins/authz-differential/veritas-plugin.yaml
apiVersion: veritas/plugin/v1alpha1
id: veritas.check.authz-differential
version: 0.1.0
kind: check
runtime:
  image: veritas/check-authz@sha256:<digest>   # built locally from this repo; pinned in .veritas/veritas.lock
  command: ["python", "-m", "authz_differential"]
protocol: vpp/1                       # MCP-compatible subset (§6.3)
operations:
  - name: run
    impact: probe                     # ceiling for every request this operation sends
    input: schemas/route-with-identities.json
    output: [candidate]
capabilities:
  network: target-scope               # none | target-scope; hosts come from the token, never the plugin
  identities: declared                # named by id; the gateway injects sessions
  filesystem: { work: tmpfs, inputs: ro }
resources: { cpu: "0.5", memory: 256Mi, pids: 64, timeout: 120s, output_max: 16Mi }
determinism: deterministic            # deterministic | seeded | nondeterministic
defaults:
  cvss: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
  remediation: remediation/authz-object-level.md
standards: { cwe: [CWE-639], wstg: [WSTG-ATHZ-04] }
```

There is no `model` capability: plugins cannot call models.

### 6.3 Protocol

- **Transport.** JSON-RPC 2.0 over the sandboxed process's stdio, on a pinned revision of the open MCP protocol. The kernel is the client. No service is involved.
- **Allowed surface.** `initialize`, `tools/list`, `tools/call` with `outputSchema` / `structuredContent`, progress, logging, and cancellation. The kernel declares no client capabilities, so plugins cannot use sampling (call a model), elicitation (prompt the operator), or roots. Server `prompts` are ignored, so plugin text never becomes agent instructions.
- **Handshake check.** `tools/list` must match the manifest's operations and schemas exactly, or the plugin is refused.
- **Data plane.** Bulk output goes to `/out` (size-capped). Results reference files by relative path; the kernel hashes, secret-scans, and ingests them with provenance `plugin`.
- **Evidence integrity.** The gateway records every exchange and returns its evidence ID in a `Veritas-Evidence` response header, after stripping any upstream header with that name. Claims about target behavior may cite only gateway-issued IDs, so a plugin cannot fabricate a target interaction.
- **Lifecycle.** One container per task by default. Observe-only engines may be reused within a run (one Ghidra project per subject) under the same token scope.

### 6.4 Core interfaces

A sketch; names may change. Kernel types are pydantic v2 models, and their JSON Schema is exported for plugins written in other languages.

```python
from dataclasses import dataclass
from enum import StrEnum
from typing import Generic, Literal, Protocol, Sequence, TypeVar
from pydantic import BaseModel


class Impact(StrEnum):
    OBSERVE = "observe"  # no target traffic: static analysis, recorded data
    PROBE = "probe"  # read-only requests with inert inputs
    MUTATE = "mutate"  # changes target state; synthetic records only
    SENSITIVE = "sensitive"  # may expose secrets or personal data, or change access-control state
    # No member exists for destructive or out-of-scope actions, so they cannot be requested.


class ClaimKind(StrEnum):
    OBSERVED = "observed"  # requires evidence ids
    INFERRED = "inferred"  # requires based_on and confidence
    UNKNOWN = "unknown"  # explicitly not determined
    LIMITATION = "limitation"  # what the run could not do, and why
    GUIDANCE = "guidance"  # remediation advice, not a statement about the target


class Claim(BaseModel):
    id: str  # C-…
    kind: ClaimKind
    text: str
    evidence: list[str] = []  # E-…
    based_on: list[str] = []  # C-…
    confidence: float | None = None
    producer: str  # plugin@version, oracle@version, or role@model-digest


class Envelope(BaseModel):  # what a task may send; enforced by the gateway
    target: str  # target id from the scope, never a raw host
    methods: list[str]
    paths: list[str]  # globs inside the target's allow list
    identities: list[str] = []
    max_requests: int


class ActionRequest(BaseModel):
    plugin: str  # id@version+digest
    op: str
    args: dict  # validated against the operation's input schema
    impact: Impact
    envelope: Envelope | None
    rationale: str  # shown to approvers; never used for decisions
    origin: Literal["workflow", "agent"]


class Decision(BaseModel):
    verdict: Literal["allow", "deny", "needs_approval"]
    rules: list[str]  # e.g. ["mutate.requires_disposable"]


class OracleResult(BaseModel):
    verdict: Literal["pass", "fail", "ambiguous"]
    decisive: bool  # one pass is conclusive, e.g. another identity's canary
    reason: str
    evidence: list[str]


class Oracle(Protocol):
    """Pure function of captured evidence: no network, no model calls."""

    id: str
    version: str

    def evaluate(self, evidence: Sequence["Evidence"]) -> OracleResult: ...


Out = TypeVar("Out", bound=BaseModel)


@dataclass(frozen=True)
class AgentTask(Generic[Out]):
    role: str  # triage | planner | analyst | remediator | reviewer | …
    route: str  # routing-table key (§10.2)
    inputs: tuple[str, ...]  # artifact ids; the context builder renders them
    output: type[Out]  # compiled to a decoding grammar (§10.4)
```

Kernel-side host interfaces:

```python
class PluginHost(Protocol):
    async def start(self, ref: "PluginRef", token: "CapabilityToken", limits: "Limits") -> "PluginSession": ...


class PluginSession(Protocol):
    async def call(self, op: str, args: dict) -> "OpResult": ...  # schema-validated
    async def cancel(self) -> None: ...
    async def close(self) -> "TaskReport": ...  # exit status, resource usage, ingested files


class EnvProvider(Protocol):  # first-party only; runs in the kernel with Docker API access
    async def up(self, spec: "EnvSpec") -> "Env": ...  # fixed addresses keep digests stable
    async def seed(self, env: "Env", identities: list["Identity"]) -> "SeedReport": ...
    async def snapshot(self, env: "Env") -> str: ...
    async def reset(self, env: "Env", snapshot: str) -> None: ...
    async def down(self, env: "Env") -> "TeardownReport": ...  # verifies nothing is left behind


class ModelServer(Protocol):  # local inference only; no hosted-API implementation exists
    async def generate(
        self, model: "ModelRef", prompt: "Prompt", schema: dict, sampling: "Sampling"
    ) -> "Generation": ...
    async def tokenize(self, model: "ModelRef", text: str) -> list[int]: ...
```

Plugin SDK surface (`veritas_sdk`); plugins in other languages implement the same protocol:

```python
class Ctx(Protocol):
    task_id: str
    http: "GatewayClient"  # all traffic goes through the gateway; identities by id; returns E-ids
    inputs: "InputStore"  # read-only typed inputs and blobs
    out: "OutputDir"  # files written here are hashed and ingested when the task ends
    log: "Logger"

    def cancelled(self) -> bool: ...


@plugin("veritas.check.cookie-attributes", version="0.1.0")
class CookieAttributes:
    @op(impact=Impact.PROBE, input=Route, output=list[Candidate])
    async def run(self, ctx: Ctx, route: Route) -> list[Candidate]: ...
```

### 6.5 Capability tokens and envelopes

```json
{
  "tid": "t-0193", "run": "r-0007", "exp": "2026-11-18T14:20:00Z",
  "plugin": "veritas.validator.mass-assignment@0.1.0+sha256:91c4…",
  "impact_max": "sensitive", "approval": "A-0004",
  "net": [{ "target": "web", "methods": ["GET", "PUT"], "paths": ["/api/profile"],
            "identities": ["alice"], "max_requests": 4 }]
}
```

The kernel mints one token per task and signs it with HMAC-SHA256, using a per-run key that only the kernel and the gateway hold. The sandbox receives the token as proxy credentials. The gateway checks every request against `net`, counts against `max_requests`, and refuses after expiry or revocation. An approval (§9.3) runs nothing by itself. It authorizes the kernel to mint a token whose envelope matches exactly what the operator approved.

Identities never enter a sandbox. A plugin names an identity in a `Veritas-Identity` request header. The gateway strips the header, logs in with the kernel-held secret, and injects the session. Session values in responses are masked before the plugin sees them (§9.5).

### 6.6 Sandbox profiles

| Profile | Used by | Isolation | Network | Default limits |
|---|---|---|---|---|
| `pure` | mappers, scorers, reporters | in-process; first-party code only | none | — |
| `tool` | recon, checks, validators | rootless container, read-only root FS, all capabilities dropped, `no-new-privileges`, default seccomp, tmpfs `/work` | internal network to the gateway only | 0.5 CPU · 256 MiB · 64 PIDs · 120 s |
| `engine` | engines, sensors, patcher | as `tool`, inputs mounted read-only | none | 2 CPU · 4 GiB · 30 min |
| `model` | the model server | container with GPU passthrough where available; weights mounted read-only | loopback port to the kernel only | memory per hardware profile (§10.2) |
| `detonate` (Phase 4) | dynamic observation of subjects | VM: microVM on Linux, Windows Sandbox on Windows; reverted after use | none, or mock services | set by the charter |
| `host-tool` (opt-in) | licensed tools that cannot be containerized | host process under a restricted user, on a copy of the input | blocked by firewall rule (best effort) | flagged in the report as weaker isolation |

Docker or Podman is required. Without one, Veritas runs only offline commands (`report`, `replay`, `audit verify`) and refuses everything else. On Windows hosts the kernel runs natively and drives Docker Desktop (WSL 2 backend) or Podman through their APIs. gVisor is used for `tool` and `engine` when available on Linux.

### 6.7 Third-party MCP servers (Phase 4)

An existing local MCP tool server, such as a community Ghidra or IDA server, can be wrapped by a Veritas manifest that lists its allowed tools and assigns each an impact class. Tool annotations the server provides (`readOnlyHint`, `destructiveHint`) are ignored for policy because they are self-descriptions from untrusted code. Unlisted tools are not exposed. The server runs in a sandbox profile like any other plugin. Servers that call remote services are not eligible.

## 7. Data model

ID prefixes: `r-` run, `t-` task, `O-` observation, `E-` evidence, `C-` claim, `F-` finding, `A-` approval.

| Entity | Key fields |
|---|---|
| Run | mode, scope or charter digest, manifest (all versions and digests, including model weights), outcome |
| Task | stage, `plugin@digest` or `role@model-digest`, argument hash, token, state, resource usage |
| Evidence | SHA-256, media type, capture source (gateway, plugin, engine, sensor), redaction state, retention |
| Observation | kind (route, form, header, function, string, IPC channel, …), subject, data, evidence |
| Claim | kind, text, evidence, based-on claims, confidence, producer |
| Finding | fingerprint, status, reproducibility, severity, CVSS, CWE/WSTG/ASVS, affected components, claims, reproduction, patch |
| ActionRequest, Decision, Approval | §6.4 and §9.3 |
| BehaviorSpec | features, interfaces, claims, conformance vectors, version digest, gate result |

A finding exists from the moment a check emits a candidate. Its status then moves to one of the terminal states in §8.4.

```json
{
  "id": "F-0003",
  "fingerprint": "sha256:5e1f…",
  "title": "Missing object-level authorization: GET /api/notes/{id}",
  "status": "confirmed",
  "reproducibility": { "passed": 3, "attempts": 3 },
  "severity": "medium",
  "cvss": {
    "version": "3.1",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
    "score": 6.5,
    "source": "check-default",
    "rationale": { "PR": "C-0040", "C": "C-0041" }
  },
  "cwe": ["CWE-639"],
  "wstg": ["WSTG-ATHZ-04"],
  "affected": [
    { "kind": "route", "value": "GET /api/notes/{id}" },
    { "kind": "source", "value": "app/server.mjs:42", "via": "route-table" }
  ],
  "claims": [
    { "id": "C-0031", "kind": "observed", "evidence": ["E-0112"],
      "text": "As alice, GET /api/notes/7 (owned by bob) returned 200 with bob's canary." },
    { "id": "C-0032", "kind": "inferred", "based_on": ["C-0031", "C-0029"], "confidence": 0.9,
      "text": "Any authenticated user can read any note; note ids are sequential." },
    { "id": "C-0033", "kind": "unknown",
      "text": "DELETE on this route was not tested: method outside scope." },
    { "id": "C-0034", "kind": "guidance",
      "text": "Filter the note query by the session user id; return 404 for notes the user does not own." }
  ],
  "repro": "runs/r-0007/repro/F-0003.yaml",
  "patch": "runs/r-0007/patches/F-0003.diff"
}
```

## 8. Execution workflows

### 8.1 Assess

```text
 1 scope check → 2 env up → 3 recon → 4 plan → 5 gate ─┬─ allow ─────────▶ 6 checks
                                                       ├─ needs approval ▶ approval broker (TTY)
                                                       └─ deny ──────────▶ recorded, not run

 6 checks → 7 validate (gated again) → 8 reproduce → 9 enrich → 10 patch drafts (optional)
          → 11 report → 12 teardown
```

| # | Stage | Produces | Runs in | Model route | Max impact |
|---|---|---|---|---|---|
| 1 | Scope check | digest, pinned addresses, acknowledgment | kernel | — | — |
| 2 | Env up | running lab, identities seeded with canaries, snapshot | env provider | — | — |
| 3 | Recon | route templates, forms, auth boundaries, fingerprint | recon plugins | `triage` (labels, optional) | probe |
| 4 | Plan | tasks of (check, route, identities, envelope) | rule planner; a planner agent may add registry checks | `triage` (optional) | — |
| 5 | Gate | allow, needs approval, or deny per task | policy engine, approval broker | — | — |
| 6 | Checks | candidates with gateway evidence | check plugins | — | probe, mutate |
| 7 | Validate | oracle result per candidate; validators pass the gate again | validator plugins | `analysis` may propose one alternative validator | per validator |
| 8 | Reproduce | `k/N` passes from recorded request templates | kernel, validator | — | as stage 7 |
| 9 | Enrich | typed claims; check-default CVSS and remediation, optionally tailored | kernel templates; agents | `analysis` (optional); `deep` review for high and critical | observe |
| 10 | Patch drafts | diff, regression test, verification status | patcher | `analysis` | observe; lab re-validation is probe |
| 11 | Report | CLI, JSON, SARIF, Markdown, coverage matrix | reporters | — | — |
| 12 | Teardown | tokens revoked, sandboxes removed, lab reset verified, audit sealed | kernel, env provider | — | — |

Every model step is optional. With `models: off`, stages 3, 4, and 9 run on rules and templates, stage 10 is skipped, and finding status is identical. Recon never fetches third-party links; it records them as observations. Forms are submitted only by tasks that passed the gate.

### 8.2 Workflow definitions

Workflows are versioned data. The engine resolves them into a task DAG with stable IDs and runs it with bounded fan-out. Tasks are idempotent by key (stage, plugin digest, input hashes), so an interrupted run resumes with `veritas resume`.

```yaml
apiVersion: veritas/workflow/v1alpha1
name: assess.web.default
version: 1
stages:
  - { id: recon,     uses: [veritas.recon.crawler, veritas.recon.openapi] }
  - { id: label,     agent: { role: triage, route: triage }, optional: true }
  - { id: plan,      uses: veritas.planner.rules, agent: { role: planner, route: triage, proposals: registry-only }, optional_agent: true }
  - { id: gate,      policy: per-task }
  - { id: checks,    fan_out: plan.tasks, concurrency: 4 }
  - { id: validate,  fan_out: checks.candidates, dedupe: fingerprint, gate: true }
  - { id: reproduce, attempts: 3 }
  - { id: enrich,    uses: veritas.enrich.templates, agent: { role: analyst, route: analysis }, optional_agent: true }
  - { id: review,    agent: { role: reviewer, route: deep }, when: "severity >= high", fallback: claim-linter }
  - { id: report,    uses: [veritas.report.cli, veritas.report.json, veritas.report.sarif] }
```

### 8.3 Analyze

1. **Charter check.** Validate the charter, pin subject hashes, record basis and purpose, acknowledge.
2. **Intake.** Copy subjects into the evidence store, detect types, mount read-only.
3. **Static analysis.** Engines in network-less `engine` sandboxes emit Program Model facts. The Program Model is engine-independent: modules, functions, symbols with name provenance, imports and exports, strings with offsets, call edges, data structures, and a resource inventory (type, size, and hash only). For JavaScript it adds the module graph, network call sites, storage use, and IPC channels.
4. **Investigation.** Program-analyst agents read Program Model slices and may request further observe-only engine operations, in a bounded, budgeted loop.
5. **Specification.** The spec writer produces a behavior spec of typed claims. Every observed claim cites Program Model evidence.
6. **Spec gate (B5).** Automated filters, then human approval of one spec version.
7. **Clean-room plan.** Implementer agents, given only clean inputs, produce a plan and optionally an implementation with conformance tests.
8. **Verification.** Similarity audit; conformance tests against sample files and, from Phase 4, against the subject in a `detonate` sandbox when the charter allows execution.
9. **Report.** Behavior spec, evidence index, inferences, unknowns, limitations, plan, and the information-flow record.

With models off, Analyze still produces the Program Model fact inventory and a mechanical interface catalog (exported symbols, IPC channels, endpoints from HAR files, file-format reads). The behavior narrative, spec, and clean-room plan need the `analysis` route or better.

| Subject | Engine adapter | Facts extracted | Notes |
|---|---|---|---|
| Native PE, ELF, Mach-O | Ghidra `analyzeHeadless` with an export script; IDA through idalib (operator's license, Phase 4); Hopper if a headless mode proves workable | functions, symbols, imports and exports, strings with offsets, cross-references, call graph; decompiler output stays dirty-side | protection layers are not unpacked |
| .NET assemblies | metadata reader (dnfile); `ilspycmd` for decompilation (dirty-side) | types, members, attributes, P/Invoke surface, resource inventory, IL call graph | name obfuscation is tolerated; encrypted method bodies become limitations |
| JavaScript, web bundles | JS parser (Babel or acorn) or tree-sitter; source-map resolver | module graph, exported API, network call sites, storage use, feature flags | needs no native engine |
| Electron apps | asar reader plus the JavaScript pipeline | main, preload, and renderer split; `webPreferences`; IPC channel inventory; protocol handlers | — |
| Websites, documented APIs | HAR 1.2 import with auth values stripped; OpenAPI and GraphQL SDL | endpoint catalog, request and response shapes, auth scheme without values | Analyze sends no traffic; live capture of an owned site runs under an Assess scope |

A behavior spec fragment:

```yaml
feature: FEAT-03 Import a project file (.lex)
interfaces:
  - id: IF-lex-container
    kind: file-format
    claims:
      - { id: C-12, kind: observed, evidence: [E-0442], text: "Files begin with the 4-byte magic 4C 45 58 01." }
      - { id: C-13, kind: observed, evidence: [E-0450, E-0451], text: "A little-endian u32 section count follows the magic." }
      - { id: C-14, kind: inferred, based_on: [C-13], confidence: 0.8, text: "Sections are length-prefixed type-length-value records." }
      - { id: C-15, kind: unknown, text: "Meaning of bit 0x04 in the section-header flags." }
      - { id: C-16, kind: limitation, text: "Section type 0x7F not analyzed: handled by license logic, excluded by policy." }
conformance:
  - { claim: C-13, sample: samples/minimal.lex, expect: { section_count: 3 } }
```

The clean-room boundary:

```text
  DIRTY ROOM: subject access      ║ B5 ║  CLEAN ROOM: no subject access
                                  ║    ║
 subject (read-only, hashed)      ║    ║
   │                              ║    ║
   ▼                              ║    ║
 engines: sandboxed, no network   ║    ║
   │                              ║    ║
   ▼                              ║    ║
 Program Model: facts + E-ids     ║    ║
   │                              ║    ║
   ▼                              ║    ║
 analyst agents                   ║    ║
   │                              ║    ║
   ▼                              ║    ║
 spec draft (typed claims) ───▶ SPEC GATE ─▶ spec vN (approved, hashed)
                                  ║    ║      │
                                  ║    ║      ▼
                                  ║    ║     implementer agents
                                  ║    ║     inputs: spec vN, public docs,
                                  ║    ║     operator's own repo
                                  ║    ║      │
                                  ║    ║      ▼
                                  ║    ║     code + conformance tests
                                  ║    ║      │
 similarity audit ◀───────────────╫────╫──────┘
 results go to the operator only  ║    ║
```

Every filter must pass before a spec version crosses B5:

| Filter | Blocks |
|---|---|
| Expression similarity | spans whose token fingerprints (winnowing) match decompiled or extracted subject code above a threshold |
| Identifiers | internal names from the subject, unless on the interface allowlist (exported symbols, wire and file-format field names, documented API names) |
| Assets | embedded binary data, images, and UI strings beyond protocol constants and error codes |
| Secrets | any secret-scanner hit |
| Excluded logic | claims touching licensing, DRM, or anti-tamper code; each is replaced with a `limitation` claim |
| Human approval | the operator approves one spec version, bound to its digest |

Implementer tasks get tokens with no access to dirty evidence, and the context builder refuses any artifact tagged dirty. The audit chain records the hash of every input to every clean-room context, which shows exactly what the clean room saw. Operator-owned sample files may cross with a spec when the gate approves them. Similarity-audit results go to the operator and never back into a clean-room context. Because models are local and stateless between calls, nothing outside the recorded context can carry dirty material into a clean-room call.

### 8.4 States and outcomes

| Finding status | Meaning |
|---|---|
| `candidate` | emitted by a check, not yet validated |
| `confirmed` | the oracle passed. Reproducibility `k/N` is reported; below `N/N` only for decisive oracles, flagged `intermittent` |
| `rejected` | the oracle failed: the control is present |
| `inconclusive` | the oracle was ambiguous, a statistical oracle was inconsistent, or the impact cannot be shown within policy. The reason is recorded |
| `blocked` | validation did not run: approval required, scope, budget, window, or model declined |
| `error` | a tool failed; diagnostics attached |

Run outcomes: `completed` (every task terminal, no gaps), `completed_with_gaps` (some tasks blocked or failed, each gap listed with its cause), `aborted` (operator stop, unresolved auto-pause, window expiry, or kernel invariant violation), and `invalid` (scope or charter rejected, so nothing ran).

## 9. Safety controls

### 9.1 Impact classes and default policy

| Impact | Meaning | Disposable lab | Local dev | Isolated staging |
|---|---|---|---|---|
| `observe` | no target traffic | auto | auto | auto |
| `probe` | read-only requests with inert inputs | auto | auto | auto, rate-limited |
| `mutate` | changes synthetic target state | auto, reset at teardown | approval | approval |
| `sensitive` | may expose secrets or personal data, or change access-control state | approval | approval | approval |

Production is not an environment kind, so a scope that declares it is rejected. Destructive and out-of-scope actions have no impact class: no plugin can declare them and no agent can request them.

### 9.2 Prohibited outcomes

| Outcome | How Veritas prevents it |
|---|---|
| Access outside scope, lateral movement | gateway allowlist with pinned addresses; hosts found in target data are never added at run time |
| Data exfiltration | sandboxes reach only the gateway; evidence flows only to the local store; no hosted model APIs; the model server has no egress |
| Persistence | no validator writes files, schedules jobs, registers webhooks, or creates accounts; `mutate` is limited to synthetic records and undone by reset |
| Service disruption | per-target rate, concurrency, and volume caps; the registry has no load or resource-exhaustion checks; auto-pause |
| Credential misuse | the gateway injects only declared synthetic identities; plugins never see session values; discovered secrets are masked and never reused |
| Destructive changes | `DELETE` and `unsafe_get` routes are excluded unless explicitly allowed in a disposable environment |

### 9.3 Approvals

```text
APPROVAL A-0004 · run r-0007 · impact sensitive
  plugin   veritas.validator.mass-assignment@0.1.0 (sha256:91c4…)
  intent   check whether PUT /api/profile accepts a client-supplied "role" field
  traffic  ≤ 4 requests · PUT and GET /api/profile · identity alice · target web
  method   write a non-privileged sentinel value, read it back; no privilege change
  effect   changes alice's synthetic profile; lab reset from snapshot at teardown
  digest   sha256:7d2e… · expires 14:20Z · single use
Type A-0004 to approve, n to deny, d for request details:
```

- An approval is bound to the digest of the plugin digest, operation, arguments, envelope, and scope digest. It is single-use and expires (default 15 minutes).
- Approvals come only from the TTY. Files, plugin output, and model output cannot approve anything.
- `mutate` approvals take `y/N`. `sensitive` approvals require typing the approval ID.
- Pending actions with the same plugin, operation, and envelope pattern can be approved as a batch. The batch is shown as one aggregate envelope with a count cap.
- In `--ci` mode no approvals are possible. Those tasks end `blocked: approval_required`, and the run is `completed_with_gaps`.

### 9.4 Safe validation rules

1. Validators show that a control is absent: unencoded reflection, a missing owner check, a writable protected field, a string-built query. They do not show what an attacker could do with it.
2. Inputs come from a reviewed, versioned corpus: per-run canaries (`vrt-<run>-<n>`), metacharacter markers that are inert in every context they target, and synthetic records seeded with per-identity canaries. A corpus entry is accepted only with a test showing it is inert in each target context. Models choose corpus entries and fill typed parameters (which parameter, which identity pair). They do not write request content.
3. Each validator declares its oracle, request budget, and impact. Exceeding them is a gateway violation and fails the task.
4. Validation stops at the first decisive oracle result.
5. Validators never read files, run commands, enumerate or extract records beyond seeded canaries, chain findings, or escalate privileges. When proving a flaw would require one of these, the finding ends `inconclusive` with the claim "impact not demonstrated: outside validation policy".
6. Sensor oracles are preferred where the operator owns the app. A canary that appears inside SQL statement text in the lab's query log, rather than as a bound parameter, confirms a string-built query without sending any attack input.

### 9.5 Data handling

- The gateway masks credentials at capture: `Authorization`, `Cookie`, and `Set-Cookie` values plus token-shaped values. Cookie attributes are kept so cookie checks still work. Masked values get stable pseudonyms (`‹session:alice#2›`), so checks can see that a session changed without seeing its value.
- A secret scanner (patterns and entropy) runs on every ingested blob and produces a redacted view. Findings about exposed secrets give the type, the location, and a short hash prefix for rotation, never the value.
- Raw evidence is kept by default only for disposable environments (`retain_raw: false` elsewhere), with a per-run TTL and `veritas purge`.
- Model traffic never leaves the machine. The model server listens on loopback inside its own container and has no network egress. A model server elsewhere on the operator's LAN must be declared explicitly, and Veritas never connects to a hosted model API.
- Prompts are built from redacted views by default (`prompt_redaction: on`), which keeps secrets out of model caches and logs. Disposable labs may turn this off.

### 9.6 Kill switch and auto-pause

- `veritas stop <run>` or Ctrl-C revokes every token at the gateway, which cuts in-flight requests. The kernel then cancels plugin calls and stops sandboxes, and the run ends `aborted: operator`. Target: revocation within 1 second.
- Auto-pause triggers have defaults that can be tightened but not loosened: a 5xx rate above 5% over 30 seconds; p95 latency above 3× the recon baseline; a failing target health check; three policy violations from one plugin, which also quarantines that plugin; an exhausted budget or window. A paused run needs `veritas resume`.

## 10. Agents and local model routing

### 10.1 Roles

| Role | Route | Reads | Emits (schema-enforced) | Can request actions |
|---|---|---|---|---|
| triage | `triage` | route catalog, redacted responses | route labels, auth boundaries, sensitivity hints | no |
| planner | `triage` | labeled routes, registry index | task proposals that reference registry check IDs | yes, through the gate |
| analyst | `analysis` | one finding's evidence and claims | typed claims; CVSS metric adjustments with cited claims; CWE refinement | one alternative validator per ambiguous candidate |
| remediator | `analysis` | finding, read-only repo excerpts | tailored guidance, patch draft, regression test | test runs in its own sandbox (bounded loop) |
| reviewer | `deep` | finding and every cited evidence item | per-claim verdict: supported, unsupported, overstated | no |
| program analyst | `analysis` | Program Model slices (dirty) | observed and inferred facts | observe-only engine operations (bounded loop) |
| spec writer | `deep` | facts (dirty) | behavior spec draft | no |
| implementer | `analysis` | approved spec, public docs, operator's repo (clean) | plan, code, conformance tests | test runs in its own sandbox (bounded loop) |

The workflow engine schedules every agent task. Agents do not spawn agents or message each other. They exchange typed artifacts through the store, and every artifact carries provenance. Most invocations are single schema-constrained calls. The kernel hosts the bounded loops listed above, and each tool call in them is an `ActionRequest`.

### 10.2 Routes, models, and hardware profiles

| Route | Used for | Size class | Approx. weights at 4-bit | Examples available at the time of writing (license) |
|---|---|---|---|---|
| `rules` | everything a rule or template can decide | — | — | — |
| `triage` | labels, plan proposals, bulk summaries | 3–8B dense | 2–5 GB | Qwen3 4B or 8B (Apache-2.0); Phi-4-mini (MIT) |
| `analysis` | tailored claims and guidance, patch drafts, program analysis, implementation | 14–32B dense, or a mixture-of-experts model with few active parameters | 9–20 GB | Qwen3-30B-A3B (Apache-2.0); gpt-oss-20b (Apache-2.0); Mistral Small 3.x 24B (Apache-2.0) |
| `deep` | reviewer, spec writer, escalations | the largest model the hardware holds | 40 GB and up | gpt-oss-120b (Apache-2.0); 70B-class dense models |

| Profile | Example hardware | Default routing |
|---|---|---|
| `laptop` | 6 cores, 16 GB RAM, no usable GPU: the Phase 2 reference machine ([ADR 0007](adr/0007-reference-hardware.md)) | one 3–4B model for `triage` and `analysis`; `deep` aliased to it, so high and critical findings get the claim linter and a `limitation` claim |
| `cpu` | 8 cores, 32 GB RAM, no GPU | `triage` on a small model; `analysis` on a sparse mixture-of-experts model for small batches; `deep` aliased to `analysis` |
| `gpu-12` | 8–12 GB VRAM, 32 GB RAM | `triage` on the GPU; `analysis` with partial CPU offload; `deep` aliased to `analysis` |
| `gpu-24` | 24 GB VRAM, or 64 GB or more of unified memory | all three routes; `deep` on the largest model that fits |

- `veritas models doctor` measures memory and throughput and proposes a profile. Aliasing one route to another is explicit config, never automatic, and the report names the model that answered every task.
- Weights are registered from local files (`veritas models add <file>`) and pinned by SHA-256 in `.veritas/veritas.lock`, with license and quantization. Veritas never downloads weights. Permissively licensed weights (Apache-2.0, MIT) are preferred, and the license is recorded in every run manifest.
- The default runtime is llama.cpp's `llama-server` (GGUF weights; CPU, CUDA, Vulkan, or Metal backends) in the `model` sandbox profile. Ollama and vLLM fit behind the same adapter. Some native runtime installs contact their vendor for updates, so the containerized server with no egress is the strict-offline default.
- Models load on first use and unload after an idle timeout. The scheduler groups tasks by route, so a machine that can hold one model at a time loads each model once per stage rather than once per call.
- The model choices above are starting points. Phase 2 sets the defaults from an eval over the lab ground truth on the reference hardware (Q3, §17), measuring claim accuracy, time, and memory per finding.

### 10.3 Escalation

1. Constrained decoding (§10.4) makes malformed JSON impossible, but outputs can still fail semantic checks, such as an unresolved ID or an observed claim without evidence. A failed output is retried once with the errors appended. The next retry goes to the next configured route. A third failure ends the task with `error: model_output_invalid`.
2. An `escalate` field with a reason from a fixed enum (`insufficient_context`, `conflicting_evidence`, `complex_authorization_logic`) moves the task up one configured route, once.
3. High and critical findings get a `deep` review. If `deep` is aliased or absent, the mechanical claim linter runs alone, and the report adds a `limitation` claim saying that no deep review ran.
4. Inputs over a route's context budget are chunked deterministically, mapped at `triage`, and reduced at the original route. Nothing is silently truncated.
5. Budget exhaustion never triggers escalation or downgrade. The stage stops, and the remaining items end `blocked: budget`.

### 10.4 Model-call contract

- **Constrained decoding.** Every call carries the role's JSON Schema, which the server compiles into a decoding grammar, so every output parses and matches the schema. Servers support only a subset of JSON Schema, so CI compiles every role schema.
- **Reproducible mode (default).** Greedy decoding, a fixed seed, one sequence per server slot, and a pinned runtime build and weight digest. Output can still differ across hardware or builds. The response cache is therefore the replay mechanism, and any cache miss on a rerun is recorded as a nondeterminism source.
- **Prompt layout.** A frozen, versioned system prompt comes first, then stable reference context (registry index, standards excerpts, approved spec), then per-task data. The server reuses its KV cache for the shared prefix, so stable context is computed once per stage. Target-derived content appears only in user-role blocks, wrapped and labeled untrusted. This is defense in depth; the actual control is §4.2.
- **Reference integrity.** Every ID in an output (evidence, claim, route, check, identity) must resolve to an existing object. Unresolved IDs fail validation, so invented references are rejected mechanically.
- **Declines.** Every output schema includes `status: answered | cannot_answer` with a reason from a fixed enum. `cannot_answer` ends the task `blocked: model_declined:<reason>`, and the report lists it. The kernel never rewrites a declined request to get around it.
- **Accounting.** Context budgets use the model's own tokenizer through the server's tokenize endpoint. Every call's prompt hash, token counts, timings, and weight digest go into the audit chain.

### 10.5 Caching and deduplication

| Cache | Key | Applies to |
|---|---|---|
| Tool results | H(plugin digest, operation, canonical args, input blob hashes) | observe-only operations: parsing, decompilation, static analysis |
| Model responses | H(weight digest, runtime version, sampling settings, prompt template version, schema version, canonical input) | every route. A hit makes no model call, which makes reruns and CI deterministic |
| KV prefix reuse | shared prompt prefix inside the model server | tasks in the same stage |
| Target responses | — | never for validation, since target state changes; only `veritas replay` serves recorded exchanges |

- Observations are deduplicated by normalized route template (`/api/notes/{id}`) and parameter set.
- Candidates are fingerprinted by H(check, method, route template, parameter, sink context). Duplicates attach their evidence to the first.
- Findings with the same fingerprint across runs are matched by `veritas diff`: new, fixed, regressed, unchanged.

### 10.6 Concurrency and budgets

- A bounded worker pool (default 4), with a separate limit for heavy engines (default 1, at 4 GiB).
- Memory-aware scheduling counts engine and model memory together. It does not start a task that would force a loaded model out mid-stage, or the reverse.
- Per-target concurrency and rate come from the scope. Model concurrency equals server slots: 1 in reproducible mode, more in an opt-in throughput mode for bulk `triage` work.
- Bounded queues with backpressure between stages. Results merge in stable-ID order regardless of completion order.
- Per-run budgets cover wall clock and tokens, with per-stage allocations. There is no metered service, so there are no money budgets. `veritas run stats` reports tokens, cache hit rates, and time per stage.

## 11. Evidence, audit, and reproducibility

```text
.veritas/
  veritas.db                  SQLite (WAL): runs, tasks, observations, claims, findings, indexes
  objects/sha256/ab/<hash>    content-addressed blobs, redacted and raw variants
  runs/r-0007/
    manifest.json             scope digest, plugin and weight lock, workflow/policy/routing/pack versions
    audit.jsonl               hash-linked events
    findings.json  report.sarif  report.md
    repro/F-0003.yaml         minimal request sequence; identities by id, no tokens
  cache/                      tool and model caches (size-capped, LRU)
```

```json
{"seq":412,"ts":"2026-11-18T14:03:07.112Z","prev":"sha256:9a0c…","type":"policy.decision",
 "task":"t-0193","action":"sha256:7d2e…","verdict":"needs_approval",
 "rules":["sensitive.requires_approval"],"actor":"kernel"}
```

- Event types include `scope.ack`, `plugin.start` and `plugin.exit` (image digest, resource use), `gateway.request` (evidence ID, verdict), `policy.decision`, `approval.granted` and `approval.denied`, `model.call` (route, weight digest, prompt hash, tokens, cache hit, status), `oracle.result`, `finding.status`, and `run.outcome`.
- `veritas audit verify r-0007` recomputes the chain and fails at the first modified, deleted, or reordered entry. In Phase 4, the chain head and run manifest are signed with a local key (cosign key-pair mode or minisign). No online transparency log is involved.
- `veritas replay r-0007` re-runs every oracle and the report over recorded evidence, offline. A different verdict means nondeterminism in Veritas itself, which is a bug.
- `veritas reproduce F-0003` re-sends the minimal request sequence against the reset target under the current scope and policy. It is a new validation with new evidence.
- `veritas export r-0007 --redacted` writes a bundle with its manifest and hashes, and `veritas verify <bundle>` checks one.

## 12. Reporting and standards

### 12.1 Finding output

Every finding carries its ID and fingerprint; title; status and reproducibility; severity (derived from the CVSS score); CVSS vector, score, source (check default or model-adjusted), and per-metric rationale; CWE, WSTG, and ASVS references; affected components (route template, plus source location and mapping method when a repo is mounted); typed claims; reproduction steps, both human-readable and as `repro/*.yaml`; guidance; and a patch reference. The CLI prints these as fixed fields without prose. `veritas show` gives the narrative. §13 shows the format.

### 12.2 Formats and CI

- `json` is the canonical, versioned schema, and every other format derives from it.
- `sarif` follows SARIF 2.1.0. Source-mapped findings use physical locations, which code-scanning tools display. Web findings carry `webRequest` and `webResponse`.
- `md` and `html` are for people. HTML escapes all evidence and ships a strict CSP with no inline script.
- `junit` feeds CI dashboards.
- Every report includes a WSTG coverage matrix that marks each test ID as executed, blocked, not applicable, or not covered by any plugin.
- `veritas assess run --ci --fail-on high` exit codes: `0` completed with no findings at or above the threshold; `1` findings at or above the threshold; `2` completed with gaps beyond `--max-gaps`; `3` aborted; `4` invalid configuration.

### 12.3 Standards mapping

All mapping data is vendored in the repo as versioned packs. Nothing is fetched at run time.

| Standard | Granularity | Source | Rule |
|---|---|---|---|
| CWE | per finding | check manifest; a validator may refine it to a child CWE | pinned CWE list version |
| OWASP WSTG | per check, plus the coverage matrix | check manifest | gaps are reported, not hidden |
| OWASP ASVS | per requirement | versioned crosswalk pack (for example 5.0.0) with version-prefixed IDs | dynamic testing reports "violated" or "no violation observed by N checks", never "passed" |
| CVSS 3.1 and 4.0 | per finding | deterministic calculator, tested against FIRST's published examples | the check supplies default metrics; a model may propose adjustments with cited claims; the calculator computes the score; operator overrides are audited |
| NIST SSDF (SP 800-218) | per run | run manifest | records evidence for PW.8 (test executable code), RV.1–RV.3 (identify, remediate, find root causes), and PO.4 (check criteria via `--fail-on`) |
| Compliance frameworks | per control | opt-in crosswalk packs with cited sources | "evidence relevant to control X", never a statement of compliance |

### 12.4 Patch proposals

- **Input.** A finding, plus the operator's repo mounted read-only into an `engine` sandbox with a copy-on-write work tree.
- **Output.** A unified diff, a regression test that encodes the oracle (for example, "alice cannot read bob's note"), and rationale claims.
- **Verification.** The patch is applied to the copy and the configured test command runs. For lab targets, the lab image is also rebuilt with the patch and the finding's validator re-runs; the expected result is `rejected`. Patch status is `verified`, `tests_failed`, or `not_verifiable` with a reason.
- **Never.** Veritas does not write to the real repo, run git, commit, or open pull requests. The operator applies a patch with `git apply`.

## 13. Demonstration: `labs/vuln-notes`

`labs/vuln-notes` is a small, intentionally vulnerable notes app that ships with Veritas. It uses only Node.js built-ins (`http` and `node:sqlite`), so its image needs no npm packages. It serves as the demo, the regression suite, and the routing-eval corpus.

- It runs only on a Veritas-managed internal Docker network and is not published on host interfaces. `veritas lab open` exposes it on 127.0.0.1 for manual inspection.
- Seeding creates synthetic identities (alice, bob) whose notes contain per-identity canaries.
- `expected-findings.yaml` is the ground truth. CI fails on any deviation in either direction.
- The README and the startup banner mark the app as intentionally vulnerable.

| # | Planted behavior | CWE | WSTG | Oracle (no attack payloads) | Expected status | Negative control |
|---|---|---|---|---|---|---|
| L1 | `GET /api/notes/{id}` has no owner check | CWE-639 | ATHZ-04 | alice's response contains bob's canary | confirmed | `/api/v2/notes/{id}` enforces ownership |
| L2 | `/search` reflects `q` unencoded | CWE-79 | INPV-01 | a WHATWG HTML parser builds an element node from an inert marker | confirmed | `/search2` encodes output |
| L3 | Session cookie lacks `HttpOnly` and `SameSite` | CWE-1004, CWE-1275 | SESS-02 | attributes of the masked `Set-Cookie` | confirmed | — |
| L4 | Stack trace on malformed JSON | CWE-209 | ERRH-01 | stack-frame signature in the body | confirmed | `/api/v2/*` returns a generic error |
| L5 | `PUT /api/profile` accepts `role` | CWE-915 | — | a non-privileged sentinel is written and read back (`sensitive`) | blocked, then confirmed after approval | — |
| L6 | `POST /api/notes` has no CSRF defense | CWE-352 | SESS-05 | accepted with no token and a cross-site `Origin` under `.invalid` | confirmed | — |
| L7 | Search query built by string concatenation (Phase 2) | CWE-89 | INPV-05 | sensor: the canary appears inside SQL statement text, not as a bound parameter | confirmed | `/api/v2/search` binds parameters |
| L8 | `POST /api/import` returns 500 with input-dependent bodies and no error signature | — | ERRH-01 | the error-disclosure oracle is ambiguous | inconclusive | — |

Negative controls must never yield a confirmed finding. L8 proves that Veritas reports ambiguity instead of guessing, and L5 exercises the approval path.

Walkthrough (illustrative output; IDs, counts, and timings are placeholders):

```text
$ veritas lab up vuln-notes
lab      vuln-notes · network vrt-lab (internal, 172.30.0.0/24) · 2 identities seeded · snapshot s-01

$ veritas scope check labs/vuln-notes/veritas.scope.yaml
scope    vuln-notes-lab · sha256:4be1…c09 · window until 2026-12-31
target   web  http://vuln-notes:8080 → 172.30.0.4 (lab network) · GET HEAD POST PUT · 10 rps
auto     observe probe mutate (disposable, reset: snapshot) · approval required: sensitive
Acknowledge this scope? [y/N] y

$ veritas assess run --scope labs/vuln-notes/veritas.scope.yaml
run      r-0007 · scope sha256:4be1…c09 · lock sha256:0d3a…71e · env disposable · profile gpu-24
recon    21 routes · 2 auth levels · 2 identities · 2 redirects refused (out of scope)
plan     31 tasks · 30 auto-approved · 1 awaiting approval (A-0004, sensitive)
checks   31/31 done · 9 candidates · 0 errors
verify   6 confirmed · 1 rejected · 1 inconclusive · 1 blocked

MEDIUM  F-0003  Missing object-level authorization: GET /api/notes/{id}       confirmed 3/3
        CWE-639 · WSTG-ATHZ-04 · CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N 6.5
        where     app/server.mjs:42 (route table)
        observed  as alice, GET /api/notes/7 (owned by bob) → 200 with bob's canary   E-0112
        inferred  any user can read any note; ids are sequential          ← C-0031 C-0029
        unknown   DELETE on this route: not tested, method outside scope
        repro     1. as bob:   GET /api/notes     → note 7 belongs to bob
                  2. as alice: GET /api/notes/7   → expected 403/404; got 200 with bob's canary
        fix       filter the note query by session user id; return 404 for notes not owned
        next      veritas show F-0003 · veritas reproduce F-0003 · veritas patch draft F-0003

MEDIUM  F-0005  Reflected HTML injection: GET /search?q=                        confirmed 3/3
        CWE-79 · WSTG-INPV-01 · CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N 6.1
        where     app/server.mjs:88 (search page)
        observed  inert marker reflected unencoded; parsed as an element node        E-0201
        observed  no Content-Security-Policy header on the response                 E-0201
        inferred  script execution likely; not demonstrated              ← C-0052 C-0053
        fix       HTML-encode q before writing it into the page; add a restrictive CSP

—       F-0019  Error disclosure: POST /api/import                              inconclusive
        reason    500 bodies vary with input but match no error signature
—       F-0022  Client-controlled role field: PUT /api/profile                  blocked
        reason    sensitive; awaiting approval → veritas approve r-0007 A-0004

+4 confirmed · veritas show r-0007 --all
outcome  completed_with_gaps (1 blocked)
models   local · 57 calls · 188k tokens · cache hit 0% (cold) · total 4m05s

$ veritas approve r-0007
(approval prompt as in §9.3) … A-0004
F-0022  Client-controlled role field: PUT /api/profile                    confirmed 3/3
outcome  completed

$ veritas patch draft F-0003
patch    F-0003 · 1 file changed · regression test added · tests pass · re-validation: rejected → verified
         review: veritas patch show F-0003 · apply it yourself: git apply runs/r-0007/patches/F-0003.diff

$ veritas lab down vuln-notes
lab      removed 3 containers, 2 networks, 1 volume · nothing left behind
```

The same run with `models: off` yields identical statuses, fingerprints, CVSS scores (the check defaults), and template guidance. It loses the tailored `fix` lines, the model-written inferred claims, and the patch drafts.

## 14. Phased MVP

Each phase ships something usable and ends at measurable exit criteria. A phase starts only after the previous phase's criteria hold.

### Phase 0: Foundations (no checks, no models)

- Kernel: run lifecycle, SQLite and content-addressed store, hash-linked audit chain, `veritas audit verify`.
- Scope schema v1alpha1 and validator (loopback, private, and lab addresses only), digest, acknowledgment, window.
- Sandbox runner with the `tool` and `engine` profiles, limits, and internal networks.
- Egress gateway: allowlist, DNS pinning, redirect checks, envelopes, tokens, identity injection, capture, rate limits, revocation.
- Plugin host: manifests, lockfile, JSON-RPC over stdio, schema validation. Plugin images are built locally.
- `labs/vuln-notes` skeleton: compose stack, seeding, snapshot and reset, ground-truth file.

Exit criteria:

- An escape suite of hostile test plugins produces zero escapes, and every attempt is audited. The suite covers direct IPs, other hostnames, DNS rebinding, out-of-scope redirects, raw TCP, IPv6 literals, envelope overruns, and forged evidence headers.
- `audit verify` detects any single modified, deleted, or reordered entry.
- Token revocation cuts in-flight requests within 1 second.
- `lab up`, `reset`, `down` leaves no containers, networks, or volumes behind.

**Status (2026-11-18): done.** All four exit criteria pass: `pytest -m docker` runs the escape suite and the lab lifecycle, and the rest of the suite runs without Docker. The implementation differs from the proposal in these ways:

- **Gateway.** An in-house asyncio proxy on h11 replaced mitmproxy (§15). It speaks HTTP only, refuses https targets and `CONNECT` until TLS interception lands, and refuses requests that carry both `Content-Length` and `Transfer-Encoding` ([ADR 0002](adr/0002-in-house-gateway-proxy.md)).
- **Control channel.** The kernel keeps one `docker exec` relay open per run, because a fresh `docker exec` took about 3.6 s on the development host. Revocation then took 16 ms end to end and cut the in-flight request at once ([ADR 0003](adr/0003-gateway-control-relay.md)).
- **Layout.** Packages follow the trust boundaries. The gateway image ships only `veritas.core` and `veritas.gateway`, with hash-pinned dependencies, and a test enforces the import rules ([ADR 0004](adr/0004-package-layout-and-layering.md)).
- **Models.** Models run locally only ([ADR 0001](adr/0001-local-models-only.md)).
- **Identities.** The gateway already enforces which identities a task may name. Logging in, injecting sessions, and masking session cookies toward plugins moved to Phase 1, where the lab gains a login route.
- **Evidence IDs.** Evidence IDs are content-derived (`E-` plus 12 hex digits of SHA-256), so the kernel can re-check every capture on ingest.
- **Lockfile.** Locally built image IDs differ per machine, so the lockfile lives in the ignored workspace (`.veritas/veritas.lock`).

### Phase 1: Assess MVP, deterministic (no models)

- HTTP(S) targets. Recon: scope-bounded crawler, OpenAPI import, route templating.
- Checks, validators, oracles, CVSS defaults, and remediation templates for L1–L6 and L8; reproduction; fingerprints; deduplication.
- Policy engine, impact classes, TTY approval broker, batch approvals, `--ci` behavior.
- Reports: CLI, JSON, SARIF 2.1.0, Markdown, WSTG coverage matrix, exit codes.
- `reproduce`, `replay`, `export`, `verify`.

Exit criteria:

- Every lab item reaches its expected status, and negative controls yield zero confirmed findings.
- Three consecutive runs produce identical findings and fingerprints.
- Gateway logs show zero requests outside approved envelopes.
- A packet capture during a full lab run shows no traffic to anything except the lab network and loopback.
- A full lab run takes under 5 minutes on a 4-core laptop.

**Status (2026-11-19): implemented; the exit criteria pass on the lab.** `tests/integration/test_assess_lab.py` runs three CI-mode assessments:
- In each run, every lab item reached its expected status and no negative control was confirmed.
- The three runs produced identical findings and fingerprints.
- The envelope audit found no request outside a declared script.
- Each run took 153–183 s.

The test runs only after a person acknowledges the lab scope in a terminal, and it never acknowledges or approves anything itself. The implementation differs from the plan in these ways:

- **Checks.** First-party checks are kernel recipes. One sandboxed executor sends each script through the gateway, under a token scoped to exactly that script, and the kernel decides every verdict from captured evidence ([ADR 0005](adr/0005-kernel-checks-and-executor.md)).
- **Identities.** The gateway signs each identity in and injects its session. Plugins only see masked cookie values.
- **HTTP only.** https targets wait for TLS interception ([ADR 0002](adr/0002-in-house-gateway-proxy.md)).
- **No packet capture yet.** That criterion is checked structurally for now:
  - Every run network is internal.
  - The escape suite proves sandboxes can't route out.
  - The envelope audit proves every allowed request belonged to a declared script.
- **Approvals.** Nobody can approve in CI mode, so L5 ends `blocked` there. Confirming it takes an interactive approval at the terminal.

### Phase 2: Local models, remediation, sensors

- Model router: routes, hardware profiles, the `model` sandbox profile, budgets, redaction, response cache, prompt layout, decline handling. llama.cpp adapter first; Ollama and vLLM adapters if needed.
- `veritas models add/list/doctor`.
- Roles: triage, planner, analyst, remediator, reviewer; claim linter and reference-integrity checks.
- Patch drafts with sandboxed tests and lab re-validation.
- The `sensor` plugin kind, the lab query-log sensor, and L7.
- Routing eval over the lab ground truth for each hardware profile.

Exit criteria:

- Every report claim is typed and every reference resolves. No unsupported claim survives the reviewer or the claim linter.
- Patch drafts for L1, L2, L4, and L7 reach `verified`, meaning re-validation returns `rejected`.
- With models on, a lab run on the reference profile (Q3) finishes within 15 minutes. A warm rerun makes zero model calls. With models off, results match Phase 1 exactly.
- The model server container cannot open any outbound connection, verified by test.
- Each profile's default routing table is set from documented eval results.

**Status (2026-11-19): partly implemented; unit-tested, not yet run against Docker or a real model.**

Implemented:
- **Sensors:** the `sensor` kind, the query-log sensor, L7 and N4 ([ADR 0006](adr/0006-sensors-and-sensor-evidence.md)).
- **Claim linter:** runs on every report and every bundle.
- **Model sandbox and relay:** [ADR 0008](adr/0008-model-sandbox-and-relay.md).
- **Model layer:**
  - `veritas models add/list/route/remove/doctor`;
  - the `laptop` profile ([ADR 0007](adr/0007-reference-hardware.md));
  - the call contract: cache, budgets, redaction, retries and escalation, declines and audit;
  - the triage, analyst, reviewer and implementer roles.

Lightweight by default: the model image is built only by `veritas images build --models`, and model steps run only once weights are registered.

**Status (2026-11-21): the remaining pieces are implemented ([ADR 0015](adr/0015-code-route-patches-eval.md)).**
- **The `code` route:** a small coding model can serve clean-room implementations and patches; otherwise `analysis` serves them.
- **Patch drafts:** `veritas patch draft` asks the local model for a fix. The kernel applies it to a copy and re-reads that copy with the same engine and rules: it must parse, the finding must be gone, and nothing new may appear.
- **The routing eval:** `veritas models eval` scores each registered model on cases with known answers and recommends one model per route.
- **Docker-backed tests:** a no-egress test on a running model, and the models-on acceptance run. Both are written and wait for the operator to register weights.

The planner role is deferred until Phase 4 brings third-party checks. Until then it could only propose probes that the rule planner already plans.

### Phase 3: Analyze MVP, static

- Charter schema; artifact intake with hashing, type detection, and read-only mounts.
- Engines: JavaScript and Electron (parser, source maps, asar, IPC inventory), .NET (metadata, IL), Ghidra headless; Program Model.
- Behavior spec with typed claims, spec gate, clean-room isolation, similarity audit, conformance harness.
- Owned demo subject `labs/lexfmt`: a reader and writer for a toy container format, built as a native binary, a .NET assembly, and a JavaScript bundle, with a ground-truth spec.

Exit criteria:

- Observed facts match the ground truth with at least 95% precision, and no ground-truth unknown is asserted as observed.
- The clean-room implementation passes at least 90% of conformance vectors, with similarity below the threshold.
- The audit chain shows no dirty artifact in any clean-room context.

**Status (2026-11-19): the JavaScript slice is implemented and unit-tested end to end ([ADR 0009](adr/0009-analyze-mvp.md)).**

The full chain runs without models: charter, intake, the sandboxed JavaScript engine (vendored acorn), the Program Model, a mechanical behavior spec, the spec gate, a person's approval, and the clean room. The clean room covers `cleanroom verify` with the conformance harness and the similarity audit, and `cleanroom draft` with the implementer model.

| Check on `labs/lexfmt` | Result |
|---|---|
| Spec precision against the ground truth | 1.000 (24 claims) |
| Recall | 1.000 |
| `never_observed` patterns asserted | none |
| License logic | excluded and reported as a limitation |

The clean room:
- refuses the subject, even under another name;
- flags a renamed or byte-altered copy through the similarity audit;
- verifies an independent implementation, 12 of 12 vectors.

**Status (2026-11-20): weaknesses in code, and Electron archives ([ADR 0010](adr/0010-code-findings-and-archives.md)).**

Analyze also finds security weaknesses in the code it reads, as candidates. Each one names the Assess check that can confirm it live, where one exists. Reports list what static rules don't cover. The engine reads `.asar` archives member by member. It analyzes the app's own code and pages, inventories bundled dependencies into `sbom.cdx.json`, and states what it left out.

HAR recordings are read for their shape only and never stored raw ([ADR 0011](adr/0011-har-recordings.md)). In Analyze, a recording gives an endpoint catalog, which becomes the spec's "HTTP endpoints" interface, and passive candidates from the app's own responses. In Assess, a target's `recordings` add in-scope routes that recon didn't otherwise find. They're never replayed.

| Ground truth | Candidates | Precision | Recall | Look-alikes flagged |
|---|---|---|---|---|
| `labs/vuln-notes` (web app source and a recorded session) | 9 | 1.000 | 1.000 | none of 6 |
| `labs/notes-desktop` (packed Electron app) | 10 | 1.000 | 1.000 | none of 7 |

**Status (2026-11-20): compiled code ([ADR 0014](adr/0014-binary-engine.md)).** A stdlib binary engine reads PE, ELF, and Mach-O files. It covers their hardening, imports, exports, and strings, and for .NET, the metadata plus a light IL scan. It adds no download, and Ghidra stays opt-in.

| Ground truth | Candidates | Precision | Recall | Look-alikes flagged |
|---|---|---|---|---|
| `labs/notes-cli` (compiled .NET tool) | 5 | 1.000 | 1.000 | none of 5 |
| `labs/native-samples` (ELF, PE, Mach-O) | 16 | 1.000 | 1.000 | none of 3 hardened twins |

Deferred, to stay lightweight:
- **lexfmt builds:** the native and .NET builds.
- **Engines:** Ghidra, opt-in, for decompilation and native data flow.
- **Dependencies:** matching the inventory against advisories, which needs a local advisory source.

Still to do:
- **Live runs:** the Docker run of the pipeline and the operator's charter acknowledgment.
- **Exit criterion 2:** a model-written clean-room implementation, which needs registered weights.

### Local UI (after Phase 3)

A clean, local interface for runs, findings, specs, and clean-room results. It is served on loopback with every asset bundled, so no CDN and no web font are fetched. It shows the same documents the CLI writes, with approvals still made by a person at a terminal or an equivalent explicit step. The design is deliberate and dense with real data, not template-driven.

**Status (2026-11-21): implemented, read-only ([ADR 0016](adr/0016-local-ui.md)).** `veritas ui` serves one page, one script, and one stylesheet with the standard library. The page shows:
- the workspace: runs, the three pipeline stages, local models and routes, and labs;
- each run: findings with their claims, the behavior spec and whether it's approved, code findings, clean-room results, and patch-draft diffs;
- the audit chain's verification status, on every view.

It binds 127.0.0.1 and needs the token printed at start. It checks the Host header, answers only GET, and renders every value as text.

### Phase 4: Breadth and hardening

- Browser target adapter (Playwright with a pinned, locally installed browser) and client-side checks; GraphQL and gRPC adapters.
- MCP bridge for local third-party tool servers.
- Plugins and run manifests signed with local keys; SBOMs for plugin images.
- `detonate` tier for dynamic observation in Analyze: microVMs on Linux, Windows Sandbox on Windows.
- IDA adapter through idalib; a Hopper adapter if a headless mode proves workable.
- Staging targets outside private ranges, gated by `written-permission` authorization.
- Compliance crosswalk packs; `veritas diff` across runs.

**Status (2026-11-20): seven more Assess checks ([ADR 0012](adr/0012-header-cors-redirect-checks.md)).**

| Check | How it decides | Lab items | Look-alikes |
|---|---|---|---|
| `csp`, `framing` | Passive. Each HTML page recon fetched is judged on its recorded response. | H1 to H4 | N7, N8 |
| `content-type-options`, `server-banner` | Passive. The site's first recorded response is judged. | H5, H6 | |
| `hsts` | Passive, on https targets only. | | |
| `cors` | A signed-in GET with an Origin under `.invalid`, then `Origin: null`. | L10 | N6 |
| `open-redirect` | A destination parameter is given a URL under `.invalid`, and only the Location header is read. | L9 | N5 |

Analyze's candidates now name these checks in `confirms_with`, so a weakness found in code or in a recording points to the live check that settles it. The new checks are unit-tested; the lab's acceptance run with them is still to come.

**Status (2026-11-20): three sensor checks ([ADR 0013](adr/0013-activity-sensor-checks.md)).** An activity-log sensor reads which files the app opens, which processes it starts, and which requests it makes. Inert canaries then settle the three flaw classes:

| Check | Lab item | Look-alike |
|---|---|---|
| `path-from-input` (CWE-22) | L11 | N9 |
| `command-from-input` (CWE-78) | L12 | N10 |
| `request-from-input` (CWE-918) | L13 | N11 |

The lab never runs a command and never sends an outbound request: its shell is `/bin/false`, and its requests are aborted before they leave.

## 15. Technology choices

| Concern | MVP choice | Why | Revisit when |
|---|---|---|---|
| Kernel, CLI | Python 3.11+, asyncio, Typer | strongest security and reverse-engineering ecosystem (Ghidra and IDA Python APIs, dnfile, LIEF, Playwright); the workload is I/O-bound | gateway or scheduler throughput becomes a bottleneck |
| Schemas | pydantic v2, exported as JSON Schema | one definition drives validation, docs, non-Python plugins, and decoding grammars | — |
| Plugin protocol | JSON-RPC 2.0 over stdio, MCP-compatible subset | open protocol with SDKs in every major language; existing local MCP tool servers can be wrapped | the MCP spec changes the subset |
| Sandboxing | Docker Engine API (Podman-compatible), rootless where available; gVisor optional | already on most developer machines, including Windows through WSL 2 | executing hostile binaries (VM tier, Phase 4) |
| Gateway | in-house asyncio forward proxy on h11, one request per connection, in its own container on internal networks only; controlled over a persistent `docker exec` relay to a Unix socket | small TCB with full control of sockets, so revocation closes them at once; the same code is tested in-process without Docker; network topology is the second layer | https targets need TLS interception (CONNECT with a per-run CA) |
| Storage | SQLite (WAL) and content-addressed blobs | local-first, zero operations, portable bundles | a shared team server; compression when evidence volume warrants it |
| HTML oracle | WHATWG-compliant HTML parser | builds the same tree a browser would, without running script | — |
| Models | llama.cpp `llama-server` (GGUF) in a no-egress container, driven over its loopback HTTP API; Ollama and vLLM behind the same adapter | no third-party service; runs on CPU or GPU on Windows, Linux, and macOS; JSON-Schema-constrained decoding; weights pinned by hash | a local runtime with better constrained decoding or throughput on the reference hardware |
| Distribution | plugin images built from in-repo Dockerfiles or loaded from tarballs; weights added from local files; base images and packages pinned by digest and fetched once at install | nothing is fetched at run time, so air-gapped installs work | — |
| CVSS | in-repo deterministic calculator | scores are never model-generated | — |

## 16. Non-goals

- Production testing, internet-wide scanning, or reconnaissance of third parties.
- Exploit development, payload weaponization, exploit chaining, or post-exploitation.
- Hosted model APIs or any other third-party service at run time.
- Autonomous remediation: applying patches, committing, or opening pull requests.
- Licensing, DRM, or anti-tamper analysis or bypass; asset extraction; credential harvesting.
- Compliance attestation or certification.
- Replacing human review of high-severity findings, or of spec release across the clean-room boundary.

## 17. Open questions

2. **Deployment.** A single-developer local CLI only, or a shared team server later? The answer affects storage, approvals with multiple approvers, and signing.

Resolved:

- Q1: the kernel is Python.
- Q3: the development laptop is the Phase 2 reference machine: a 6-core CPU, 16 GB of RAM, and no usable GPU, under the new `laptop` profile ([ADR 0007](adr/0007-reference-hardware.md)).
- Q4: JavaScript and Electron come first, as the lightest engines (a vendored parser on the lab's own Node base). .NET metadata follows, then native through Ghidra, opt-in because of its size ([ADR 0009](adr/0009-analyze-mvp.md)).
- Q5: the lab uses Node.js built-ins with no npm dependencies. That keeps it buildable offline and makes it an owned JavaScript subject for Analyze.
