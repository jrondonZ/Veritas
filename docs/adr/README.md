# Architecture decision records

Each record captures one significant decision: the context, the decision, and its consequences. Records are numbered and never rewritten. To change a decision, add a new record that supersedes the old one, and update [../architecture.md](../architecture.md) in the same change.

| ADR | Decision | Status |
|---|---|---|
| [0001](0001-local-models-only.md) | Run models locally only; no hosted model APIs | Accepted |
| [0002](0002-in-house-gateway-proxy.md) | Build the egress gateway on asyncio and h11 instead of mitmproxy | Accepted |
| [0003](0003-gateway-control-relay.md) | Control the gateway through a persistent `docker exec` relay | Accepted |
| [0004](0004-package-layout-and-layering.md) | Organize packages by trust boundary and enforce layering with a test | Accepted |
| [0005](0005-kernel-checks-and-executor.md) | Run first-party checks as kernel recipes through one sandboxed executor | Accepted |
| [0006](0006-sensors-and-sensor-evidence.md) | Read app internals through network-less sensor plugins, and decide in the kernel | Accepted |
| [0007](0007-reference-hardware.md) | Make the development laptop the Phase 2 reference machine | Accepted |
| [0008](0008-model-sandbox-and-relay.md) | Run llama-server with no network, reached through a relay inside its container | Accepted |
| [0009](0009-analyze-mvp.md) | Build Analyze around a mechanical spec, a hash-checked clean view, and a similarity audit | Accepted |
| [0010](0010-code-findings-and-archives.md) | Find weaknesses in code as candidates that Assess confirms, and read Electron archives member by member | Accepted |
| [0011](0011-har-recordings.md) | Read HAR recordings for their shape only, and never store them raw | Accepted |
| [0012](0012-header-cors-redirect-checks.md) | Judge response headers from recon's own fetches, and probe CORS and redirects with `.invalid` origins | Accepted |
| [0013](0013-activity-sensor-checks.md) | Decide path, command, and outbound-request flaws from the app's own activity log | Accepted |
| [0014](0014-binary-engine.md) | Read compiled code with a stdlib binary engine: .NET metadata and IL, and native headers, without Ghidra | Accepted |
| [0015](0015-code-route-patches-eval.md) | A small coding model for clean-room code, model-drafted patches checked by the rules, and a routing eval | Accepted |
| [0016](0016-local-ui.md) | A read-only local UI on loopback: stdlib server, bundled assets, data rendered as text | Accepted |

## Template

```markdown
# NNNN. Title

- Status: Proposed | Accepted | Superseded by NNNN
- Date: YYYY-MM-DD

## Context
## Decision
## Consequences
```
