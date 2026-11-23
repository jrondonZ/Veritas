# 0005. Run first-party checks as kernel recipes through one sandboxed executor

- Status: Accepted
- Date: 2026-11-18

## Context

The architecture proposed one sandboxed plugin per check, with a container per task. Building Phase 1 raised three problems:

- Starting a container took about 9.5 seconds on the development host. A container per probe would blow the 5-minute budget for a lab run.
- A check plugin that both sends requests and reports a verdict can lie about the verdict.
- Approval prompts should show exactly which requests will be sent. That's only possible if the requests are known before anything runs.

## Decision

- **Checks are recipes.** First-party checks are kernel-side recipes. `plan()` turns recon into probes: explicit request scripts. `evaluate()` is the oracle, a pure function of exchanges.
- **One executor per run.** A single sandboxed plugin, `veritas.http-executor`, runs for the whole run and sends each script through the gateway. It returns status codes and evidence IDs only, never response bodies.
- **One token per script.** Every script gets its own token. Its envelope allows exactly that script's method and path pairs, with exact request counts, and the token is revoked as soon as the script ends.
- **Verdicts come from captured evidence.** The kernel reads every response from the gateway's capture and re-checks its content hash. It confirms the record belongs to that script's task ID, method, and path, and only then runs the oracle.
- **The gateway handles identities.** It signs each identity in and injects its session; plugins only ever see masked cookie values.

## Consequences

- A compromised executor can't confirm a finding. The most it can do is fail to send requests, which surfaces as an `error`.
- Container start-up is paid once per run, not once per probe.
- The kernel parses target HTML and JSON in-process for crawling and oracles. It uses stdlib parsers only, and the gateway caps bodies at 8 MiB. If that becomes a concern, the parsing can move into a no-network sandbox.
- Third-party checks (Phase 4) still run as sandboxed plugins under the same gateway rules.
