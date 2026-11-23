# 0003. Control the gateway through a persistent `docker exec` relay

- Status: Accepted
- Date: 2026-11-18

## Context

The kernel must be able to revoke tokens and cut in-flight requests within one second. The gateway listens only on internal Docker networks, which can't publish ports, so the kernel can't reach it over TCP. A `docker exec` per command took about 3.6 seconds on the development host (Docker Desktop on Windows). With that delay, the first escape-suite run revoked after the request had already finished.

## Decision

- The gateway serves control requests on a Unix socket inside its container, at `/run/veritas/control.sock` on a tmpfs.
- When a run starts, the kernel opens one long-lived `docker exec -i <gateway> python -m veritas.gateway.ctl stdio` relay. Each command is then a single JSON line written to that relay.

## Consequences

- Measured revocation round trips are 16 to 31 ms, and the in-flight request is cut at once.
- The relay is a process the kernel supervises. If it dies, `RunSandbox.control` raises, and Phase 1 must treat that as a reason to abort the run.
- The gateway has no listening port outside the sandbox network.
