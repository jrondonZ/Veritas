# 0002. Build the egress gateway on asyncio and h11 instead of mitmproxy

- Status: Accepted
- Date: 2026-11-18

## Context

The proposal used mitmproxy with a scope-enforcement addon. The gateway is part of the trusted computing base, and three requirements made mitmproxy a poor fit:

- Revocation has to cut in-flight requests at once. mitmproxy's addon API can kill a flow, but it does not reliably close sockets that are waiting on an upstream response.
- The TCB should be small and fully reviewable.
- The admission rules should be testable in-process, without Docker.

## Decision

- An in-house forward proxy on asyncio and h11. It handles one request per connection (`Connection: close` both ways) and forwards only to addresses pinned at scope check, without ever re-resolving.
- Admission is a pure function (`veritas/gateway/admission.py`) that every request passes through.
- Responses are buffered up to 8 MiB, so evidence IDs can be content-derived and returned in `Veritas-Evidence`.
- The proxy refuses `CONNECT`, https targets, and requests that carry both `Content-Length` and `Transfer-Encoding`.

## Consequences

- https targets need TLS interception (CONNECT with a per-run CA) before Phase 4 staging support.
- Responses larger than 8 MiB are refused with `response_too_large`.
- The same proxy code runs in unit tests on 127.0.0.1 and in the Docker escape suite.
