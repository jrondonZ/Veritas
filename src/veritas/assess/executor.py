"""The kernel's side of the HTTP executor plugin: every script gets its own exactly-scoped token."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Sequence

from ..core.impact import Impact
from ..core.tokens import TokenClaims, mint
from ..plugins.host import PluginSession
from ..sandbox import RunSandbox
from ..scope.model import Target
from ..store import AuditChain
from .evidence import CaptureEvidence, Exchange
from .probes import Step, envelope


class ExecutorError(Exception):
    pass


class Executor:
    def __init__(
        self,
        session: PluginSession,
        sandbox: RunSandbox,
        key: bytes,
        target: Target,
        evidence: CaptureEvidence,
        audit: AuditChain,
        plugin_ref: str,
    ):
        self.session, self.sandbox, self.key, self.target = session, sandbox, key, target
        self.evidence, self.audit, self.plugin_ref = evidence, audit, plugin_ref
        self._count = 0
        self.last_tid: str | None = None

    async def run(
        self, steps: Sequence[Step], impact: Impact, purpose: str, approval: str | None = None
    ) -> list[Exchange | None]:
        self._count += 1
        tid = self.last_tid = f"t-{self._count:04d}"
        grants = envelope(tuple(steps), self.target.id)
        claims = TokenClaims(
            tid=tid,
            run=self.sandbox.run_id,
            exp=int(time.time()) + 60 + 30 * len(steps),
            plugin=self.plugin_ref,
            impact_max=impact,
            approval=approval,
            net=grants,
        )
        self.audit.append(
            "task.start",
            tid=tid,
            purpose=purpose,
            impact=str(impact),
            approval=approval,
            requests=[f"{s.method} {s.path} as {s.identity or 'anonymous'}" for s in steps],
        )
        try:
            reply = await self.session.call(
                "execute",
                {"tid": tid, "token": mint(claims, self.key), "steps": [s.wire(self.target.base_url) for s in steps]},
                timeout=60 + 30 * len(steps),
            )
        finally:
            await asyncio.to_thread(self.sandbox.revoke, tid)  # the token dies with its script
        results = reply.get("results")
        if not isinstance(results, list) or [r.get("id") for r in results] != [s.id for s in steps]:
            raise ExecutorError(f"{tid}: the executor's results do not match the script")
        exchanges: list[Exchange | None] = []
        for step, result in zip(steps, results, strict=True):
            evidence_id = result.get("evidence")
            exchange = self.evidence.get(evidence_id) if isinstance(evidence_id, str) else None
            if exchange is not None and (exchange.tid, exchange.method, exchange.path) != (tid, step.method, step.path):
                raise ExecutorError(f"{tid}: evidence {evidence_id} does not belong to step {step.id}")
            exchanges.append(exchange)
        self.audit.append(
            "task.end",
            tid=tid,
            evidence=[e.id if e else None for e in exchanges],
            statuses=[r.get("status") for r in results],
            denied=sorted({r["denied"] for r in results if r.get("denied")}),
        )
        return exchanges

    def logins(self) -> dict[str, str]:
        return self.evidence.logins()
