"""Turning oracle results into findings: status, reproducibility, claims, CVSS, and stable IDs."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any, NamedTuple

from ..findings import Attempt, Claim, Finding, base_score, fingerprint, severity
from .checks import CHECKS, Check, OracleResult, PlanContext
from .evidence import Exchange, SensorRecord
from .probes import Probe


class AttemptResult(NamedTuple):
    attempt: int
    result: OracleResult
    exchanges: list[Exchange | None]
    tid: str | None
    signals: tuple[SensorRecord, ...] = ()


def status_of(check: Check, results: list[AttemptResult]) -> tuple[str, str, int]:
    """(status, reason, passes) from the attempts in order. Only a pass is reproduced."""
    verdicts = [a.result.verdict for a in results]
    passes = verdicts.count("pass")
    if "error" in verdicts:
        return "error", next(a.result.reason for a in results if a.result.verdict == "error"), passes
    if passes == 0:
        first = results[0].result
        return ("rejected" if first.verdict == "fail" else "inconclusive"), first.reason, 0
    if passes == len(results) or check.info.decisive:
        reason = results[0].result.reason if passes == len(results) else f"intermittent: {passes} of {len(results)}"
        return "confirmed", reason, passes
    return "inconclusive", f"a statistical oracle passed {passes} of {len(results)} times", passes


def build_finding(check: Check, probe: Probe, results: list[AttemptResult], ctx: PlanContext) -> Finding:
    status, reason, passes = status_of(check, results)
    decisive = next((a.result for a in results if a.result.verdict == "pass"), results[0].result)
    oracle, own = f"oracle:{check.id}", f"check:{check.id}"
    claims: list[Claim] = [Claim("", "observed", o.text, list(o.evidence), producer=oracle) for o in decisive.observed]
    if status == "confirmed":
        claims += [Claim("", "inferred", text, producer=oracle) for text in decisive.inferred]
    claims += [Claim("", "unknown", text, producer=own) for text in check.unknowns(probe, ctx)]
    claims += [Claim("", "limitation", text, producer=own) for text in check.limitations(probe, ctx)]
    if status == "inconclusive":
        claims.append(Claim("", "limitation", f"Not decided: {reason}.", producer="kernel"))
    if status in ("confirmed", "inconclusive"):
        claims.append(Claim("", "guidance", check.info.remediation, producer=f"template:{check.id}"))
    finding = _base(check, probe, ctx, status, reason)
    finding.passed, finding.attempts, finding.claims = passes, len(results), claims
    finding.history = [
        Attempt(
            a.result.verdict,
            a.result.reason,
            [e.id if e else None for e in a.exchanges],
            a.tid,
            [s.id for s in a.signals],
        )
        for a in results
    ]
    if status == "confirmed":
        score = base_score(check.info.cvss)
        finding.cvss = {"version": "3.1", "vector": check.info.cvss, "score": score}
        finding.severity = severity(score)
    return finding


def blocked_finding(check: Check, probe: Probe, ctx: PlanContext, reason: str) -> Finding:
    return _base(check, probe, ctx, "blocked", reason)


def _base(check: Check, probe: Probe, ctx: PlanContext, status: str, reason: str) -> Finding:
    steps = check.steps_for(probe, 1)
    return Finding(
        id="",
        fingerprint=fingerprint(check.id, ctx.target.id, probe.key),
        check=check.id,
        title=f"{check.info.title}: {probe.route}",
        route=probe.route,
        status=status,  # type: ignore[arg-type]
        reason=reason,
        passed=0,
        attempts=0,
        cwe=list(check.info.cwe),
        wstg=list(check.info.wstg),
        repro=[f"as {s.identity or 'anonymous'}: {s.method} {s.path}" for s in steps]
        or [f"inspect {len(probe.evidence)} recorded response(s) to {probe.route}"],
        probe={
            "key": list(probe.key),
            "route": probe.route,
            "description": probe.description,
            "params": probe.params,
            "steps": [asdict(s) for s in probe.steps],
            "evidence": list(probe.evidence),
        },
    )


def number(findings: list[Finding]) -> list[Finding]:
    """Assign F- and C- IDs in a fixed order (check order, then fingerprint), so reruns line up."""
    order = {c.id: i for i, c in enumerate(CHECKS)}
    ordered = sorted(findings, key=lambda f: (order.get(f.check, len(order)), f.fingerprint))
    claim_number = 0
    for index, finding in enumerate(ordered, 1):
        finding.id = f"F-{index:04d}"
        observed: list[str] = []
        for claim in finding.claims:
            claim_number += 1
            claim.id = f"C-{claim_number:04d}"
            if claim.kind == "observed":
                observed.append(claim.id)
            elif claim.kind == "inferred":
                claim.based_on = list(observed)
    return ordered


def summary(findings: list[Finding]) -> dict[str, Any]:
    counts = {
        s: sum(f.status == s for f in findings) for s in ("confirmed", "rejected", "inconclusive", "blocked", "error")
    }
    by_severity = {s: sum(f.severity == s for f in findings) for s in ("critical", "high", "medium", "low")}
    return {**counts, "by_severity": by_severity}


def coverage(findings: list[Finding]) -> list[dict[str, Any]]:
    rows = []
    for check in CHECKS:
        mine = [f for f in findings if f.check == check.id]
        status = "not applicable" if not mine else "blocked" if all(f.status == "blocked" for f in mine) else "executed"
        rows += [{"wstg": w, "check": check.id, "status": status, "probes": len(mine)} for w in check.info.wstg]
    return sorted(rows, key=lambda r: (r["wstg"], r["check"]))
