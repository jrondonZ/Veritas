"""What a role sees about one finding: its claims and evidence under short aliases (docs/architecture.md §10.4).

Prompts never contain raw evidence or claim IDs. Each finding's claims become C1, C2, …
and its evidence E1, E2, …, so equal behavior yields byte-identical prompts across runs
and a warm rerun replays from the response cache. Volatile headers (Date and the like)
are left out of excerpts for the same reason. Everything taken from the target is
wrapped as untrusted, and every alias a model cites must resolve back to a real ID.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..assess.evidence import Exchange, SensorRecord
from ..models.prompts import untrusted

KEPT_HEADERS = ("content-type", "content-security-policy", "set-cookie", "location", "x-content-type-options")
BODY_EXCERPT = 600
SQL_EXCERPT = 300


def exchange_excerpt(exchange: Exchange) -> str:
    lines = [f"{exchange.method} {exchange.path} as {exchange.identity or 'anonymous'} -> {exchange.status}"]
    lines += [f"{name}: {value}" for name, value in exchange.response_headers if name in KEPT_HEADERS]
    body = exchange.text
    if body:
        cut = body[:BODY_EXCERPT]
        lines.append(f"body ({len(body)} bytes{', excerpt' if len(body) > BODY_EXCERPT else ''}):\n{cut}")
    return "\n".join(lines)


def sensor_excerpt(record: SensorRecord) -> str:
    lines = [f"query log entries that mention {', '.join(record.markers)}:"]
    for entry in record.entries[:5]:
        sql = str(entry.get("sql", ""))[:SQL_EXCERPT]
        lines.append(f"- sql: {sql}\n  params: {entry.get('params')}")
    return "\n".join(lines) if record.entries else lines[0] + " none"


@dataclass
class FindingContext:
    finding: dict[str, Any]
    exchanges: dict[str, Exchange] = field(default_factory=dict)  # evidence ID -> exchange
    signals: dict[str, SensorRecord] = field(default_factory=dict)  # evidence ID -> sensor record
    claim_alias: dict[str, str] = field(default_factory=dict)  # C1 -> real claim ID
    evidence_alias: dict[str, str] = field(default_factory=dict)  # E1 -> real evidence ID

    def __post_init__(self) -> None:
        for claim in self.finding.get("claims", []):
            self.claim_alias[f"C{len(self.claim_alias) + 1}"] = claim["id"]
            for evidence_id in claim.get("evidence", []):
                if evidence_id not in self.evidence_alias.values():
                    self.evidence_alias[f"E{len(self.evidence_alias) + 1}"] = evidence_id

    def alias_of(self, real_id: str) -> str:
        table = {**{v: k for k, v in self.claim_alias.items()}, **{v: k for k, v in self.evidence_alias.items()}}
        return table[real_id]

    def claims_text(self, kinds: tuple[str, ...] = ("observed", "inferred", "unknown", "limitation")) -> str:
        lines = []
        for claim in self.finding.get("claims", []):
            if claim["kind"] not in kinds:
                continue
            refs = [self.alias_of(e) for e in claim.get("evidence", [])]
            basis = [self.alias_of(b) for b in claim.get("based_on", [])]
            cites = f" [{', '.join(refs)}]" if refs else ""
            rests = f" (based on {', '.join(basis)})" if basis else ""
            lines.append(f"{self.alias_of(claim['id'])} {claim['kind']}: {claim['text']}{cites}{rests}")
        return "\n".join(lines)

    def evidence_text(self) -> str:
        blocks = []
        for alias, real in self.evidence_alias.items():
            if real in self.exchanges:
                blocks.append(f"{alias}:\n" + untrusted(exchange_excerpt(self.exchanges[real]), "target"))
            elif real in self.signals:
                blocks.append(f"{alias}:\n" + untrusted(sensor_excerpt(self.signals[real]), "app query log"))
        return "\n\n".join(blocks)

    def observed_aliases(self) -> set[str]:
        kinds = {c["id"]: c["kind"] for c in self.finding.get("claims", [])}
        return {alias for alias, real in self.claim_alias.items() if kinds.get(real) in ("observed", "inferred")}

    def unknown_aliases(self, aliases: list[str], allowed: set[str]) -> list[str]:
        return [a for a in aliases if a not in allowed]

    def real_claims(self, aliases: list[str]) -> list[str]:
        return [self.claim_alias[a] for a in aliases]
