"""The Program Model (docs/architecture.md §8.3): engine-independent facts about a subject.

Every fact is dirty: it comes from the subject, through a sandboxed engine, and is
stored as evidence. Nothing here crosses into a clean-room context. Only the spec gate's
filtered claims can, once a person approves them (§8.3, B5).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class FileModel:
    path: str
    sha256: str
    evidence: str  # E- ID of the engine record these facts came from
    facts: dict[str, Any]

    def items(self, kind: str) -> list[dict[str, Any]]:
        return [x for x in self.facts.get(kind) or [] if isinstance(x, dict)]

    @property
    def functions(self) -> dict[str, dict[str, Any]]:
        return {f["name"]: f for f in self.items("functions")}

    @property
    def excluded(self) -> dict[str, str]:
        return {e["function"]: e["reason"] for e in self.items("excluded")}

    @property
    def exports(self) -> list[dict[str, Any]]:
        return self.items("exports")

    @property
    def exported_functions(self) -> list[str]:
        return [e["name"] for e in self.exports if e.get("kind") == "function" and e["name"] in self.functions]

    @property
    def constants(self) -> dict[str, dict[str, Any]]:
        return dict(self.facts.get("constants") or {})

    @property
    def identifiers(self) -> set[str]:
        return set(self.facts.get("identifiers") or [])

    @property
    def strings(self) -> set[str]:
        return {s["value"] for s in self.items("strings")}

    def reachable(self, root: str) -> list[str]:
        """`root` and every function it reaches by direct calls, never entering excluded logic."""
        functions, excluded = self.functions, self.excluded
        order, queue = [], [root]
        while queue:
            name = queue.pop(0)
            if name in order or name not in functions or name in excluded:
                continue
            order.append(name)
            queue += [c for c in functions[name].get("calls", []) if c not in order]
        return order

    def excluded_reached(self, root: str) -> set[str]:
        functions, excluded = self.functions, self.excluded
        return {c for f in self.reachable(root) for c in functions[f].get("calls", []) if c in excluded}
