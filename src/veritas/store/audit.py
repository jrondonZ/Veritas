"""Append-only, hash-linked audit log (docs/architecture.md §11).

Each line is the canonical JSON of one entry. An entry's hash covers every field
except `hash` itself, and each entry names the previous entry's hash in `prev`.
Editing, deleting, or reordering any line breaks the chain. Deleting lines from
the end is caught by comparing against the head recorded in the workspace index.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..core.canonical import canonical_json, digest

GENESIS = "sha256:" + "0" * 64
_RESERVED = frozenset({"seq", "ts", "prev", "type", "hash"})


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class AuditChain:
    """Single-writer appender. `on_append(entries, head)` lets the index track the head."""

    def __init__(self, path: Path, on_append: Callable[[int, str], None] | None = None):
        self.path = Path(path)
        self._on_append = on_append
        self._lock = threading.Lock()
        self._count, self._head = 0, GENESIS
        if self.path.exists():
            result = verify(self.path)
            if not result.ok:
                raise ValueError(f"refusing to append to a broken audit log: {result.problems[0]}")
            self._count, self._head = result.entries, result.head

    @property
    def head(self) -> str:
        return self._head

    @property
    def count(self) -> int:
        return self._count

    def append(self, event_type: str, **fields: Any) -> dict[str, Any]:
        clash = _RESERVED & fields.keys()
        if clash:
            raise ValueError(f"reserved audit field names: {sorted(clash)}")
        with self._lock:
            entry = {"seq": self._count, "ts": utc_now(), "prev": self._head, "type": event_type, **fields}
            entry["hash"] = digest(entry)
            with open(self.path, "a", encoding="utf-8", newline="\n") as f:
                f.write(canonical_json(entry) + "\n")
                f.flush()
                os.fsync(f.fileno())
            self._count += 1
            self._head = entry["hash"]
            if self._on_append:
                self._on_append(self._count, self._head)
            return entry


@dataclass
class VerifyResult:
    entries: int = 0
    head: str = GENESIS
    problems: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems


def verify(path: Path, expected_head: str | None = None, expected_entries: int | None = None) -> VerifyResult:
    result = VerifyResult()
    prev, seq = GENESIS, 0
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                result.problems.append(f"line {lineno}: not valid JSON")
                return result
            if not isinstance(entry, dict):
                result.problems.append(f"line {lineno}: not a JSON object")
                return result
            if entry.get("seq") != seq:
                result.problems.append(
                    f"line {lineno}: expected seq {seq}, found {entry.get('seq')!r} (entry removed or reordered)"
                )
                return result
            if entry.get("prev") != prev:
                result.problems.append(f"line {lineno} (seq {seq}): prev does not match the preceding entry's hash")
                return result
            stored = entry.pop("hash", None)
            if stored != digest(entry):
                result.problems.append(f"line {lineno} (seq {seq}): contents do not match the entry hash (modified)")
                return result
            prev, seq = stored, seq + 1
    result.entries, result.head = seq, prev
    if expected_entries is not None and expected_entries != seq:
        result.problems.append(
            f"log has {seq} entries but the index recorded {expected_entries} (entries removed or appended)"
        )
    elif expected_head is not None and expected_head != prev:
        result.problems.append("log head does not match the head recorded in the index")
    return result
