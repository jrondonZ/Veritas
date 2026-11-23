"""The model response cache (docs/architecture.md §10.5): the replay mechanism for model output.

The key covers everything that decides an output: weights, runtime build, sampling,
prompt template version, schema, and the exact messages. Every attempt is cached,
including ones the kernel later rejects, so a warm rerun repeats the same sequence of
attempts without a single model call.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from ..core.canonical import digest

MAX_BYTES = 256 * 1024 * 1024


class ResponseCache:
    def __init__(self, root: Path, max_bytes: int = MAX_BYTES):
        self.dir = Path(root) / ".veritas" / "cache" / "models"
        self.max_bytes = max_bytes

    @staticmethod
    def key(**parts: Any) -> str:
        return digest(parts)

    def _path(self, key: str) -> Path:
        hexdigest = key.removeprefix("sha256:")
        return self.dir / hexdigest[:2] / f"{hexdigest}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        path = self._path(key)
        try:
            value: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        os.utime(path)  # least recently used is pruned first
        return value

    def put(self, key: str, value: dict[str, Any]) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
        self.prune()

    def prune(self) -> int:
        files = sorted(self.dir.glob("*/*.json"), key=lambda p: p.stat().st_mtime)
        total = sum(p.stat().st_size for p in files)
        removed = 0
        while files and total > self.max_bytes:
            oldest = files.pop(0)
            total -= oldest.stat().st_size
            oldest.unlink(missing_ok=True)
            removed += 1
        return removed
