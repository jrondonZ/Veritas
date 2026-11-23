"""Envelope audit: prove from a run's audit chain that nothing was sent outside an approved envelope.

Every `task.start` entry declares the exact requests of its script. Every request the
gateway allowed is logged with its task ID. This check matches the two, request by request.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


def audit_envelopes(audit_log: Path) -> list[str]:
    declared: dict[str, Counter[str]] = {}
    allowed: list[tuple[str, str]] = []
    for line in audit_log.read_text(encoding="utf-8").splitlines():
        entry = json.loads(line)
        if entry["type"] == "task.start":
            requests = (r.rsplit(" as ", 1)[0] for r in entry["requests"])  # "METHOD /path?query as identity"
            declared[entry["tid"]] = Counter(requests)
        elif entry["type"] == "gateway.request" and entry.get("verdict") == "allow":
            parts = urlsplit(entry["uri"])
            request = f"{entry['method']} {parts.path}" + (f"?{parts.query}" if parts.query else "")
            allowed.append((entry.get("tid", ""), request))
    problems = []
    used: dict[str, Counter[str]] = {}
    for tid, request in allowed:
        budget = declared.get(tid)
        if budget is None:
            problems.append(f"{tid or 'no task'}: allowed {request} with no declared script")
            continue
        used.setdefault(tid, Counter())[request] += 1
        if used[tid][request] > budget[request]:
            problems.append(f"{tid}: allowed {request} beyond its declared script")
    return problems
