"""Secret scanning for prompts (docs/architecture.md §9.5): secrets stay out of model inputs, caches, and logs.

The gateway already masks credentials at capture. This is the second pass, over
everything a prompt is built from: known token formats, `key=value` secrets, and
long high-entropy strings. Hex digests and Veritas IDs have at most 4 bits of entropy
per character and are left alone.
"""

from __future__ import annotations

import math
import re
from collections import Counter

PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("authorization", re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{12,}")),
)
# key = value, key: value, "key": "value" -- the key stays, the value goes
ASSIGNED = re.compile(
    r"(?i)(\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|token)\b\"?\s*[:=]\s*\"?)([^\s\"&,;]{4,})"
)
CANDIDATE = re.compile(r"[A-Za-z0-9+/_=-]{32,}")


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def _random_looking(token: str) -> bool:
    classes = sum((any(c.islower() for c in token), any(c.isupper() for c in token), any(c.isdigit() for c in token)))
    return classes >= 3 and entropy(token) > 4.0


def redact(text: str) -> tuple[str, Counter[str]]:
    found: Counter[str] = Counter()
    for kind, pattern in PATTERNS:

        def mark(_: re.Match[str], kind: str = kind) -> str:
            found[kind] += 1
            return f"[redacted:{kind}]"

        text = pattern.sub(mark, text)

    def keep_key(m: re.Match[str]) -> str:
        found["assigned-secret"] += 1
        return f"{m.group(1)}[redacted:secret]"

    text = ASSIGNED.sub(keep_key, text)

    def token(m: re.Match[str]) -> str:
        if not _random_looking(m.group(0)):
            return m.group(0)
        found["high-entropy"] += 1
        return "[redacted:token]"

    return CANDIDATE.sub(token, text), found
