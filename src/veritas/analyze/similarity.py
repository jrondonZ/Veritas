"""Token fingerprints by winnowing (Schleimer, Wilkerson, Aiken 2003), for the spec gate and the similarity audit.

Text is tokenized, optionally with identifiers and literals normalized (so renaming
can't hide copying), hashed as k-grams, and winnowed: the smallest hash in each window
of consecutive k-gram hashes is kept. Overlap is the share of one text's fingerprints
found in the other's.
"""

from __future__ import annotations

import hashlib
import re

TOKEN = re.compile(
    r"[A-Za-z_$][A-Za-z0-9_$]*|0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?|\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|`[^`]*`|\S"
)
KEYWORDS = frozenset(
    {
        *("break", "case", "catch", "class", "const", "continue", "default", "delete", "do", "else", "export"),
        *("extends", "finally", "for", "function", "if", "import", "in", "instanceof", "let", "new", "of"),
        *("return", "switch", "this", "throw", "try", "typeof", "var", "void", "while", "yield", "async", "await"),
        *("null", "true", "false", "undefined"),
    }
)


def tokens(text: str, normalize: bool = False) -> list[str]:
    out = []
    for tok in TOKEN.findall(text):
        if normalize:
            if tok[0].isalpha() or tok[0] in "_$":
                tok = tok if tok in KEYWORDS else "ID"
            elif tok[0] in "\"'`":
                tok = "STR"
            elif tok[0].isdigit():
                tok = "NUM"
        out.append(tok)
    return out


def _hash(gram: tuple[str, ...]) -> int:
    return int.from_bytes(hashlib.blake2b("\x1f".join(gram).encode(), digest_size=8).digest(), "big")


def fingerprints(toks: list[str], k: int = 5, window: int = 4) -> set[int]:
    hashes = [_hash(tuple(toks[i : i + k])) for i in range(len(toks) - k + 1)]
    if len(hashes) <= window:
        return set(hashes)
    return {min(hashes[i : i + window]) for i in range(len(hashes) - window + 1)}


def overlap(text: str, reference: set[int], *, normalize: bool = False, k: int = 5) -> float:
    """Share of `text`'s fingerprints that occur in `reference` (0 when `text` is too short to fingerprint)."""
    mine = fingerprints(tokens(text, normalize), k)
    return len(mine & reference) / len(mine) if mine else 0.0
