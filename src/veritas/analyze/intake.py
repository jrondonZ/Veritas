"""Subject intake (docs/architecture.md §8.3 step 2): copy, hash, detect the type, and stage for read-only mounting.

Subjects are dirty from the moment they're read. Their bytes go into the evidence store
with provenance `dirty:subject`, and a copy is staged in the run's `inputs/` directory,
which engines get mounted read-only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from ..core.canonical import sha256_hex

SUBJECT_MEDIA_TYPE = "application/vnd.veritas.subject"
JS_SUFFIXES = (".js", ".mjs", ".cjs")
# Recordings hold live session tokens and personal data. They're read in memory and never copied into the
# workspace, so evidence bundles can't carry them; only what their reader keeps is stored.
UNSTORED = frozenset({"har"})
MACHO = (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe")


@dataclass(frozen=True)
class Subject:
    path: str  # as the charter names it
    sha256: str  # hex
    size: int
    type: str  # javascript, source-map, har, asar, pe, elf, macho, unknown
    staged: str  # name inside the run's inputs/ directory; empty for a recording, which is never copied


def detect(path: Path, head: bytes) -> str:
    suffix = path.suffix.lower()
    if head[:2] == b"MZ":
        return "pe"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in MACHO:
        return "macho"
    if suffix == ".asar" or (head[:4] == b"\x04\x00\x00\x00" and b'{"files"' in head[:64]):
        return "asar"
    if suffix == ".map":
        return "source-map"
    if suffix == ".har":
        return "har"
    if suffix in JS_SUFFIXES:
        return "javascript"
    if suffix == ".json":
        try:
            doc = json.loads(path.read_bytes())
        except ValueError:
            return "unknown"
        return "har" if isinstance(doc, dict) and "entries" in (doc.get("log") or {}) else "unknown"
    return "unknown"


def stage(base: Path, path: str, inputs: Path) -> tuple[Subject, bytes]:
    """Read one subject and stage a copy of exactly the bytes read (the caller checks them against the charter)."""
    source = base / path
    data = source.read_bytes()
    digest = sha256_hex(data)
    kind = detect(source, data[:4096])
    if kind in UNSTORED:
        return Subject(path, digest, len(data), kind, ""), data
    staged = f"{digest[:16]}-{source.name}"
    inputs.mkdir(parents=True, exist_ok=True)
    target = inputs / staged
    if not target.exists():
        target.write_bytes(data)
    return Subject(path, digest, len(data), kind, staged), data
