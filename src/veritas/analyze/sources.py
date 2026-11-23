"""Subject text for the similarity checks: the spec gate's filter and the clean room's audit.

The reference is the source of every subject an engine read. For an Electron archive, that
means the members the engine analyzed. They're sliced from the staged copy and checked
against the engine's hashes, so a large archive is never decoded whole and an engine can't
point the checks at bytes it didn't analyze.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from ..core.canonical import sha256_hex

COMPILED = frozenset({"pe", "elf", "macho"})  # their source text isn't in the subject


class SourceError(Exception):
    """An engine's account of a subject doesn't match the staged bytes."""


def staged_name(subject: dict[str, Any]) -> str:
    return subject.get("staged") or f"{subject['sha256'][:16]}-{PurePosixPath(subject['path']).name}"


def member_texts(path: Path, members: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    size = path.stat().st_size
    with path.open("rb") as fh:
        for m in members:
            offset, length = m.get("offset"), m.get("size")
            if (
                not isinstance(offset, int)
                or not isinstance(length, int)
                or min(offset, length) < 0
                or offset + length > size
            ):
                raise SourceError(f"the engine placed {m.get('path')!r} outside the archive")
            fh.seek(offset)
            data = fh.read(length)
            if sha256_hex(data) != m.get("sha256"):
                raise SourceError(f"the engine's record of {m.get('path')!r} doesn't match the archive's bytes")
            out.append(data.decode("utf-8", errors="replace"))
    return out


def subject_sources(inputs: Path, subjects: list[dict[str, Any]]) -> list[str]:
    """The source text of each subject an engine read, from the run's staged copies."""
    out: list[str] = []
    for s in subjects:
        if not s.get("facts") or s.get("staged") == "" or s.get("type") in COMPILED:
            continue  # no engine read it; or it's a recording, data that's never stored; or it's compiled code
        staged = inputs / staged_name(s)
        if s.get("members") is not None:
            out += member_texts(staged, s["members"])
        else:
            out.append(staged.read_text(encoding="utf-8", errors="replace"))
    return out
