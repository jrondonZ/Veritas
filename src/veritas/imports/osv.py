"""Offline advisories in the OSV format, imported from files the operator downloaded. Veritas never fetches one.

`veritas advisories import` reads one JSON record, a JSON list of records, a folder of record
files, or a zip export (osv.dev publishes one per ecosystem) without extracting it. Every
input is untrusted. File sizes, member counts, total bytes, and compression ratios are
capped, and only the fields matching needs are kept, each length-limited. Records go into a
SQLite index in `.veritas/advisories/`, keyed by ecosystem and package name. Each source is
recorded by its SHA-256, so a finding can say which import its advisory came from.

Versions compare as Semantic Versioning 2.0.0, which is npm's scheme. A version is affected
when it falls in a range under the OSV evaluation rules (`introduced`, `fixed`,
`last_affected`, and `limit` events) or is in the record's explicit `versions` list.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
import zipfile
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

FOLDER = "advisories"
DATABASE = "advisories.db"
MEDIA_TYPE = "application/vnd.veritas.advisory+json"
ECOSYSTEMS = ("npm",)  # what Analyze matches today: the dependencies Electron archives bundle
MAX_FILE = 64 * 1024 * 1024  # one JSON file, read whole
MAX_RECORD = 4 * 1024 * 1024  # one zip member or folder file
MAX_TOTAL = 4 * 1024**3  # everything read from one source
MAX_FILES = 1_000_000
MAX_RATIO = 200  # a zip member that inflates more than this is refused
MAX_VERSIONS = 5_000
MAX_EVENTS = 200
MAX_RANGES = 20
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
CWE = re.compile(r"^CWE-\d{1,5}$")
EVENTS = ("introduced", "last_affected", "fixed", "limit")  # also the order of equal versions in a range
_CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f  ]+")
_SEMVER = re.compile(
    r"^v?(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z.-]+)?$"
)
_BASE = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
_SCHEMA = """
CREATE TABLE IF NOT EXISTS advisories (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    id TEXT NOT NULL,
    record TEXT NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (ecosystem, name, id)
);
CREATE TABLE IF NOT EXISTS sources (
    sha256 TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    records INTEGER NOT NULL,
    skipped INTEGER NOT NULL,
    imported_at TEXT NOT NULL
);
"""
Version = tuple[Any, ...]
LOWEST: Version = (-1,)  # `introduced: "0"`, before every version


class AdvisoryError(Exception):
    """A source can't be read as OSV advisories, or it goes past a cap."""


# ------------------------------------------------------------------ versions


def version_key(text: str) -> Version | None:
    """A sortable key with Semantic Versioning 2.0.0 precedence, or None for what isn't a version."""
    m = _SEMVER.match(text.strip()) if isinstance(text, str) and len(text) <= 64 else None
    if m is None:
        return None
    release = tuple(int(g or 0) for g in m.group(1, 2, 3))
    if m.group(4) is None:
        return (*release, 1, ())  # a release sorts after its pre-releases
    parts = tuple((0, int(p), "") if p.isdigit() else (1, 0, p) for p in m.group(4).split("."))
    return (*release, 0, parts)  # numeric identifiers sort before alphanumeric ones, and numerically


def _event_key(kind: str, value: str) -> Version | None:
    return LOWEST if kind == "introduced" and value == "0" else version_key(value)


def _in_range(version: Version, events: list[tuple[Version, int, str]]) -> bool:
    affected = False
    for key, _, kind in sorted(events):
        if kind == "limit":
            if version >= key:
                return False
            continue
        if kind == "last_affected":
            if version > key:
                affected = False
            elif version < key:
                break
            continue
        if version < key:
            break
        affected = kind == "introduced"
    return affected


def _keyed(events: list[list[str]]) -> list[tuple[Version, int, str]] | None:
    out = []
    for kind, value in events:
        key = _event_key(kind, value)
        if key is None:
            return None
        out.append((key, EVENTS.index(kind), kind))
    return out


def affected(version: str, record: dict[str, Any]) -> bool | None:
    """Whether a version is affected, or None when the version or one of the record's ranges can't be compared."""
    if version in record.get("versions", ()):
        return True
    ranges = record.get("ranges", ())
    key = version_key(version)
    if key is None:
        return None if ranges else False
    unknown = False
    for events in ranges:
        keyed = _keyed(events)
        if keyed is None:
            unknown = True
        elif _in_range(key, keyed):
            return True
    return None if unknown else False


def describe(record: dict[str, Any]) -> str:
    """The affected ranges, briefly: `<1.0.0`, `>=2.0.0 <2.3.1`, and so on."""
    spans = []
    for events in record.get("ranges", ()):
        keyed = sorted(((_event_key(k, v) or LOWEST), EVENTS.index(k), k, v) for k, v in events)
        span: list[str] = []
        for _, _, kind, value in keyed:
            if kind == "introduced":
                span = [] if value == "0" else [f">={value}"]
            elif kind in ("fixed", "limit"):
                spans.append(" ".join([*span, f"<{value}"]))
                span = []
            elif kind == "last_affected":
                spans.append(" ".join([*span, f"<={value}"]))
                span = []
        if span or (keyed and keyed[-1][2] == "introduced"):
            spans.append(" ".join(span) or "every version")
    listed = len(record.get("versions", ()))
    if listed:
        spans.append(f"{listed} listed version{'s' if listed != 1 else ''}")
    return ", ".join(spans) or "no stated versions"


def first_fixed(version: str, record: dict[str, Any]) -> str | None:
    """The lowest fixed version above this one, if the record names one."""
    key = version_key(version)
    fixed = [(k, v) for events in record.get("ranges", ()) for kind, v in events if kind == "fixed"
             and (k := version_key(v)) is not None and (key is None or k > key)]  # fmt: skip
    return min(fixed)[1] if fixed else None


# ------------------------------------------------------------------ reading untrusted sources


def _text(value: Any, limit: int) -> str:
    return _CONTROL.sub(" ", value).strip()[:limit] if isinstance(value, str) else ""


def _strings(value: Any, count: int, limit: int) -> list[str]:
    items = value if isinstance(value, list) else []
    return [s for s in (_text(v, limit + 1) for v in items[:count]) if s and len(s) <= limit]


def _cvss(severity: Any) -> str | None:
    """A CVSS 3.x base vector from an OSV `severity` list, as 3.1 (the 3.0 base metrics and formula are the same)."""
    for entry in severity if isinstance(severity, list) else []:
        score = entry.get("score") if isinstance(entry, dict) else None
        if not isinstance(score, str) or not score.startswith(("CVSS:3.0/", "CVSS:3.1/")) or len(score) > 200:
            continue
        metrics = dict(part.partition(":")[::2] for part in score.split("/")[1:])
        if all(metrics.get(m) for m in _BASE):
            return "CVSS:3.1/" + "/".join(f"{m}:{metrics[m]}" for m in _BASE)
    return None


def compact(doc: dict[str, Any], ecosystems: tuple[str, ...] = ECOSYSTEMS) -> list[tuple[str, str, dict[str, Any]]]:
    """(ecosystem, package, record) for each package in the given ecosystems. Raises ValueError for a non-record."""
    advisory = doc.get("id")
    if not isinstance(advisory, str) or not ID.match(advisory):
        raise ValueError("not an OSV record: no valid id")
    extra = doc.get("database_specific") if isinstance(doc.get("database_specific"), dict) else {}
    base = {
        "id": advisory,
        "aliases": [a for a in _strings(doc.get("aliases"), 10, 128) if ID.match(a)],
        "summary": _text(doc.get("summary") or doc.get("details"), 300),
        "modified": _text(doc.get("modified"), 40),
        "withdrawn": _text(doc.get("withdrawn"), 40) or None,
        "label": _text(extra.get("severity"), 20) or None,  # the database's own rating, when it gives one
        "cwe": [c for c in _strings(extra.get("cwe_ids"), 10, 12) if CWE.match(c)],
    }
    packages: dict[tuple[str, str], dict[str, Any]] = {}
    for item in doc.get("affected") if isinstance(doc.get("affected"), list) else []:
        package = item.get("package") if isinstance(item, dict) else None
        if not isinstance(package, dict) or package.get("ecosystem") not in ecosystems:
            continue
        name = package.get("name")
        if not isinstance(name, str) or not 0 < len(name) <= 214 or _CONTROL.search(name):
            continue
        entry = packages.setdefault((package["ecosystem"], name), {**base, "cvss": None, "ranges": [], "versions": []})
        entry["cvss"] = entry["cvss"] or _cvss(doc.get("severity")) or _cvss(item.get("severity"))
        for r in (item.get("ranges") if isinstance(item.get("ranges"), list) else [])[:MAX_RANGES]:
            if not isinstance(r, dict) or r.get("type") not in ("SEMVER", "ECOSYSTEM"):
                continue  # GIT ranges name commits, which a bundled package doesn't carry
            events = [[k, v] for e in (r.get("events") if isinstance(r.get("events"), list) else [])[:MAX_EVENTS]
                      if isinstance(e, dict) and len(e) == 1 for k, v in e.items()
                      if k in EVENTS and isinstance(v, str) and 0 < len(v) <= 64]  # fmt: skip
            if events:
                entry["ranges"].append(events)
        entry["versions"] = sorted(set(entry["versions"]) | set(_strings(item.get("versions"), MAX_VERSIONS, 64)))
    return [(eco, name, record) for (eco, name), record in packages.items() if record["ranges"] or record["versions"]]


@dataclass
class ImportReport:
    source: str
    sha256: str = ""
    documents: int = 0  # files or members read
    records: int = 0  # advisories kept
    packages: int = 0  # (package, advisory) rows written
    other: int = 0  # advisories with no package in the imported ecosystems
    skipped: int = 0  # documents that weren't OSV records, or that a cap refused
    notes: list[str] = field(default_factory=list)


def _digest(source: Path, files: list[Path] | None) -> str:
    h = hashlib.sha256()
    if files is None:
        with open(source, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    for path in files:  # a folder: its files' names and hashes, in order
        h.update(f"{path.relative_to(source).as_posix()}\0{_digest(path, None)}\n".encode())
    return h.hexdigest()


def _folder(source: Path) -> list[Path]:
    found: list[Path] = []
    for here, dirs, names in os.walk(source, followlinks=False):
        dirs.sort()
        for name in sorted(names):
            path = Path(here) / name
            if path.suffix.lower() == ".json" and not path.is_symlink():
                found.append(path)
                if len(found) > MAX_FILES:
                    raise AdvisoryError(f"more than {MAX_FILES} files")
    return found


def _documents(source: Path, files: list[Path] | None, report: ImportReport) -> Iterator[bytes]:
    total = 0

    def counted(data: bytes) -> bytes:
        nonlocal total
        total += len(data)
        if total > MAX_TOTAL:
            raise AdvisoryError(f"more than {MAX_TOTAL // 1024**3} GiB of records")
        report.documents += 1
        return data

    if files is not None:
        for path in files:
            if path.stat().st_size > MAX_RECORD:
                report.skipped += 1
                continue
            yield counted(path.read_bytes())
        return
    if zipfile.is_zipfile(source):
        try:
            archive = zipfile.ZipFile(source)
        except (zipfile.BadZipFile, OSError) as exc:
            raise AdvisoryError(f"{source.name} isn't a readable zip archive: {exc}") from exc
        with archive:
            members = archive.infolist()
            if len(members) > MAX_FILES:
                raise AdvisoryError(f"more than {MAX_FILES} members")
            for info in members:  # read in memory one at a time; nothing is extracted
                if info.is_dir() or not info.filename.lower().endswith(".json"):
                    continue
                inflates = info.file_size > 1 << 20 and info.file_size > MAX_RATIO * max(info.compress_size, 1)
                if info.file_size > MAX_RECORD or inflates:
                    report.skipped += 1
                    continue
                try:
                    with archive.open(info) as handle:
                        data = handle.read(MAX_RECORD + 1)
                except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError, zlib.error):
                    report.skipped += 1  # damaged, encrypted, or compressed in a way the standard library can't read
                    continue
                if len(data) > MAX_RECORD:
                    report.skipped += 1
                    continue
                yield counted(data)
        return
    if source.stat().st_size > MAX_FILE:
        raise AdvisoryError(f"{source.name} is larger than {MAX_FILE // 1024**2} MiB; import a zip or a folder instead")
    yield counted(source.read_bytes())


def database(workspace: Path) -> Path:
    """The index, given the workspace folder (`.veritas`)."""
    return workspace / FOLDER / DATABASE


def import_advisories(workspace: Path, source: Path, ecosystems: tuple[str, ...] = ECOSYSTEMS) -> ImportReport:
    """Read a source into the index in one transaction: all of it, or, on an error, none of it."""
    if not source.exists():
        raise AdvisoryError(f"{source} doesn't exist")
    report = ImportReport(source.name)
    files = _folder(source) if source.is_dir() else None
    report.sha256 = _digest(source, files)
    folder = workspace / FOLDER
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    db = sqlite3.connect(database(workspace))
    try:
        db.executescript(_SCHEMA)
        with db:
            for data in _documents(source, files, report):
                try:
                    parsed = json.loads(data)
                except (ValueError, RecursionError):
                    report.skipped += 1
                    continue
                for doc in parsed if isinstance(parsed, list) else [parsed]:
                    try:
                        rows = compact(doc, ecosystems) if isinstance(doc, dict) else None
                    except ValueError:
                        rows = None
                    if rows is None:
                        report.skipped += 1
                    elif not rows:
                        report.other += 1
                    else:
                        report.records += 1
                        report.packages += len(rows)
                        db.executemany("INSERT OR REPLACE INTO advisories VALUES (?, ?, ?, ?, ?)",
                                       [(eco, name, rec["id"], json.dumps(rec, sort_keys=True), report.sha256)
                                        for eco, name, rec in rows])  # fmt: skip
            imported = datetime.now(UTC).isoformat(timespec="seconds")
            db.execute("INSERT OR REPLACE INTO sources VALUES (?, ?, ?, ?, ?)",
                       (report.sha256, source.name[:200], report.records, report.skipped, imported))  # fmt: skip
    except sqlite3.Error as exc:
        raise AdvisoryError(f"the advisory index couldn't be written: {exc}") from exc
    finally:
        db.close()
    if not report.records:
        report.notes.append(f"no advisories for {', '.join(ecosystems)} packages were found in {source.name}")
    return report


class Advisories:
    """The imported advisories, opened read-only for matching."""

    def __init__(self, workspace: Path):
        path = database(workspace)
        if not path.exists():
            raise FileNotFoundError(path)
        self._db = sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True)

    def for_package(self, ecosystem: str, name: str) -> list[dict[str, Any]]:
        rows = self._db.execute("SELECT record, source FROM advisories WHERE ecosystem = ? AND name = ? ORDER BY id",
                                (ecosystem, name))  # fmt: skip
        return [{**json.loads(record), "source": source} for record, source in rows]

    def summary(self) -> dict[str, Any]:
        (records,) = self._db.execute("SELECT COUNT(DISTINCT id) FROM advisories").fetchone()
        (packages,) = self._db.execute("SELECT COUNT(DISTINCT ecosystem || '/' || name) FROM advisories").fetchone()
        sources = [{"sha256": s, "name": n, "records": r, "skipped": k, "imported": t} for s, n, r, k, t in
                   self._db.execute("SELECT sha256, name, records, skipped, imported_at FROM sources "
                                    "ORDER BY imported_at")]  # fmt: skip
        return {"records": records, "packages": packages, "sources": sources}

    def close(self) -> None:
        self._db.close()


def open_advisories(workspace: Path) -> Advisories | None:
    try:
        return Advisories(workspace)
    except (FileNotFoundError, sqlite3.Error):
        return None


def summary(workspace: Path) -> dict[str, Any]:
    """What's imported, for the status command and the central page. Empty when nothing is."""
    store = open_advisories(workspace)
    if store is None:
        return {"records": 0, "packages": 0, "sources": []}
    try:
        return store.summary()
    except sqlite3.Error:
        return {"records": 0, "packages": 0, "sources": []}
    finally:
        store.close()
