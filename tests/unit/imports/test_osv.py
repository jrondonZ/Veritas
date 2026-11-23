"""Offline OSV advisories: version precedence, range evaluation, and imports of untrusted files under caps."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from veritas.imports import osv
from veritas.imports.osv import AdvisoryError, affected, compact, describe, first_fixed, import_advisories, version_key

FIXTURE = Path(__file__).resolve().parents[3] / "labs" / "notes-desktop" / "advisories" / "lab-osv.json"


def record(*ranges: list[list[str]], versions: tuple[str, ...] = ()) -> dict:
    return {"id": "VRT-TEST-1", "ranges": [list(r) for r in ranges], "versions": list(versions)}


def osv_doc(advisory: str = "VRT-TEST-1", name: str = "pkg", events: list | None = None, **extra: object) -> dict:
    events = events or [{"introduced": "0"}, {"fixed": "1.0.0"}]
    return {"id": advisory, "affected": [{"package": {"ecosystem": "npm", "name": name},
                                          "ranges": [{"type": "SEMVER", "events": events}]}], **extra}  # fmt: skip


def test_versions_sort_by_semver_precedence() -> None:
    ordered = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11",
               "1.0.0-rc.1", "1.0.0", "1.0.1", "1.10.0", "2.0.0"]  # the Semantic Versioning 2.0.0 example, and more
    keys = [version_key(v) for v in ordered]
    assert keys == sorted(keys)  # type: ignore[type-var]
    assert version_key("1.0.0+build.7") == version_key("1.0.0") == version_key("v1.0.0")
    assert version_key("1.2") == version_key("1.2.0")
    for bad in ("", "latest", "1.0.0-", "1..0", "x" * 80, "1.0.0 || 2.0.0"):
        assert version_key(bad) is None, bad


def test_ranges_follow_the_osv_evaluation_rules() -> None:
    below = record([["introduced", "0"], ["fixed", "1.0.0"]])
    assert [affected(v, below) for v in ("0.9.4", "1.0.0-rc.1", "1.0.0", "1.2.0")] == [True, True, False, False]
    inclusive = record([["introduced", "2.0.0"], ["last_affected", "2.1.0"]])
    assert [affected(v, inclusive) for v in ("1.9.9", "2.0.0", "2.1.0", "2.1.1")] == [False, True, True, False]
    two = record([["introduced", "1.0.0"], ["fixed", "1.5.0"], ["introduced", "2.0.0"], ["fixed", "2.3.0"]])
    assert [affected(v, two) for v in ("0.1.0", "1.2.0", "1.7.0", "2.1.0", "2.3.0")] == [False, True, False, True, False]
    unsorted = record([["fixed", "1.5.0"], ["introduced", "1.0.0"]])  # events may come in any order
    assert affected("1.2.0", unsorted) is True
    limited = record([["introduced", "0"], ["limit", "3.0.0"]])
    assert (affected("2.9.0", limited), affected("3.0.0", limited)) == (True, False)
    open_ended = record([["introduced", "4.0.0"]])
    assert (affected("3.9.9", open_ended), affected("9.0.0", open_ended)) == (False, True)
    assert affected("0.0.1", record(versions=("0.0.1",))) is True  # an explicit list matches exactly


def test_what_cannot_be_compared_is_unknown_not_safe() -> None:
    assert affected("not-a-version", record([["introduced", "0"]])) is None
    assert affected("1.0.0", record([["introduced", "0"], ["fixed", "next"]])) is None
    assert affected("1.0.0", record([["introduced", "0"], ["fixed", "next"]], [["introduced", "0"]])) is True
    assert affected("not-a-version", record()) is False  # nothing to compare against


def test_ranges_read_briefly_and_name_the_nearest_fix() -> None:
    assert describe(record([["introduced", "0"], ["fixed", "1.0.0"]])) == "<1.0.0"
    assert describe(record([["introduced", "0.4.0"], ["fixed", "0.4.3"]])) == ">=0.4.0 <0.4.3"
    assert describe(record([["introduced", "2.0.0"], ["last_affected", "2.1.0"]])) == ">=2.0.0 <=2.1.0"
    assert describe(record([["introduced", "0"]], versions=("0.0.1",))) == "every version, 1 listed version"
    two = record([["introduced", "1.0.0"], ["fixed", "1.5.2"]], [["introduced", "2.0.0"], ["fixed", "2.3.1"]])
    assert (first_fixed("1.2.0", two), first_fixed("2.1.0", two), first_fixed("3.0.0", two)) == ("1.5.2", "2.3.1", None)


def test_only_bounded_fields_from_the_imported_ecosystems_are_kept() -> None:
    doc = osv_doc(
        summary="line one\nline two\x1b[31m", aliases=["CVE-2026-0001", "bad alias with spaces", "x" * 200],
        severity=[{"type": "CVSS_V3", "score": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:P/RL:O"}],
        database_specific={"severity": "HIGH", "cwe_ids": ["CWE-79", "79; DROP"]},
    )  # fmt: skip
    doc["affected"] += [
        {"package": {"ecosystem": "npm", "name": "pkg"}, "versions": ["0.0.1", "y" * 100]},  # merges into one row
        {"package": {"ecosystem": "PyPI", "name": "pkg"}, "versions": ["1.0"]},
        {"package": {"ecosystem": "npm", "name": "git-only"}, "ranges": [{"type": "GIT", "events": [{"fixed": "ab"}]}]},
    ]
    ((ecosystem, name, kept),) = compact(doc)
    assert (ecosystem, name) == ("npm", "pkg")
    assert kept["summary"] == "line one line two [31m"
    assert kept["aliases"] == ["CVE-2026-0001"]
    assert kept["cvss"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"  # 3.0 base metrics, temporal ones dropped
    assert (kept["label"], kept["cwe"], kept["versions"]) == ("HIGH", ["CWE-79"], ["0.0.1"])
    with pytest.raises(ValueError, match="no valid id"):
        compact({"id": "../../etc", "affected": []})
    assert compact(osv_doc(), ("PyPI",)) == []


def test_the_lab_advisories_import_and_record_their_source(tmp_path: Path) -> None:
    report = import_advisories(tmp_path, FIXTURE)
    assert (report.documents, report.records, report.other, report.skipped) == (1, 3, 1, 0)
    assert report.sha256 == hashlib.sha256(FIXTURE.read_bytes()).hexdigest()
    store = osv.open_advisories(tmp_path)
    assert store is not None
    try:
        assert [r["id"] for r in store.for_package("npm", "lab-markdown")] == ["VRT-LAB-0001", "VRT-LAB-0003"]
        assert store.for_package("npm", "lab-markdown")[0]["source"] == report.sha256
        assert store.for_package("PyPI", "lab-markdown") == []
    finally:
        store.close()
    info = osv.summary(tmp_path)
    assert (info["records"], info["packages"], [s["sha256"] for s in info["sources"]]) == (3, 2, [report.sha256])


def test_a_newer_export_replaces_records_with_the_same_id(tmp_path: Path) -> None:
    first, second = tmp_path / "a.json", tmp_path / "b.json"
    first.write_text(json.dumps(osv_doc(summary="old")), encoding="utf-8")
    second.write_text(json.dumps([osv_doc(summary="new")]), encoding="utf-8")
    import_advisories(tmp_path / "ws", first)
    import_advisories(tmp_path / "ws", second)
    store = osv.open_advisories(tmp_path / "ws")
    assert store is not None
    try:
        assert [r["summary"] for r in store.for_package("npm", "pkg")] == ["new"]
        assert len(store.summary()["sources"]) == 2
    finally:
        store.close()


def test_zip_exports_are_read_in_memory_under_caps(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(osv, "MAX_RECORD", 2 * 1024 * 1024)
    export = tmp_path / "all.zip"
    with zipfile.ZipFile(export, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("VRT-TEST-1.json", json.dumps(osv_doc()))
        z.writestr("README.txt", "not a record")  # not JSON by name: ignored
        z.writestr("broken.json", "{not json")
        z.writestr("deep.json", "[" * 100_000)  # parses only by recursing past the limit
        z.writestr("bomb.json", " " * (3 * 1024 * 1024))  # larger than the member cap, and inflates enormously
        z.writestr("ratio.json", "[" + " " * (1536 * 1024) + "]")  # under the cap, but past the ratio limit
        z.writestr("../../outside.json", json.dumps(osv_doc("VRT-TEST-2")))  # names are never paths: read, not written
    report = import_advisories(tmp_path / "ws", export)
    assert (report.records, report.skipped) == (2, 4)
    assert not (tmp_path / "outside.json").exists()
    assert sorted(p.name for p in (tmp_path / "ws").rglob("*")) == ["advisories", "advisories.db"]


def test_folders_are_walked_without_following_links(tmp_path: Path) -> None:
    folder = tmp_path / "osv"
    (folder / "npm").mkdir(parents=True)
    (folder / "npm" / "a.json").write_text(json.dumps(osv_doc("VRT-TEST-1")), encoding="utf-8")
    (folder / "b.json").write_text(json.dumps(osv_doc("VRT-TEST-2", "other")), encoding="utf-8")
    (folder / "notes.md").write_text("ignored", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "c.json").write_text(json.dumps(osv_doc("VRT-TEST-3", "third")), encoding="utf-8")
    try:
        (folder / "link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pass  # creating links needs a privilege on some systems; the walk is the same either way
    report = import_advisories(tmp_path / "ws", folder)
    assert (report.documents, report.records) == (2, 2)


def test_a_failed_import_changes_nothing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    good = tmp_path / "good.json"
    good.write_text(json.dumps(osv_doc()), encoding="utf-8")
    import_advisories(tmp_path / "ws", good)
    big = tmp_path / "big.json"
    big.write_text(json.dumps([osv_doc(f"VRT-TEST-{n}", f"p{n}") for n in range(50)]), encoding="utf-8")
    monkeypatch.setattr(osv, "MAX_FILE", 1024)
    with pytest.raises(AdvisoryError, match="larger than"):
        import_advisories(tmp_path / "ws", big)
    folder = tmp_path / "osv"
    folder.mkdir()
    for n in (1, 2):  # the first file is written to the index before the second goes past the total
        (folder / f"{n}.json").write_text(json.dumps(osv_doc(f"VRT-TEST-{n + 10}", f"q{n}")), encoding="utf-8")
    monkeypatch.setattr(osv, "MAX_TOTAL", (folder / "1.json").stat().st_size + 10)
    with pytest.raises(AdvisoryError, match="GiB of records"):
        import_advisories(tmp_path / "ws", folder)
    db = sqlite3.connect(osv.database(tmp_path / "ws"))
    try:
        assert db.execute("SELECT COUNT(*) FROM advisories").fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM sources").fetchone() == (1,)
    finally:
        db.close()
    with pytest.raises(AdvisoryError, match="doesn't exist"):
        import_advisories(tmp_path / "ws", tmp_path / "missing.zip")
