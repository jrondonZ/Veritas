"""Electron archives: the notes-desktop lab against its ground truth, end to end, and archives built to mislead."""

import asyncio
import json
import struct

import pytest

from veritas.analyze.charter import check_charter
from veritas.analyze.ground import compare_code
from veritas.analyze.intake import Subject
from veritas.analyze.runner import _archive, _run, local_launcher
from veritas.analyze.sbom import purl
from veritas.analyze.security import code_findings
from veritas.analyze.sources import SourceError, member_texts
from veritas.core.canonical import sha256_hex
from veritas.documents import load_yaml
from veritas.store import Workspace

ARCHIVE = "dist/app.asar"


def asar(files: dict[str, bytes] | None = None, index: dict | None = None) -> bytes:
    """Electron's layout: a pickle holding the header's size, the header pickle with the JSON index, then contents."""
    tree: dict = {}
    data = b""
    for path, content in sorted((files or {}).items()):
        node = tree
        *dirs, name = path.split("/")
        for d in dirs:
            node = node.setdefault(d, {"files": {}})["files"]
        node[name] = {"size": len(content), "offset": str(len(data))}
        data += content
    raw = json.dumps(index if index is not None else {"files": tree}).encode()
    pad = (4 - len(raw) % 4) % 4
    payload = 4 + len(raw) + pad
    return struct.pack("<4I", 4, 4 + payload, payload, len(raw)) + raw + b"\0" * pad + data


@pytest.fixture(scope="module")
def desktop(repo_root):
    return repo_root / "labs" / "notes-desktop"


@pytest.fixture(scope="module")
def desktop_facts(run_engine, desktop):
    sha = sha256_hex((desktop / ARCHIVE).read_bytes())
    (result,) = run_engine(desktop / "dist", [{"path": "app.asar", "sha256": sha}])
    assert "error" not in result, result.get("error")
    return Subject(ARCHIVE, sha, 0, "asar", "app.asar"), result


def test_the_packed_app_yields_exactly_the_expected_candidates(desktop_facts, desktop):
    subject, result = desktop_facts
    models, _, _ = _archive(subject, "E-0123456789ab", result)
    found = code_findings(models)
    truth = load_yaml(desktop / "expected-code-findings.yaml")
    outcome = compare_code(found, truth)
    assert (outcome.precision, outcome.recall) == (1.0, 1.0), (outcome.unexpected, outcome.missed)
    assert outcome.look_alikes == []
    assert len(found) == len(truth["expected"])


def test_the_archive_is_read_member_by_member_and_says_what_it_left_out(desktop_facts, desktop):
    subject, result = desktop_facts
    models, extra, notes = _archive(subject, "E-0123456789ab", result)
    assert [m.path for m in models] == [ARCHIVE] + [f"{ARCHIVE}!/{n}" for n in ("main.js", "preload.js", "renderer.js")]
    assert extra["counts"] == {"members": 3, "pages": 3, "dependencies": 3}
    assert notes == [f"{ARCHIVE}: 1 file(s) stored unpacked next to the archive, so not analyzed"]
    truth = load_yaml(desktop / "expected-code-findings.yaml")
    assert extra["dependencies"] == truth["dependencies"]
    assert extra["package"] == {"name": "notes-desktop-lab", "version": "0.0.1", "main": "main.js"}
    # Each member's recorded range holds exactly the bytes the engine analyzed.
    texts = member_texts(desktop / ARCHIVE, extra["members"])
    assert texts[0] == (desktop / "app" / "main.js").read_text(encoding="utf-8")


def test_a_member_record_that_does_not_match_the_bytes_is_refused(desktop_facts, desktop):
    _, result = desktop_facts
    member = {k: result["members"][0][k] for k in ("path", "offset", "size", "sha256")}
    with pytest.raises(SourceError, match="doesn't match"):
        member_texts(desktop / ARCHIVE, [{**member, "offset": member["offset"] + 1}])
    with pytest.raises(SourceError, match="outside the archive"):
        member_texts(desktop / ARCHIVE, [{**member, "size": 10**9}])


def test_names_and_offsets_from_the_archive_are_not_trusted(tmp_path, run_engine):
    index = {
        "files": {
            "..": {"files": {"evil.js": {"size": 3, "offset": "0"}}},
            "a\\b.js": {"size": 3, "offset": "0"},
            "far.js": {"size": 3, "offset": "999999"},
            "neg.js": {"size": 3, "offset": "-3"},
            "ok.js": {"size": 3, "offset": "0"},
        }
    }
    (tmp_path / "trick.asar").write_bytes(asar(index=index) + b"1;\n")
    (result,) = run_engine(
        tmp_path, [{"path": "trick.asar", "sha256": sha256_hex((tmp_path / "trick.asar").read_bytes())}]
    )
    assert [m["path"] for m in result["members"]] == ["ok.js"]
    assert result["refused"] == 4


def test_a_deep_tree_is_cut_off_and_counted(tmp_path, run_engine):
    node: dict = {"deep.js": {"size": 3, "offset": "0"}}
    for _ in range(70):
        node = {"d": {"files": node}}
    (tmp_path / "deep.asar").write_bytes(asar(index={"files": node}) + b"1;\n")
    (result,) = run_engine(
        tmp_path, [{"path": "deep.asar", "sha256": sha256_hex((tmp_path / "deep.asar").read_bytes())}]
    )
    assert (result["members"], result["refused"]) == ([], 1)


def test_a_file_that_only_claims_to_be_an_archive_is_not_read_as_one(tmp_path, run_engine):
    (tmp_path / "fake.asar").write_bytes(b"\x04\x00\x00\x00not an archive")
    (result,) = run_engine(
        tmp_path, [{"path": "fake.asar", "sha256": sha256_hex((tmp_path / "fake.asar").read_bytes())}]
    )
    assert result["error"].startswith("parse failed")


def test_a_csp_set_by_the_apps_code_counts(tmp_path, run_engine):
    files = {
        "index.html": b"<!doctype html><title>x</title>",
        "main.js": b"session.defaultSession.webRequest.onHeadersReceived((d, cb) => cb({ responseHeaders: "
        b"{ ...d.responseHeaders, 'Content-Security-Policy': [\"default-src 'self'\"] } }));\n",
    }
    (tmp_path / "app.asar").write_bytes(asar(files))
    (result,) = run_engine(tmp_path, [{"path": "app.asar", "sha256": sha256_hex((tmp_path / "app.asar").read_bytes())}])
    models, _, _ = _archive(Subject("app.asar", result["sha256"], 0, "asar", "app.asar"), "E-0123456789ab", result)
    assert result["csp_in_code"] is True
    assert [f["rule"] for f in code_findings(models)] == []


def test_package_urls_follow_the_purl_spec():
    assert purl("@lab/storage", "0.3.1") == "pkg:npm/%40lab/storage@0.3.1"
    assert purl("lab-markdown", None) == "pkg:npm/lab-markdown"


@pytest.fixture
def desktop_run(tmp_path, repo_root, desktop, node):
    report = check_charter(desktop / "veritas.charter.yaml")
    assert report.ok, report.errors
    ws = Workspace(tmp_path)
    launcher = local_launcher(repo_root, node)
    result = asyncio.run(_run(ws, report, report.charter, report.digest, repo_root, launcher, lambda a, b: None))
    yield ws, result
    ws.close()


def test_an_analysis_of_the_packed_app_writes_findings_an_inventory_and_its_gaps(desktop_run, desktop):
    ws, result = desktop_run
    run_dir = ws.runs_dir / result.run_id
    assert result.outcome == "completed_with_gaps"
    assert any("stored unpacked" in text for text in result.document["limitations"])
    (subject,) = result.document["subjects"]
    assert (subject["type"], subject["counts"]["members"], len(subject["members"])) == ("asar", 3, 3)
    truth = load_yaml(desktop / "expected-code-findings.yaml")
    outcome = compare_code(result.code, truth)
    assert (outcome.precision, outcome.recall, outcome.look_alikes) == (1.0, 1.0, [])

    sbom = json.loads((run_dir / "sbom.cdx.json").read_text(encoding="utf-8"))
    assert (sbom["bomFormat"], sbom["specVersion"]) == ("CycloneDX", "1.5")
    assert [c["purl"] for c in sbom["components"]] == [
        "pkg:npm/%40lab/storage@0.3.1", "pkg:npm/lab-markdown@0.9.4", "pkg:npm/lab-markdown@1.2.0",
    ]  # fmt: skip

    sarif = json.loads((run_dir / "code-findings.sarif").read_text(encoding="utf-8"))
    locations = {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]: r["locations"][0]["physicalLocation"]
                 for r in sarif["runs"][0]["results"]}  # fmt: skip
    assert "region" not in locations[f"{ARCHIVE}!/index.html"]  # a finding about the whole page
    assert locations[f"{ARCHIVE}!/renderer.js"]["region"]["startLine"] > 0

    report = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "## Bundled dependencies" in report
    assert f"`{ARCHIVE}!/index.html`" in report
    assert ws.verify_run(result.run_id).ok
