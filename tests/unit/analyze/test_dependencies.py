"""Bundled dependencies against imported advisories: the notes-desktop lab end to end, and the matcher's edges."""

from __future__ import annotations

import asyncio
import json

import pytest

from veritas.analyze.charter import check_charter
from veritas.analyze.dependencies import dependency_candidates
from veritas.analyze.ground import compare_code
from veritas.analyze.runner import _run, local_launcher
from veritas.documents import load_yaml
from veritas.findings.lint import lint_claims
from veritas.imports.osv import import_advisories
from veritas.store import Workspace


@pytest.fixture(scope="module")
def desktop(repo_root):
    return repo_root / "labs" / "notes-desktop"


def _analyze(root, repo_root, desktop, node):
    report = check_charter(desktop / "veritas.charter.yaml")
    assert report.ok, report.errors
    ws = Workspace(root)
    result = asyncio.run(_run(ws, report, report.charter, report.digest, repo_root, local_launcher(repo_root, node),
                              lambda a, b: None))  # fmt: skip
    return ws, result


def test_imported_advisories_turn_a_bundled_version_into_a_candidate(tmp_path, repo_root, desktop, node):
    imported = import_advisories(tmp_path / ".veritas", desktop / "advisories" / "lab-osv.json")
    ws, result = _analyze(tmp_path, repo_root, desktop, node)
    try:
        truth = load_yaml(desktop / "expected-code-findings.yaml")
        outcome = compare_code(result.code, {**truth, "expected": truth["expected"] + truth["with_advisories"]})
        assert (outcome.precision, outcome.recall, outcome.look_alikes) == (1.0, 1.0, [])
        (finding,) = [f for f in result.code if f["rule"] == "vulnerable-dependency"]
        assert finding["advisory"] == {"id": "VRT-LAB-0001", "aliases": [], "source": imported.sha256}
        assert finding["if_confirmed"]["cvss"] == {"vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", "score": 6.1}
        assert finding["cwe"] == ["CWE-1395", "CWE-79"]
        kinds = [c["kind"] for c in finding["claims"]]
        assert kinds == ["observed", "observed", "inferred", "limitation", "guidance"]
        observed = [c["id"] for c in finding["claims"] if c["kind"] == "observed"]
        assert finding["claims"][2]["based_on"] == observed
        assert "1.0.0 or later" in finding["claims"][4]["text"]
        assert lint_claims("code", finding["claims"], ws.evidence_ids(result.run_id).__contains__) == []

        assert result.document["dependencies"] == {"bundled": 3, "checked": True, "matched": 1,
                                                   "sources": [imported.sha256]}  # fmt: skip
        run_dir = ws.runs_dir / result.run_id
        events = [json.loads(line) for line in (run_dir / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [e["matched"] for e in events if e["type"] == "advisories.match"] == [1]
        assert "1 match(es)" in (run_dir / "report.md").read_text(encoding="utf-8")
        sarif = json.loads((run_dir / "code-findings.sarif").read_text(encoding="utf-8"))
        assert "vulnerable-dependency" in {r["id"] for r in sarif["runs"][0]["tool"]["driver"]["rules"]}
        assert ws.verify_run(result.run_id).ok
    finally:
        ws.close()


def test_without_advisories_the_gap_is_stated(tmp_path, repo_root, desktop, node):
    ws, result = _analyze(tmp_path, repo_root, desktop, node)
    try:
        assert not [f for f in result.code if f["rule"] == "vulnerable-dependency"]
        assert any("not checked for known vulnerabilities" in t for t in result.document["limitations"])
        assert result.document["dependencies"] == {"bundled": 3, "checked": False}
    finally:
        ws.close()


class _Store:
    def __init__(self, records):
        self.records = records

    def for_package(self, ecosystem, name):
        return [{**r, "source": "ab" * 32} for r in self.records.get(name, [])]


def test_what_cannot_be_matched_is_said_not_skipped():
    subjects = [{"path": "app.asar", "facts": "E-0123456789ab", "dependencies": [
        {"name": "odd", "version": "1.0.0", "path": "node_modules/odd/package.json"},
        {"name": "bare", "version": None, "path": "node_modules/bare/package.json"},
    ]}]  # fmt: skip
    store = _Store({"odd": [{"id": "VRT-TEST-9", "aliases": [], "summary": "", "ranges": [[["fixed", "soon"]]],
                             "versions": [], "cwe": []}]})  # fmt: skip
    found, notes, info = dependency_candidates(subjects, store, lambda data, media, source: "E-ffffffffffff")  # type: ignore[arg-type]
    assert found == []
    assert notes == ["1 bundled dependency has no version, so it couldn't be checked against advisories",
                     "1 advisory range couldn't be compared with a bundled version: odd 1.0.0 (VRT-TEST-9)"]  # fmt: skip
    assert info == {"bundled": 2, "checked": True, "matched": 0, "sources": []}
