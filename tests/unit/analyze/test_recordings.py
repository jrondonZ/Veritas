"""The vuln-notes charter end to end: the app's source and a recorded session, read together, and nothing raw kept."""

import asyncio
import json

import pytest

from veritas.analyze.charter import check_charter
from veritas.analyze.ground import compare_code
from veritas.analyze.runner import _run, local_launcher
from veritas.documents import load_yaml
from veritas.store import Workspace

RECORDING = "recordings/browse.har"


@pytest.fixture(scope="module")
def lab(repo_root):
    return repo_root / "labs" / "vuln-notes"


@pytest.fixture
def analysis(tmp_path, repo_root, lab, node):
    report = check_charter(lab / "veritas.charter.yaml")
    assert report.ok, report.errors
    ws = Workspace(tmp_path)
    launcher = local_launcher(repo_root, node)
    result = asyncio.run(_run(ws, report, report.charter, report.digest, repo_root, launcher, lambda a, b: None))
    yield ws, result
    ws.close()


def test_code_and_recording_together_yield_exactly_the_expected_candidates(analysis, lab):
    _, result = analysis
    assert result.outcome == "completed", result.document["limitations"]
    outcome = compare_code(result.code, load_yaml(lab / "expected-code-findings.yaml"))
    assert (outcome.precision, outcome.recall) == (1.0, 1.0), (outcome.unexpected, outcome.missed)
    assert outcome.look_alikes == []
    traffic = [f for f in result.code if f["file"] == RECORDING]
    assert {f["confirms_with"] for f in traffic if f["rule"] == "cookie-attributes"} == {
        "veritas.check.cookie-attributes"
    }


def test_no_credential_from_the_recording_is_kept_anywhere(analysis):
    ws, result = analysis
    leaked = [p for p in ws.root.rglob("*") if p.is_file() and b"vrt-fake" in p.read_bytes()]
    assert leaked == []
    run_dir = ws.runs_dir / result.run_id
    assert not any(RECORDING.rsplit("/", 1)[-1] in p.name for p in (run_dir / "inputs").iterdir())
    intake = [json.loads(line) for line in (run_dir / "audit.jsonl").read_text().splitlines()
              if json.loads(line)["type"] == "subject.intake"]  # fmt: skip
    stored = {e["path"]: e["stored"] for e in intake}
    assert stored[RECORDING] is False
    assert all(stored[p] for p in stored if p != RECORDING)


def test_the_recorded_endpoints_cross_as_an_interface(analysis):
    ws, result = analysis
    clean = json.loads((ws.runs_dir / result.run_id / "spec.json").read_text(encoding="utf-8"))
    (http,) = [i for i in clean["interfaces"] if i["id"] == "IF-http"]
    texts = " ".join(c["text"] for c in http["claims"])
    assert "`GET /api/notes/{id}` answered 200" in texts
    assert "`role` (string)" in texts  # the profile returns a field the API description doesn't list
    assert len(http["claims"]) == 10  # the app's endpoints; the CDN's stylesheet is catalogued, not specified
    (subject,) = [s for s in result.document["subjects"] if s["path"] == RECORDING]
    assert (subject["type"], subject["counts"], subject["evidence"]) == (
        "har", {"entries": 13, "endpoints": 11, "origins": 2}, None,
    )  # fmt: skip
