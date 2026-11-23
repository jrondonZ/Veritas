"""The Analyze pipeline end to end in a throwaway workspace, then the clean room: refusals, verification, drafts.

The human steps stay human. The tests call the pipeline after its acknowledgment check, and
they record a spec approval only in a temporary workspace, as a store operation.
"""

import asyncio
import json
import re

import pytest

from veritas.analyze.charter import check_charter
from veritas.analyze.cleanroom import DirtyInput, NotApproved, draft, load_approved, verify
from veritas.analyze.runner import AnalyzeError, AnalyzeOptions, _run, analyze, local_launcher
from veritas.models.calls import ModelResult
from veritas.store import Workspace

RENAMES = {
    **{"crc32": "c32", "crcTable": "tbl", "checkLicense": "chk", "decodeText": "dt", "decodeSection": "ds"},
    **{"encodeSection": "es", "MAGIC": "MG", "HEADER_SIZE": "HS", "SECTION_HEADER_SIZE": "SHS", "TRAILER_SIZE": "TS"},
    "VERSION": "VV",
}
PARTIAL = (
    "export function readLex(bytes) {\n"
    "  if (bytes[0] !== 0x4c) throw Object.assign(new Error(), { code: 'LEX_BAD_MAGIC' });\n"
    "  return {};\n"
    "}\n"
)


@pytest.fixture
def analysis(tmp_path, repo_root, lexfmt, node):
    report = check_charter(lexfmt / "veritas.charter.yaml")
    ws = Workspace(tmp_path)
    launcher = local_launcher(repo_root, node)
    result = asyncio.run(_run(ws, report, report.charter, report.digest, repo_root, launcher, lambda a, b: None))
    yield ws, result
    ws.close()


@pytest.fixture
def harness(repo_root, node):
    script = str(repo_root / "plugins" / "conformance-js" / "harness.mjs")
    return lambda impl, samples: ([node, script], {"VERITAS_IMPL": str(impl), "VERITAS_SAMPLES": str(samples)})


@pytest.fixture
def approved(analysis):
    ws, result = analysis
    ws.approve_spec(result.run_id, result.clean["digest"])  # a store operation in a temporary workspace
    return load_approved(ws, result.run_id)


def implementation(tmp_path, name, source):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "index.mjs").write_text(source, encoding="utf-8")
    return folder


def test_analysis_writes_a_clean_spec_and_a_verifiable_audit(analysis):
    ws, result = analysis
    run_dir = ws.runs_dir / result.run_id
    assert (result.outcome, result.document["spec"]["claims"]) == ("completed", 24)
    clean_text = (run_dir / "spec.json").read_text(encoding="utf-8")
    assert json.loads(clean_text)["digest"] == result.clean["digest"]
    assert not re.search(r"E-[0-9a-f]{12}", clean_text)  # no evidence reference crosses
    assert len(ws.evidence_ids(result.run_id)) == 2  # the subject and its Program Model record
    assert ws.verify_run(result.run_id).ok
    events = [json.loads(line)["type"] for line in (run_dir / "audit.jsonl").read_text().splitlines()]
    assert events == ["run.start", "subject.intake", "engine.facts", "code.findings", "spec.draft", "run.end"]
    assert "## Behavior spec" in (run_dir / "report.md").read_text(encoding="utf-8")


def test_an_unacknowledged_charter_does_not_run(tmp_path, repo_root, lexfmt, node):
    options = AnalyzeOptions(launcher=local_launcher(repo_root, node))
    with pytest.raises(AnalyzeError, match="not acknowledged"):
        asyncio.run(analyze(lexfmt / "veritas.charter.yaml", tmp_path, options))


def test_a_spec_enters_a_clean_room_only_after_approval(analysis):
    ws, result = analysis
    with pytest.raises(NotApproved, match="not approved"):
        load_approved(ws, result.run_id)


def test_the_subject_cannot_pose_as_an_implementation(analysis, approved, harness, tmp_path, lexfmt):
    ws, _ = analysis
    subject = (lexfmt / "dist" / "lexfmt.js").read_bytes()
    exact = tmp_path / "exact"
    exact.mkdir()
    (exact / "index.mjs").write_bytes(subject)
    with pytest.raises(DirtyInput, match="same content as a subject"):
        verify(ws, approved, exact, "index.mjs", harness, "verify-1")
    # A byte-level change gets past the hash check; the similarity audit still catches the copy.
    crlf = tmp_path / "crlf"
    crlf.mkdir()
    (crlf / "index.mjs").write_bytes(subject.replace(b"\n", b"\r\n"))
    result = verify(ws, approved, crlf, "index.mjs", harness, "verify-2")
    assert result.passed == 12
    assert result.similarity["similar"]
    assert not result.verified


def test_a_renamed_copy_passes_the_vectors_but_fails_the_similarity_audit(
    analysis, approved, harness, tmp_path, lexfmt
):
    ws, _ = analysis
    source = (lexfmt / "dist" / "lexfmt.js").read_text(encoding="utf-8")
    for old, new in RENAMES.items():
        source = re.sub(rf"\b{old}\b", new, source)
    result = verify(ws, approved, implementation(tmp_path, "renamed", source), "index.mjs", harness, "verify-1")
    assert (result.passed, result.total) == (12, 12)
    assert result.similarity["similar"]
    assert result.similarity["overall"] > 0.9
    assert not result.verified


def test_an_independent_implementation_is_verified(analysis, approved, harness, repo_root):
    ws, _ = analysis
    fixture = repo_root / "tests" / "unit" / "analyze" / "fixtures" / "lexfmt-alt"
    result = verify(ws, approved, fixture, "index.mjs", harness, "verify-1")
    assert (result.passed, result.total, result.loaded) == (12, 12, True), result.results
    assert not result.similarity["similar"], result.similarity
    assert result.verified
    context = [json.loads(line) for line in (approved.run.dir / "audit.jsonl").read_text().splitlines()
               if json.loads(line)["type"] == "cleanroom.context"][-1]  # fmt: skip
    assert {i["role"] for i in context["inputs"]} == {"spec", "sample", "implementation"}
    subject_hashes = {s["sha256"] for s in approved.document["subjects"]}
    assert not subject_hashes & {i["sha256"] for i in context["inputs"]}


def test_a_partial_implementation_is_not_verified(analysis, approved, harness, tmp_path):
    ws, _ = analysis
    result = verify(ws, approved, implementation(tmp_path, "partial", PARTIAL), "index.mjs", harness, "verify-1")
    assert result.passed < 3
    assert not result.verified
    assert any("vector minimal" in line for line in result.clean_feedback())
    missing = verify(
        ws, approved, implementation(tmp_path, "empty", "export const x = 1;\n"), "index.mjs", harness, "v2"
    )
    assert (missing.loaded, missing.passed) == (False, 0)
    assert "does not export a function named readLex" in missing.error


class ScriptedImplementer:
    """Answers the implementer role with a fixed module and records what it was asked."""

    def __init__(self, module):
        self.module, self.tasks = module, []

    async def run(self, task):
        self.tasks.append(task)
        output = {"status": "answered", "reason": "none", "escalate": "none", "module": self.module, "notes": ""}
        assert task.check(output) == []
        return ModelResult("answered", task.role, output=output)


def test_a_draft_is_written_from_clean_inputs_only_and_verified(analysis, approved, harness, repo_root):
    ws, _ = analysis
    module = (repo_root / "tests" / "unit" / "analyze" / "fixtures" / "lexfmt-alt" / "index.mjs").read_text(
        encoding="utf-8"
    )
    service = ScriptedImplementer(module)
    drafts = asyncio.run(draft(ws, approved, service, harness, rounds=2))
    assert [(d.task, d.status, d.verification.verified) for d in drafts] == [("draft-1", "answered", True)]
    prompt = "\n".join(m["content"] for m in service.tasks[0].prompt.messages())
    assert "Export: readLex(bytes)" in prompt  # the spec
    assert "4c 45 58 01" in prompt  # and the operator's samples
    assert not re.search(r"E-[0-9a-f]{12}", prompt)
    assert not any(name in prompt for name in ("checkLicense", "decodeSection", "crc32", "crcTable", "HEADER_SIZE"))


def test_the_implementer_check_refuses_forbidden_code(analysis, approved):
    from veritas.agents.implementer import task

    samples = {v["sample"]: b"" for v in approved.clean["conformance"]["vectors"]}
    check = task(approved.clean, samples).check
    bad = {"module": "import fs from 'node:fs';\nexport function other() {}", "status": "answered"}
    assert check(bad) == [
        "the module must export a function named readLex",
        "the module uses what the clean room forbids: import",
    ]
