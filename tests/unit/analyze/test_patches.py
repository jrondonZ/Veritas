"""Patch drafts: a scripted patcher's edits are applied to a copy, diffed, and re-read by the same engine and rules."""

import asyncio
import json

import pytest

from veritas.analyze.charter import check_charter
from veritas.analyze.patches import PatchError, apply_edits, draft_patch
from veritas.analyze.runner import _run, local_launcher
from veritas.models.calls import ModelResult
from veritas.store import Workspace

SEARCH = 'page("Search", `<p>Results for: ${term}</p><p>No notes matched.</p>`));'  # handlers.search only
ESCAPED = 'page("Search", `<p>Results for: ${escapeHtml(term)}</p><p>No notes matched.</p>`));'


class ScriptedPatcher:
    """Answers the patcher role with fixed edits, after the same checks a real model's answer gets."""

    def __init__(self, edits, notes=""):
        self.edits, self.notes, self.tasks = edits, notes, []

    async def run(self, task):
        self.tasks.append(task)
        output = {"status": "answered", "reason": "none", "escalate": "none", "edits": self.edits, "notes": self.notes}
        problems = task.check(output)
        if problems:
            return ModelResult("invalid", task.role, reason="; ".join(problems))
        return ModelResult("answered", task.role, output=output)


@pytest.fixture
def analysis(tmp_path, repo_root, node):
    report = check_charter(repo_root / "labs" / "vuln-notes" / "veritas.charter.yaml")
    ws = Workspace(tmp_path)
    launcher = local_launcher(repo_root, node)
    result = asyncio.run(_run(ws, report, report.charter, report.digest, repo_root, launcher, lambda a, b: None))
    yield ws, result, launcher
    ws.close()


def finding_id(result, rule, function):
    return next(f["id"] for f in result.code if f["rule"] == rule and f["function"] == function)


def draft(analysis, repo_root, finding, edits):
    ws, result, launcher = analysis
    patcher = ScriptedPatcher(edits, notes="Encode the term for HTML.")
    outcome = asyncio.run(draft_patch(ws, result.run_id, finding, patcher, launcher, repo_root))
    return outcome, patcher


def test_a_real_fix_is_verified_and_left_for_review(analysis, repo_root):
    ws, result, _ = analysis
    l2 = finding_id(result, "html-from-input", "handlers.search")
    outcome, patcher = draft(analysis, repo_root, l2, [{"find": SEARCH, "replace": ESCAPED}])
    assert outcome.verified, outcome.verification
    assert f'+    send(res, 200, "text/html; charset=utf-8", {ESCAPED}' in outcome.diff
    folder = ws.runs_dir / result.run_id / "patches"
    record = json.loads((folder / f"{l2}.json").read_text(encoding="utf-8"))
    assert (record["status"], record["verified"], record["diff"]) == ("answered", True, f"{l2}.diff")
    assert "${term}</p><p>No notes" in (repo_root / "labs" / "vuln-notes" / "app" / "server.mjs").read_text("utf-8")
    events = [json.loads(e) for e in (ws.runs_dir / result.run_id / "audit.jsonl").read_text().splitlines()]
    assert [e["verified"] for e in events if e["type"] == "patch.draft"] == [True]
    prompt = "\n".join(m["content"] for m in patcher.tasks[0].prompt.messages())
    assert "Encode untrusted values for the HTML context" in prompt  # the rule's remediation
    assert ws.verify_run(result.run_id).ok


def test_a_patch_that_misses_or_adds_a_flaw_is_not_verified(analysis, repo_root):
    _, result, _ = analysis
    l2 = finding_id(result, "html-from-input", "handlers.search")
    cosmetic = [{"find": SEARCH, "replace": SEARCH.replace("No notes matched.", "Nothing matched.")}]
    missed, _ = draft(analysis, repo_root, l2, cosmetic)
    assert (missed.verified, missed.verification["finding_gone"]) == (False, False)
    worse = [{"find": SEARCH, "replace": ESCAPED + "\n    eval(term);"}]
    added, _ = draft(analysis, repo_root, l2, worse)
    assert added.verification["finding_gone"] is True
    assert added.verification["new_findings"] == ["dynamic-code in handlers.search"]
    assert not added.verified
    broken, _ = draft(analysis, repo_root, l2, [{"find": SEARCH, "replace": ESCAPED + " {{"}])
    assert (broken.verification["parses"], broken.verified) == (False, False)


def test_edits_must_name_text_that_occurs_exactly_once(analysis, repo_root):
    _, result, _ = analysis
    l2 = finding_id(result, "html-from-input", "handlers.search")
    ambiguous = [{"find": 'const term = url.searchParams.get("q") ?? "";', "replace": "const term = '';"}]
    outcome, _ = draft(analysis, repo_root, l2, ambiguous)
    assert outcome.status == "invalid"
    assert "occurs 2 times" in outcome.reason
    assert outcome.diff == ""
    with pytest.raises(PatchError, match="exactly once"):
        apply_edits("a b a", [{"find": "a", "replace": "c"}])
    assert (
        apply_edits("one two three", [{"find": "three", "replace": "3"}, {"find": "one", "replace": "1"}]) == "1 two 3"
    )


def test_only_owned_javascript_is_patched(analysis, repo_root):
    ws, result, _ = analysis
    recorded = next(f["id"] for f in result.code if f["file"] == "recordings/browse.har")
    with pytest.raises(PatchError, match="only findings in JavaScript source files"):
        draft(analysis, repo_root, recorded, [{"find": "x", "replace": "y"}])
    path = ws.runs_dir / result.run_id / "analysis.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["charter"]["basis"] = "interoperability"
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(PatchError, match="for code you own"):
        draft(analysis, repo_root, finding_id(result, "html-from-input", "handlers.search"), [])
