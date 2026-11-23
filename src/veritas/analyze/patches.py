"""Patch drafts (docs/architecture.md §8.1 stage 10): a model's fix for one code finding, checked before review.

A draft is never applied to the operator's tree. The kernel applies its edits to a copy of
the owned subject and writes a unified diff for review. Then it reads the patched copy with
the same engine and rules:

- it still parses;
- the finding is gone: its rule no longer fires in that function;
- nothing new: no rule fires that didn't before.

Only a draft that passes all three is verified. Even then, a person reviews it and applies
it with their own tools.
"""

from __future__ import annotations

import difflib
import json
import secrets
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..agents import patcher
from ..core.canonical import sha256_hex
from ..models.calls import ModelService
from ..plugins.manifest import load_manifest
from ..store import Workspace
from .intake import Subject
from .program import FileModel
from .runner import ENGINES, Launcher, _engine
from .security import RULES, code_findings


class PatchError(Exception):
    """A draft can't be made for this finding."""


@dataclass
class PatchDraft:
    finding: str
    status: str  # the model result's status, or "rejected" when its edits fail the kernel's checks
    reason: str = ""
    diff: str = ""
    notes: str = ""
    verification: dict[str, Any] = field(default_factory=dict)

    @property
    def verified(self) -> bool:
        v = self.verification
        return bool(v) and v.get("parses") is True and v.get("finding_gone") is True and not v.get("new_findings")


def apply_edits(source: str, edits: list[dict[str, str]]) -> str:
    """Each edit's text must occur exactly once; edits apply from the end so earlier offsets hold."""
    located = []
    for i, edit in enumerate(edits):
        if source.count(edit["find"]) != 1:
            raise PatchError(f"edit {i + 1}: its text doesn't occur exactly once in the file")
        located.append((source.find(edit["find"]), edit))
    for start, edit in sorted(located, key=lambda x: x[0], reverse=True):
        source = source[:start] + edit["replace"] + source[start + len(edit["find"]) :]
    return source


def unified(path: str, before: str, after: str) -> str:
    return "".join(difflib.unified_diff(before.splitlines(keepends=True), after.splitlines(keepends=True),
                                        f"a/{path}", f"b/{path}"))  # fmt: skip


def _key(f: dict[str, Any]) -> tuple[str, str | None]:
    return f["rule"], f.get("function")


async def _reread(
    root: Path, path: str, text: str, launcher: Launcher, sandbox: str
) -> tuple[bool, list[dict[str, Any]]]:
    """The patched copy, read by the same engine and rules as the subject was."""
    data = text.encode("utf-8")
    with tempfile.TemporaryDirectory(prefix="vrt-patch-") as tmp:
        inputs = Path(tmp)
        staged = f"{sha256_hex(data)[:16]}-{Path(path).name}"
        (inputs / staged).write_bytes(data)
        subject = Subject(path, sha256_hex(data), len(data), "javascript", staged)
        manifest = load_manifest(root / ENGINES["javascript"].manifest)
        (result,) = await _engine("javascript", [subject], manifest, launcher(sandbox, "javascript", manifest, inputs))
    if result.get("error"):
        return False, []
    return True, code_findings([FileModel(path, subject.sha256, "E-000000000000", result)])


async def draft_patch(
    ws: Workspace, run_id: str, finding_id: str, service: ModelService, launcher: Launcher, root: Path
) -> PatchDraft:
    run = ws.open_run(run_id)
    try:
        document = json.loads((run.dir / "analysis.json").read_text(encoding="utf-8"))
        findings = json.loads((run.dir / "code-findings.json").read_text(encoding="utf-8"))["findings"]
    except (OSError, ValueError, KeyError) as exc:
        raise PatchError(f"{run_id} isn't an analysis run with code findings") from exc
    if document["charter"]["basis"] != "owned":
        raise PatchError("patch drafts are for code you own; this charter's basis is " + document["charter"]["basis"])
    finding = next((f for f in findings if f["id"] == finding_id), None)
    if finding is None:
        raise PatchError(f"{run_id} has no finding {finding_id}")
    subject = next((s for s in document["subjects"] if s["path"] == finding["file"]), None)
    if subject is None or subject.get("type") != "javascript" or not subject.get("staged"):
        raise PatchError("only findings in JavaScript source files can be patched in this phase")
    source = (run.dir / "inputs" / subject["staged"]).read_text(encoding="utf-8")

    result = await service.run(patcher.task(finding, subject["path"], source, RULES[finding["rule"]].remediation))
    draft = PatchDraft(finding_id, result.status, result.reason)
    if result.status == "answered" and result.output is not None:
        draft.notes = result.output.get("notes", "")
        try:
            patched = apply_edits(source, result.output["edits"])
        except PatchError as exc:
            draft.status, draft.reason = "rejected", str(exc)
        else:
            draft.diff = unified(subject["path"], source, patched)
            parses, after = await _reread(root, subject["path"], patched, launcher, f"{run_id}-{secrets.token_hex(3)}")
            before = {_key(f) for f in findings if f["file"] == finding["file"]}
            draft.verification = {
                "parses": parses,
                "finding_gone": parses and _key(finding) not in {_key(f) for f in after},
                "new_findings": [
                    f"{f['rule']} in {f.get('function') or 'the file'}" for f in after if _key(f) not in before
                ],
            }
    _record(run, draft, result.producer)
    return draft


def _record(run: Any, draft: PatchDraft, producer: str) -> None:
    folder = run.dir / "patches"
    folder.mkdir(exist_ok=True)
    if draft.diff:
        (folder / f"{draft.finding}.diff").write_text(draft.diff, encoding="utf-8")
    record = {"finding": draft.finding, "status": draft.status, "reason": draft.reason, "verified": draft.verified,
              "verification": draft.verification, "notes": draft.notes, "producer": producer,
              "diff": f"{draft.finding}.diff" if draft.diff else None}  # fmt: skip
    (folder / f"{draft.finding}.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    run.audit.append("patch.draft", finding=draft.finding, status=draft.status, verified=draft.verified,
                     diff=sha256_hex(draft.diff.encode()) if draft.diff else None, producer=producer)  # fmt: skip
