"""The patcher role (docs/architecture.md §8.1 stage 10): a draft fix for one code finding, for a person to review.

It sees one finding (its rule, CWE, typed claims, and the rule's remediation) and the owned
source file the finding is in. It answers with exact edits: text that occurs once in the
file, and what replaces it. The kernel applies them to a copy, never to the operator's
tree, and checks the result before anyone reads it (veritas.analyze.patches).
"""

from __future__ import annotations

from typing import Any

from ..models.calls import ModelTask, answer_envelope
from ..models.prompts import Prompt, untrusted

VERSION = "1"
MAX_SOURCE = 40_000  # characters of the file shown; a larger file is cut to the finding's neighborhood
MAX_EDITS = 6
SYSTEM = """\
You are the patcher. You get one security finding in code, with its remediation, and the source file it's in. \
Propose the smallest change that fixes the weakness the finding names.
- Answer with edits. Each edit's "find" is text copied exactly from the file that occurs there exactly once; \
"replace" is what goes there instead. Include enough surrounding text in "find" to make it unique.
- Change only what the fix needs. Keep the file's style. Add no dependencies and no new files.
- If a complete fix needs more than this file, say so in "notes" and fix what this file can.
"""


def excerpt(source: str, line: int) -> str:
    """The file, or for a long one, the lines around the finding."""
    if len(source) <= MAX_SOURCE:
        return source
    lines = source.splitlines(keepends=True)
    start = max(0, (line or 1) - 120)
    out, size = [], 0
    for text in lines[start:]:
        if size + len(text) > MAX_SOURCE:
            break
        out.append(text)
        size += len(text)
    return "".join(out)


def task(finding: dict[str, Any], path: str, source: str, remediation: str) -> ModelTask:
    shown = excerpt(source, int(finding.get("line") or 0))
    schema = answer_envelope(
        {
            "edits": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_EDITS,
                "items": {
                    "type": "object",
                    "properties": {
                        "find": {"type": "string", "minLength": 1, "maxLength": 4000},
                        "replace": {"type": "string", "maxLength": 6000},
                    },
                    "required": ["find", "replace"],
                    "additionalProperties": False,
                },
            },
            "notes": {"type": "string", "maxLength": 600},
        },
        ["edits", "notes"],
    )
    where = f"{path}:{finding.get('line')}" if finding.get("line") else path
    about = (
        f"Finding: {finding['title']} ({', '.join(finding.get('cwe') or [])})\n"
        f"Where: {where}" + (f", in {finding['function']}" if finding.get("function") else "") + "\n"
        f"What was observed: {finding['claims'][0]['text']}\nRemediation: {remediation}"
    )

    def check(output: dict[str, Any]) -> list[str]:
        problems = []
        spans: list[tuple[int, int]] = []
        for i, edit in enumerate(output["edits"]):
            count = shown.count(edit["find"])
            if count != 1:
                problems.append(f"edits[{i}].find occurs {count} times in the file; it must occur exactly once")
                continue
            start = source.find(edit["find"])
            if source.count(edit["find"]) != 1:
                problems.append(f"edits[{i}].find also occurs outside the part of the file shown")
                continue
            if edit["replace"] == edit["find"]:
                problems.append(f"edits[{i}] changes nothing")
            span = (start, start + len(edit["find"]))
            if any(s < span[1] and span[0] < e for s, e in spans):
                problems.append(f"edits[{i}] overlaps an earlier edit")
            spans.append(span)
        return problems

    prompt = Prompt("patcher", VERSION, SYSTEM, about, untrusted(shown, f"owned source {path}"))
    return ModelTask("patcher", "code", finding["id"], prompt, schema, 1500, check)
