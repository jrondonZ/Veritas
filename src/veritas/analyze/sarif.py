"""SARIF 2.1.0 for code findings: each candidate at its file and line, so code-scanning tools can show it in place."""

from __future__ import annotations

from typing import Any

from .. import __version__
from .security import RULES

LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "none": "note"}


def render_code_sarif(findings: list[dict[str, Any]], run_id: str) -> dict[str, Any]:
    used = sorted({f["rule"] for f in findings})
    rules = [
        {
            "id": rid,
            "name": RULES[rid].title,
            "shortDescription": {"text": RULES[rid].title},
            "help": {"text": RULES[rid].remediation},
            "properties": {
                "tags": ["security", *RULES[rid].cwe],
                "security-severity": str(
                    next(f for f in findings if f["rule"] == rid)["if_confirmed"]["cvss"]["score"]
                ),
            },
        }
        for rid in used
    ]
    results = [
        {
            "ruleId": f["rule"],
            "ruleIndex": used.index(f["rule"]),
            "level": LEVEL[f["if_confirmed"]["severity"]],
            "message": {"text": f["claims"][0]["text"]},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f["file"]},
                        # line 0 means the finding is about the whole file, so there's no region
                        **({"region": {"startLine": f["line"]}} if f["line"] > 0 else {}),
                    }
                }
            ],
            "partialFingerprints": {"veritas/v1": f["fingerprint"]},
            "properties": {"veritasId": f["id"], "status": f["status"], "confirmsWith": f["confirms_with"]},
        }
        for f in findings
    ]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "Veritas Analyze", "version": __version__, "rules": rules}},
                "results": results,
                "properties": {"run": run_id},
            }
        ],
    }
