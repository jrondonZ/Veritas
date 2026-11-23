"""Reports, all derived from the canonical findings document (docs/architecture.md §12)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .markdown import render_markdown
from .sarif import render_sarif
from .terminal import render_terminal

__all__ = ["render_markdown", "render_sarif", "render_terminal", "write_reports"]


def write_reports(run_dir: Path, document: dict[str, Any], exchanges: dict[str, Any] | None = None) -> list[Path]:
    """Write findings.json, report.md, and report.sarif; `exchanges` maps evidence IDs to SARIF web objects."""
    outputs = {
        "findings.json": json.dumps(document, indent=2, sort_keys=True) + "\n",
        "report.md": render_markdown(document),
        "report.sarif": json.dumps(render_sarif(document, exchanges or {}), indent=2) + "\n",
    }
    written = []
    for name, text in outputs.items():
        path = run_dir / name
        path.write_text(text, encoding="utf-8", newline="\n")
        written.append(path)
    return written
