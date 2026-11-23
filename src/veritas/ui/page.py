"""The central page: one self-contained HTML file with the workspace inside, opened straight from disk.

`veritas ui` writes `.veritas/index.html` and opens it. Every command that changes the
workspace rewrites it, so it stays current. Nothing listens on a port and nothing is
fetched. The page's script and style are inline, and its Content-Security-Policy allows
exactly those, by their hashes, and nothing else. The data is a JSON block the script reads
as text. Target-derived text inside it can't end the block, because `<`, `>`, and `&` are
escaped.

The workspace stays on this machine: the page lives inside `.veritas/`, which git ignores,
and it holds only what the CLI already wrote there.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import data

STATIC = Path(__file__).parent / "static"
PAGE = "index.html"
MAX_DETAILS = 30  # the newest runs carry their full documents; older ones, their summaries
MAX_DIFF = 200_000
PLACEHOLDERS = ("__CSP__", "__STYLE__", "__SCRIPT__", "__DATA__")


def snapshot(root: Path, max_details: int = MAX_DETAILS) -> dict[str, Any]:
    overview = data.overview(root)
    runs: dict[str, Any] = {}
    for run in overview["runs"][:max_details]:
        detail = data.run_detail(root, run["id"])
        if detail is None:
            continue
        for patch in detail.get("patches") or []:
            if patch and patch.get("diff"):
                text = data.run_file(root, run["id"], f"patches/{patch['diff']}") or ""
                patch["diff_text"] = text[:MAX_DIFF]
        runs[run["id"]] = detail
    generated = datetime.now(UTC).isoformat(timespec="seconds")
    return {"overview": overview, "runs": runs, "generated": generated, "kept": max_details}


def embed(value: Any) -> str:
    """JSON that can't end the script element it sits in, or be read as anything but data."""
    text = json.dumps(value, sort_keys=True, ensure_ascii=False)
    for raw, escaped in (("&", "\\u0026"), ("<", "\\u003c"), (">", "\\u003e"), (" ", "\\u2028"),
                         (" ", "\\u2029")):  # fmt: skip
        text = text.replace(raw, escaped)
    return text


def _hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


def build(root: Path, max_details: int = MAX_DETAILS) -> str:
    template = (STATIC / "page.html").read_text(encoding="utf-8")
    style = (STATIC / "app.css").read_text(encoding="utf-8")
    script = (STATIC / "app.js").read_text(encoding="utf-8")
    for part in (style, script):  # inline code must not be able to end its own element or hold a placeholder
        if any(p in part for p in PLACEHOLDERS) or "</" in part:
            raise ValueError("a static asset contains a placeholder or a closing tag")
    csp = (f"default-src 'none'; script-src {_hash(script)}; style-src {_hash(style)}; img-src data:; "
           "base-uri 'none'; form-action 'none'")  # fmt: skip
    page = template.replace("__CSP__", csp).replace("__STYLE__", style).replace("__SCRIPT__", script)
    return page.replace("__DATA__", embed(snapshot(root, max_details)))  # last: data never becomes a placeholder


def publish(root: Path) -> Path:
    """Write `.veritas/index.html` atomically, so a browser never sees half a page."""
    folder = root / ".veritas"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)  # as the workspace makes it: this user's only
    text = build(root)
    fd, temp = tempfile.mkstemp(prefix=".index-", suffix=".html", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(temp, folder / PAGE)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise
    return folder / PAGE
