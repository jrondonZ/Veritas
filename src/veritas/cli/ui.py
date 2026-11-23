"""`veritas ui`: write the central page, `.veritas/index.html`, and open it. Nothing listens on a port."""

from __future__ import annotations

import webbrowser
from typing import Annotated

import typer

from ..ui.page import publish
from .output import EXIT_INVALID, line, project_root


def ui(
    open_browser: Annotated[bool, typer.Option("--open/--no-open", help="Open the page in your browser.")] = True,
) -> None:
    """Write the central page and open it: runs, findings, specs, clean-room results, and patch drafts.

    It's one self-contained file, .veritas/index.html, that reads nothing from the network.

    It's a read-only snapshot. Commands that change the workspace rewrite it; approvals stay at the terminal.
    """
    root = project_root()
    try:
        path = publish(root)
    except (OSError, ValueError) as exc:
        line("error", f"the page wasn't written: {exc}")
        raise typer.Exit(EXIT_INVALID) from None
    line("ui", str(path))
    line("note", "a read-only snapshot, opened from disk; commands that change the workspace rewrite it")
    if open_browser:
        webbrowser.open(path.resolve().as_uri())
