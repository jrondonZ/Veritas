"""Terminal output helpers shared by all commands."""

from __future__ import annotations

import functools
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypeVar, cast

import typer

EXIT_FINDINGS = 1  # also: verification failed
EXIT_INVALID = 4  # invalid configuration (docs/architecture.md §12.2)
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
F = TypeVar("F", bound=Callable[..., Any])


def safe(text: object) -> str:
    """Strip terminal control characters from anything that may echo file or target content."""
    return _CONTROL.sub("?", str(text))


def line(label: str, text: str) -> None:
    typer.echo(f"{label:<8} {safe(text)}")


def project_root() -> Path:
    return Path.cwd()


def refresh_page(root: Path) -> None:
    """Rewrite the central page after a command changed the workspace. The page is a convenience: if it can't be
    written, the command's own result still stands, so this only warns."""
    if not (root / ".veritas").is_dir():
        return
    try:
        from ..ui.page import publish  # imported here so commands that never touch the page don't load it

        publish(root)
    except Exception as exc:  # noqa: BLE001  # any failure, and only a warning
        line("warning", f"the central page wasn't updated ({type(exc).__name__}: {exc}); `veritas ui` rewrites it")


def refreshes(command: F) -> F:
    """For commands that change the workspace: when one finishes, or exits with a status, the page is rewritten.
    An interrupted or crashed command leaves the page as it was."""

    @functools.wraps(command)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        try:
            result = command(*args, **kwargs)
        except typer.Exit:
            refresh_page(project_root())
            raise
        refresh_page(project_root())
        return result

    return cast(F, wrapper)
