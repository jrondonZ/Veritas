"""`veritas audit ...`"""

from __future__ import annotations

from typing import Annotated

import typer

from ..store import Workspace
from .output import EXIT_FINDINGS, EXIT_INVALID, line, project_root

app = typer.Typer(no_args_is_help=True, help="Check audit logs.")


@app.command("verify")
def verify(run: Annotated[str, typer.Argument(help="Run ID, e.g. r-0001.")]) -> None:
    """Recompute a run's hash chain and compare it with the recorded head."""
    ws = Workspace(project_root())
    try:
        result = ws.verify_run(run)
    except KeyError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()
    if result.ok:
        line("audit", f"{run} · {result.entries} entries · head {result.head} · ok")
        return
    for problem in result.problems:
        line("error", problem)
    raise typer.Exit(EXIT_FINDINGS)
