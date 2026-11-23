"""`veritas assess ...`"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import Annotated

import typer

from ..assess.policy import deny_all, terminal_approver
from ..assess.runner import RunError, RunOptions, assess
from ..findings import at_least
from ..findings.model import SEVERITY_ORDER
from ..reports import render_terminal
from .output import EXIT_FINDINGS, EXIT_INVALID, line, project_root, refreshes, safe

EXIT_GAPS = 2
EXIT_ABORTED = 3

app = typer.Typer(no_args_is_help=True, help="Run authorized assessments.")


def _ask(question: str) -> str:
    answer: str = typer.prompt(question, default="", show_default=False)
    return answer


@app.command("run")
@refreshes
def run(
    scope: Annotated[Path, typer.Option("--scope", help="Scope file (acknowledged with `veritas scope check`).")],
    ci: Annotated[bool, typer.Option("--ci", help="Non-interactive: probes that need approval end blocked.")] = False,
    fail_on: Annotated[
        str | None, typer.Option(help="Exit 1 if a confirmed finding is at least: low|medium|high|critical.")
    ] = None,
    max_gaps: Annotated[
        int | None, typer.Option(help="Exit 2 if more probes than this end blocked or in error.")
    ] = None,
    attempts: Annotated[int, typer.Option(min=1, max=5, help="Attempts per probe; only a pass is reproduced.")] = 3,
    models: Annotated[
        bool | None,
        typer.Option("--models/--no-models", help="Override the scope's policy.models. Status is the same either way."),
    ] = None,
) -> None:
    """Assess the scope's target: recon, deterministic checks, approvals, and reports."""
    if fail_on is not None and fail_on not in SEVERITY_ORDER[1:]:
        line("error", f"--fail-on must be one of {', '.join(SEVERITY_ORDER[1:])}")
        raise typer.Exit(EXIT_INVALID)
    interactive = not ci and sys.stdin.isatty()
    approver = terminal_approver(lambda text: typer.echo(safe(text)), _ask) if interactive else deny_all
    try:
        options = RunOptions(attempts=attempts, approver=approver, log=line, models=models)
        result = asyncio.run(assess(scope, project_root(), options))
    except RunError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    typer.echo("")
    for text in render_terminal(result.document):
        typer.echo(safe(text))
    line("reports", f".veritas/runs/{result.run_id}/ (findings.json, report.md, report.sarif)")
    if result.leftovers:
        line("error", f"resources left behind: {', '.join(result.leftovers)}")
    if result.outcome == "aborted":
        raise typer.Exit(EXIT_ABORTED)
    if fail_on and any(f.status == "confirmed" and at_least(f.severity, fail_on) for f in result.findings):
        raise typer.Exit(EXIT_FINDINGS)
    gaps = sum(f.status in ("blocked", "error") for f in result.findings)
    if max_gaps is not None and gaps > max_gaps:
        raise typer.Exit(EXIT_GAPS)
