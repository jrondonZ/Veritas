"""Commands over recorded runs: show, report, replay, reproduce, export, verify."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated, Any

import typer

from ..assess.bundle import export as export_bundle
from ..assess.bundle import verify_bundle
from ..assess.policy import deny_all, terminal_approver
from ..assess.replay import load_document, rebuild
from ..assess.replay import replay as replay_run
from ..assess.runner import RunError, RunOptions, assess
from ..reports import render_terminal
from ..store import Workspace
from .output import EXIT_FINDINGS, EXIT_INVALID, line, project_root, refreshes, safe

REPORTS = {"json": "findings.json", "md": "report.md", "sarif": "report.sarif"}


def _document(run: str) -> dict[str, Any]:
    ws = Workspace(project_root())
    try:
        return load_document(ws, run)
    except KeyError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()


def show(
    run: Annotated[str, typer.Argument(help="Run ID, e.g. r-0001.")],
    finding: Annotated[str | None, typer.Argument(help="A finding ID, e.g. F-0003.")] = None,
    show_all: Annotated[bool, typer.Option("--all", help="Include rejected probes.")] = False,
) -> None:
    """Show a run's findings, or one finding in full."""
    document = _document(run)
    if finding is None:
        for text in render_terminal(document, show_rejected=show_all):
            typer.echo(safe(text))
        return
    match = next((f for f in document["findings"] if f["id"] == finding), None)
    if match is None:
        line("error", f"no finding {finding} in {run}")
        raise typer.Exit(EXIT_INVALID)
    typer.echo(safe(json.dumps(match, indent=2)))


def report(
    run: Annotated[str, typer.Argument(help="Run ID.")],
    fmt: Annotated[str, typer.Option("--format", help="json, md, or sarif.")] = "md",
) -> None:
    """Print one of a run's reports."""
    if fmt not in REPORTS:
        line("error", f"--format must be one of {', '.join(REPORTS)}")
        raise typer.Exit(EXIT_INVALID)
    path = project_root() / ".veritas" / "runs" / run / REPORTS[fmt]
    if not path.exists():
        line("error", f"run {run} has no {REPORTS[fmt]}")
        raise typer.Exit(EXIT_INVALID)
    typer.echo(safe(path.read_text(encoding="utf-8")))


def replay(run: Annotated[str, typer.Argument(help="Run ID.")]) -> None:
    """Re-run every oracle over the run's stored evidence, offline, and compare the verdicts."""
    try:
        rows = replay_run(project_root(), run)
    except KeyError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    for row in rows:
        line(
            "replay",
            f"{row.finding} recorded {row.recorded} · replayed {row.replayed}" + ("" if row.matches else "  MISMATCH"),
        )
    mismatches = [r for r in rows if not r.matches]
    line("result", f"{len(rows) - len(mismatches)} of {len(rows)} verdicts reproduced from stored evidence")
    if mismatches:
        raise typer.Exit(EXIT_FINDINGS)


@refreshes
def reproduce(
    run: Annotated[str, typer.Argument(help="Run ID.")],
    finding: Annotated[str, typer.Argument(help="Finding ID to re-validate live.")],
    scope: Annotated[Path, typer.Option("--scope", help="The scope file the run used.")],
    attempts: Annotated[int, typer.Option(min=1, max=5)] = 3,
) -> None:
    """Re-send a finding's probe against the target, under the current scope and policy."""
    document = _document(run)
    match = next((f for f in document["findings"] if f["id"] == finding), None)
    if match is None:
        line("error", f"no finding {finding} in {run}")
        raise typer.Exit(EXIT_INVALID)
    approver = (
        terminal_approver(lambda t: typer.echo(safe(t)), lambda q: typer.prompt(q, default="", show_default=False))
        if sys.stdin.isatty()
        else deny_all
    )
    options = RunOptions(attempts=attempts, approver=approver, log=line)
    try:
        result = asyncio.run(assess(scope, project_root(), options, only=[rebuild(match)]))
    except RunError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    if result.document["scope"]["digest"] != document["scope"]["digest"]:
        line("notice", "the scope changed since the original run; this result is under the current scope")
    (new,) = result.findings
    line("was", f"{finding} {match['status']} {match['passed']}/{match['attempts']} in {run}")
    line("now", f"{new.status} {new.passed}/{new.attempts} in {result.run_id} · {new.reason}")


def export(
    run: Annotated[str, typer.Argument(help="Run ID.")],
    out: Annotated[Path, typer.Option("--out", help="Bundle path, e.g. r-0001.tar.gz.")],
) -> None:
    """Write a self-verifying evidence bundle for a run."""
    try:
        path = export_bundle(project_root(), run, out)
    except KeyError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    line("bundle", f"{path} · check it with `veritas verify {path}`")


def verify(bundle: Annotated[Path, typer.Argument(help="A bundle written by `veritas export`.")]) -> None:
    """Check a bundle's file hashes, evidence IDs, and audit chain."""
    result = verify_bundle(bundle)
    for problem in result.problems:
        line("error", problem)
    if not result.ok:
        raise typer.Exit(EXIT_FINDINGS)
    line("verify", f"{result.run} · {result.files} files · hashes, evidence IDs, and audit chain ok")
