"""`veritas scope ...`"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

import typer

from ..core.impact import Impact
from ..scope import check_scope
from ..store import Workspace
from .output import EXIT_INVALID, line, project_root, refreshes

app = typer.Typer(no_args_is_help=True, help="Validate and acknowledge scope files.")


@app.command("check")
@refreshes
def check(
    file: Annotated[Path, typer.Argument(help="Scope file to validate.")],
    ack: Annotated[
        bool, typer.Option("--ack/--no-ack", help="Ask to acknowledge a digest seen for the first time.")
    ] = True,
) -> None:
    """Validate a scope file, pin target addresses, and print its digest."""
    report = check_scope(file)
    scope = report.scope
    if scope is not None:
        window = scope.authorization.window
        line(
            "scope",
            f"{scope.metadata.name} · {report.digest or 'no digest (errors)'} · window until {window.end.isoformat()}",
        )
        for pinned, target in zip(report.pinned, scope.targets, strict=False):
            addrs = ", ".join(f"{a} ({lbl})" for a, lbl in zip(pinned.addresses, pinned.labels, strict=True))
            methods = " ".join(target.allow.methods)
            line("target", f"{target.id}  {target.base_url} → {addrs} · {methods} · {target.limits.rps:g} rps")
        for sensor in scope.sensors:
            line(
                "sensor",
                f"{sensor.id}  {sensor.kind} for {sensor.target} · reads volume {sensor.volume} read-only, no network",
            )
        auto = [i.value for i in scope.policy.auto_approve]
        need = [i.value for i in Impact if i.value not in auto and i != Impact.OBSERVE]
        line("auto", " ".join(auto) + (f" · approval required: {' '.join(need)}" if need else ""))
    for notice in report.notices:
        line("notice", notice)
    for error in report.errors:
        line("error", error)
    if not report.ok or scope is None or report.digest is None:
        raise typer.Exit(EXIT_INVALID)
    ws = Workspace(project_root())
    try:
        if ws.is_acknowledged(report.digest):
            line("ack", "already acknowledged")
        elif ack:
            if not sys.stdin.isatty():
                line("ack", "not acknowledged; run this command in an interactive terminal to acknowledge")
                raise typer.Exit(EXIT_INVALID)
            if typer.confirm("Acknowledge this scope?", default=False):
                summary = {"targets": {p.id: p.addresses for p in report.pinned}, "file": str(file)}
                ws.acknowledge(report.digest, scope.metadata.name, summary)
                line("ack", "acknowledged")
            else:
                line("ack", "not acknowledged")
                raise typer.Exit(EXIT_INVALID)
    finally:
        ws.close()
