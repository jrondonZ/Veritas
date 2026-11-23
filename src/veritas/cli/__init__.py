"""The `veritas` command line. Each command group lives in its own module."""

from __future__ import annotations

import typer

from . import advisories, analyze, assess, audit, images, lab, models, patch, runs, scope, ui

app = typer.Typer(
    no_args_is_help=True,
    add_completion=False,
    help="Veritas: authorized security validation, evidence-based reverse engineering, and clean-room replication.",
)
app.add_typer(scope.app, name="scope")
app.add_typer(assess.app, name="assess")
app.add_typer(analyze.charter_app, name="charter")
app.add_typer(analyze.analyze_app, name="analyze")
app.add_typer(analyze.spec_app, name="spec")
app.add_typer(analyze.cleanroom_app, name="cleanroom")
app.add_typer(audit.app, name="audit")
app.add_typer(lab.app, name="lab")
app.add_typer(images.app, name="images")
app.add_typer(models.app, name="models")
app.add_typer(patch.app, name="patch")
app.add_typer(advisories.app, name="advisories")
for command in (runs.show, runs.report, runs.replay, runs.reproduce, runs.export, runs.verify, ui.ui):
    app.command(command.__name__)(command)

__all__ = ["app"]
