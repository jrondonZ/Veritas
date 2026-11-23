"""`veritas advisories ...`: OSV advisories from files you downloaded, for offline dependency checks.

Veritas never fetches advisories. Download an OSV export yourself (osv.dev publishes one zip
per ecosystem), then import it. Analyze matches the packages bundled in Electron archives
against what's imported.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer

from ..imports.osv import ECOSYSTEMS, AdvisoryError, import_advisories, summary
from ..store import Workspace
from .output import EXIT_INVALID, line, project_root, refreshes

app = typer.Typer(no_args_is_help=True, help="Import OSV advisories from local files, for offline dependency checks.")


@app.command("import")
@refreshes
def import_(
    source: Annotated[Path, typer.Argument(help="An OSV JSON file, a folder of them, or a zip export.")],
    ecosystem: Annotated[
        list[str] | None, typer.Option("--ecosystem", help="Ecosystem to keep; repeat it. Default: npm.")
    ] = None,
) -> None:
    """Import advisories into this workspace. Nothing is fetched. Importing a newer export replaces records that
    have the same IDs."""
    ws = Workspace(project_root())  # the workspace folder, made for this user only if this is the first command
    ws.close()
    try:
        report = import_advisories(ws.root, source, tuple(ecosystem or ECOSYSTEMS))
    except (AdvisoryError, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    line("source", f"{report.source} · sha256:{report.sha256}")
    line("read", f"{report.documents} document(s) · {report.records} advisories kept · {report.packages} package "
                 f"entries · {report.other} for other ecosystems · {report.skipped} skipped")  # fmt: skip
    for note in report.notes:
        line("notice", note)
    if not report.records:
        raise typer.Exit(EXIT_INVALID)
    line("next", "analyses from now on check bundled dependencies against these; `veritas advisories status`")


@app.command("status")
def status() -> None:
    """Show what's imported: advisories, packages, and each source by its SHA-256."""
    info = summary(project_root() / ".veritas")
    if not info["records"]:
        line("advisories", "none imported; download an OSV export, then run `veritas advisories import <file>`")
        return
    line("advisories", f"{info['records']} advisories for {info['packages']} packages")
    for s in info["sources"]:
        line("source", f"{s['name']} · sha256:{s['sha256'][:16]}… · {s['records']} kept · {s['skipped']} skipped · "
                       f"imported {s['imported']}")  # fmt: skip
