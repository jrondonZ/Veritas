"""`veritas lab ...`"""

from __future__ import annotations

from typing import Annotated

import typer

from ..environments import Lab
from .output import EXIT_FINDINGS, line, project_root

app = typer.Typer(no_args_is_help=True, help="Manage bundled, intentionally vulnerable labs.")


@app.command("up")
def up(name: str) -> None:
    """Build, start, seed, and snapshot a lab on its internal network."""
    health = Lab(name, project_root()).up()
    line("lab", f"{name} up · {health.get('users')} identities seeded · snapshot s-01")


@app.command("reset")
def reset(name: str, snapshot: Annotated[str, typer.Option(help="Snapshot to restore.")] = "s-01") -> None:
    """Restore a lab snapshot."""
    health = Lab(name, project_root()).reset(snapshot)
    line("lab", f"{name} restored {snapshot} · {health.get('notes')} notes")


@app.command("down")
def down(name: str) -> None:
    """Remove a lab's containers, network, and volume, and check that nothing is left."""
    leftovers = Lab(name, project_root()).down()
    if leftovers:
        line("error", f"left behind: {', '.join(leftovers)}")
        raise typer.Exit(EXIT_FINDINGS)
    line("lab", f"{name} removed · nothing left behind")
