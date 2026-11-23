"""`veritas images ...`"""

from __future__ import annotations

from typing import Annotated

import typer

from ..sandbox import build_images, write_lock
from .output import line, project_root

app = typer.Typer(no_args_is_help=True, help="Build first-party images locally.")


@app.command("build")
def build(
    models: Annotated[
        bool, typer.Option("--models", help="Also build the local model server (its base image is about 800 MB).")
    ] = False,
) -> None:
    """Build the gateway and first-party plugin images and pin their IDs in the workspace lock."""
    ids = build_images(project_root(), extras=("models",) if models else ())
    for tag, image_id in ids.items():
        line("image", f"{tag} {image_id}")
    line("lock", str(write_lock(project_root(), ids)))
