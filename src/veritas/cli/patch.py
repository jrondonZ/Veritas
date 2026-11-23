"""`veritas patch draft` (docs/architecture.md §8.1 stage 10): a local model's fix for one code finding, for review."""

from __future__ import annotations

import asyncio
import secrets
from typing import Annotated

import typer

from ..analyze.patches import PatchDraft, PatchError, draft_patch
from ..analyze.runner import AnalyzeError, docker_launcher
from ..models import ModelService, ResponseCache, RouteUnavailable, TokenBudget, load_models, load_routing
from ..plugins.host import PluginRefused
from ..plugins.rpc import RpcError
from ..sandbox import read_lock
from ..sandbox.images import MODEL_IMAGE
from ..store import Workspace
from .output import EXIT_FINDINGS, EXIT_INVALID, line, project_root, refreshes

app = typer.Typer(no_args_is_help=True, help="Draft fixes for code findings, for a person to review and apply.")


@app.command("draft")
@refreshes
def draft(
    run_id: Annotated[str, typer.Argument(metavar="RUN", help="An analysis run of code you own.")],
    finding: Annotated[str, typer.Argument(metavar="FINDING", help="A code finding's ID, for example S-0003.")],
) -> None:
    """Have the local model draft a fix for one code finding, then check it. Nothing is applied to your files."""
    root = project_root()
    lock = read_lock(root)
    image = lock.get("images", {}).get(MODEL_IMAGE)
    routing = load_routing(root, load_models(lock))
    try:
        served = routing.resolve("code")
    except RouteUnavailable as exc:
        line("error", f"no local model: {exc}")
        raise typer.Exit(EXIT_INVALID) from None
    if image is None:
        line("error", "the model server is missing; run `veritas images build --models`")
        raise typer.Exit(EXIT_INVALID)
    line("model", f"{served.model.name} · {served.model.quantization} · {served.model.license}")
    ws = Workspace(root)
    try:
        run = ws.open_run(run_id)
        service = ModelService(routing, image, f"{run_id}-{secrets.token_hex(3)}", run.audit, ResponseCache(root),
                               TokenBudget(500_000), log=line)  # fmt: skip

        async def main() -> PatchDraft:
            try:
                return await draft_patch(ws, run_id, finding, service, docker_launcher(root), root)
            finally:
                await service.close()

        result = asyncio.run(main())
    except (KeyError, PatchError, AnalyzeError, PluginRefused, RpcError, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()
    line("draft", f"{finding} · {result.status}" + (f" ({result.reason})" if result.reason else ""))
    if result.notes:
        line("notes", result.notes)
    if result.diff:
        line("diff", f".veritas/runs/{run_id}/patches/{finding}.diff")
    v = result.verification
    if v:
        yes = {True: "yes", False: "no"}
        line("check", f"parses {yes[bool(v['parses'])]} · finding gone {yes[bool(v['finding_gone'])]} · "
                      f"new findings {len(v['new_findings'])}")  # fmt: skip
        for text in v["new_findings"]:
            line("new", text)
    if result.verified:
        line("result", "verified. Review the diff, then apply it yourself, for example with `git apply`.")
        return
    line("result", "not verified")
    raise typer.Exit(EXIT_FINDINGS)
