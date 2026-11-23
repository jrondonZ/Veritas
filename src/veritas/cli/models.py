"""`veritas models ...` (docs/architecture.md §10.2): local weights only; Veritas never downloads any."""

from __future__ import annotations

import asyncio
import json
import secrets
import shutil
import tempfile
from pathlib import Path
from typing import Annotated, Any

import typer

from ..analyze.cleanroom import DirtyInput, NotApproved, clean_context, load_approved, verify
from ..evals.routing import code_case, evaluate
from ..models import ModelService, ResponseCache, TokenBudget
from ..models.doctor import benchmark, docker_resources, propose_profile
from ..models.profiles import PROFILES, ROUTES, RouteUnavailable, Routing, load_routing, save_routing
from ..models.registry import RegistryError, load_models, register
from ..sandbox import DockerError, read_lock
from ..sandbox.engine import JobError, harness_argv
from ..sandbox.images import CONFORMANCE_JS_IMAGE, MODEL_IMAGE, update_lock
from ..sandbox.model import install_weights, remove_weights
from ..store import Workspace
from .output import EXIT_INVALID, line, project_root, refreshes

app = typer.Typer(no_args_is_help=True, help="Register local model weights and choose the model for each route.")


def _model_image(lock: dict[str, object]) -> str:
    images = lock.get("images")
    image = images.get(MODEL_IMAGE) if isinstance(images, dict) else None
    if not isinstance(image, str):
        line("error", "the model-server image is missing; run `veritas images build`")
        raise typer.Exit(EXIT_INVALID)
    return image


@app.command("add")
@refreshes
def add(
    file: Annotated[Path, typer.Argument(help="A GGUF weights file on this machine.")],
    name: Annotated[str | None, typer.Option(help="Name to register it under; defaults to the file name.")] = None,
    license_id: Annotated[
        str | None, typer.Option("--license", help="SPDX license ID, if the file doesn't declare one.")
    ] = None,
) -> None:
    """Register local weights: hash them, record their license, and copy them into the models volume."""
    root = project_root()
    lock = read_lock(root)
    image = _model_image(lock)
    line("hash", f"{file} · this reads the whole file")
    try:
        entry, models = register(file, lock, lambda src, dest, sha: install_weights(image, src, dest, sha), name,
                                 license_id)  # fmt: skip
    except (RegistryError, DockerError, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from exc
    update_lock(root, "models", models)
    size = f"{entry.size / 2**30:.2f} GiB"
    line("model", f"{entry.name} · {entry.title or '?'} · {entry.quantization} · {size} · {entry.license}")
    line("weights", f"{entry.sha256} · verified in the models volume")
    if not entry.permissive:
        line("notice", f"{entry.license} is not Apache-2.0, MIT, or BSD; check its terms before you rely on it")


@app.command("list")
def list_models() -> None:
    """Show registered weights and which model serves each route."""
    root = project_root()
    models = load_models(read_lock(root))
    for m in models.values():
        line("model", f"{m.name} · {m.quantization} · {m.size / 2**30:.2f} GiB · {m.license} · {m.sha256[:19]}…")
    routing = load_routing(root, models)
    line("profile", f"{routing.profile.name} · {routing.profile.hardware}")
    for route in ROUTES:
        try:
            r = routing.resolve(route)
            via = f" (aliased to {r.serving})" if r.aliased else ""
            line("route", f"{route}{via} → {r.model.name} · from {r.source}")
        except RouteUnavailable as exc:
            line("route", f"{route} → unavailable: {exc}")


@app.command("route")
@refreshes
def route(
    route_name: Annotated[
        str, typer.Argument(metavar="ROUTE", help="triage, analysis, deep, or code (clean-room implementations).")
    ],
    model: Annotated[str, typer.Argument(help="A registered model name.")],
) -> None:
    """Choose the model that serves a route in this workspace."""
    root = project_root()
    models = load_models(read_lock(root))
    if route_name not in ROUTES or model not in models:
        line("error", f"routes are {', '.join(ROUTES)}; registered models are {', '.join(models) or 'none'}")
        raise typer.Exit(EXIT_INVALID)
    routing = load_routing(root, models)
    save_routing(root, routing.profile.name, {**routing.choices, route_name: model})
    line("route", f"{route_name} → {model}")


@app.command("remove")
@refreshes
def remove(name: Annotated[str, typer.Argument(help="A registered model name.")]) -> None:
    """Remove registered weights from the models volume and the lock."""
    root = project_root()
    lock = read_lock(root)
    models = load_models(lock)
    if name not in models:
        line("error", f"no model named {name} is registered")
        raise typer.Exit(EXIT_INVALID)
    remove_weights(_model_image(lock), models[name].file)
    update_lock(root, "models", {k: m.to_json() for k, m in models.items() if k != name})
    routing = load_routing(root, models)
    save_routing(root, routing.profile.name, {r: m for r, m in routing.choices.items() if m != name})
    line("removed", name)


@app.command("eval")
@refreshes
def evaluate_models(
    model: Annotated[
        list[str] | None, typer.Option("--model", help="A registered model to include; repeat it. Default: all.")
    ] = None,
    cleanroom_run: Annotated[
        str | None, typer.Option("--cleanroom-run", help="An approved lexfmt analysis run, to score the code route.")
    ] = None,
    apply: Annotated[bool, typer.Option("--apply", help="Save the recommended routes in this workspace.")] = False,
) -> None:
    """Score registered models on each route's cases on this machine, and recommend one per route."""
    root = project_root()
    lock = read_lock(root)
    image = _model_image(lock)
    registered = load_models(lock)
    names = model or sorted(registered)
    unknown = [n for n in names if n not in registered]
    if not names or unknown:
        line("error", f"registered models are {', '.join(registered) or 'none'}; add weights with `veritas models add`")
        raise typer.Exit(EXIT_INVALID)
    routing = load_routing(root, registered)
    ws = Workspace(root)
    scratch = Path(tempfile.mkdtemp(prefix="vrt-eval-"))
    try:
        run = ws.create_run("eval", None)
        run.audit.append("eval.start", models=names, profile=routing.profile.name, cleanroom_run=cleanroom_run)
        code = _code_case(ws, root, cleanroom_run, scratch) if cleanroom_run else None

        def service_for(name: str) -> ModelService:
            pinned = Routing(routing.profile, dict.fromkeys(ROUTES, name), registered)
            return ModelService(pinned, image, f"{run.id}-{secrets.token_hex(3)}", run.audit, ResponseCache(scratch),
                                TokenBudget(2_000_000), log=line)  # fmt: skip

        async def close(service: ModelService) -> None:
            await service.close()

        report = asyncio.run(evaluate(names, service_for, routing.profile.name, code, close))  # type: ignore[arg-type]
        out = ws.root / "evals" / f"{run.id}.json"
        out.parent.mkdir(exist_ok=True)
        out.write_text(json.dumps(report.to_json(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
        run.audit.append("eval.end", recommended=report.recommend())
        ws.set_outcome(run.id, "completed")
    except (KeyError, NotApproved, DirtyInput, JobError, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()
        shutil.rmtree(scratch, ignore_errors=True)
    for r in report.results:
        line("case", f"{r.model} · {r.route} · {r.case} · {r.status} · score {r.score:.2f} · {r.seconds} s · "
                     f"{r.tokens} tokens" + (f" · {r.note}" if r.note else ""))  # fmt: skip
    for note in report.skipped:
        line("skipped", note)
    recommended = report.recommend()
    for route_name, name in sorted(recommended.items()):
        line("best", f"{route_name} → {name}")
    line("report", f".veritas/evals/{run.id}.json")
    if apply and recommended:
        save_routing(root, routing.profile.name, {**routing.choices, **recommended})
        line("routes", "saved; `veritas models list` shows them")


def _code_case(ws: Workspace, root: Path, run_id: str, scratch: Path) -> tuple[Any, Any]:
    """The lexfmt implementer task and a scorer that runs the conformance harness, from an approved spec."""
    approved = load_approved(ws, run_id)
    work = scratch / "context"
    clean_context(approved, work)
    samples = {v["sample"]: (work / "samples" / v["sample"]).read_bytes()
               for v in approved.clean["conformance"]["vectors"]}  # fmt: skip
    image = read_lock(root).get("images", {}).get(CONFORMANCE_JS_IMAGE)
    if image is None:
        raise OSError("the conformance harness image is missing; run `veritas images build`")
    sandbox = f"{run_id}-{secrets.token_hex(3)}"
    count = [0]

    async def score(output: dict[str, Any]) -> tuple[float, str]:
        count[0] += 1
        impl = scratch / f"impl-{count[0]}"
        impl.mkdir()
        (impl / "index.mjs").write_text(output["module"], encoding="utf-8")

        def harness(implementation: Path, samples_dir: Path) -> tuple[list[str], dict[str, str]]:
            return harness_argv(sandbox, image, implementation, samples_dir), {}

        result = await asyncio.to_thread(verify, ws, approved, impl, "index.mjs", harness, f"eval-{count[0]}")
        return (result.passed / result.total if result.total else 0.0), "" if result.verified else (
            f"{result.passed}/{result.total} vectors" + (", similar to the subject" if result.similarity.get(
                "similar") else ""))  # fmt: skip

    return code_case(approved.clean, samples), score


@app.command("doctor")
def doctor() -> None:
    """Measure the CPUs and memory Docker provides and each registered model's speed; propose a profile."""
    root = project_root()
    lock = read_lock(root)
    resources = docker_resources()
    line("docker", f"{resources.cpus} CPUs · {resources.memory_gb} GB for containers")
    profile, why = propose_profile(resources)
    line("profile", f"{profile} · {why}")
    models = load_models(lock)
    if not models:
        line("models", "none registered; add weights with `veritas models add <file>`")
        return
    image = _model_image(lock)
    for model in models.values():
        try:
            b = asyncio.run(benchmark(model, image, PROFILES[profile].limits))
        except Exception as exc:  # report and continue with the next model
            line("error", f"{model.name}: {type(exc).__name__}: {exc}")
            continue
        memory = f" · {b.memory_mb:.0f} MiB" if b.memory_mb is not None else ""
        line("bench", f"{b.model} · load {b.load_s} s · prompt {b.prompt_tps} tok/s · "
                      f"generate {b.generate_tps} tok/s{memory}")  # fmt: skip
