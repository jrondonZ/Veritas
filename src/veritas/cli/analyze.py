"""`veritas charter`, `veritas analyze`, `veritas spec`, and `veritas cleanroom` (docs/architecture.md §8.3)."""

from __future__ import annotations

import asyncio
import secrets
import sys
from pathlib import Path
from typing import Annotated

import typer

from ..analyze.charter import check_charter
from ..analyze.cleanroom import (
    PASS_TARGET,
    DirtyInput,
    Draft,
    HarnessLauncher,
    NotApproved,
    Verification,
    draft,
    load_approved,
    load_spec,
    verify,
)
from ..analyze.runner import AnalyzeError, AnalyzeOptions, analyze
from ..models import ModelService, ResponseCache, RouteUnavailable, TokenBudget, load_models, load_routing
from ..sandbox import read_lock
from ..sandbox.engine import JobError, harness_argv
from ..sandbox.images import CONFORMANCE_JS_IMAGE, MODEL_IMAGE
from ..store import Workspace
from .output import EXIT_FINDINGS, EXIT_INVALID, line, project_root, refreshes

charter_app = typer.Typer(no_args_is_help=True, help="Validate and acknowledge analysis charters.")
analyze_app = typer.Typer(no_args_is_help=True, help="Reverse-engineer owned or permitted software with evidence.")
spec_app = typer.Typer(no_args_is_help=True, help="Review and approve behavior specs (the clean-room gate).")
cleanroom_app = typer.Typer(no_args_is_help=True, help="Replicate behavior from an approved spec, then verify it.")


@charter_app.command("check")
@refreshes
def charter_check(file: Annotated[Path, typer.Argument(help="Charter file to validate.")]) -> None:
    """Validate a charter, pin its subjects, and acknowledge its digest."""
    report = check_charter(file)
    charter = report.charter
    if charter is not None:
        line("charter", f"{charter.metadata.name} · {report.digest or 'no digest (errors)'} · basis {charter.basis}")
        line("purpose", " ".join(charter.purpose.split()))
        for subject in charter.subjects:
            line("subject", f"{subject.path} · sha256:{subject.sha256[:16]}…")
        if charter.conformance is not None:
            line("vectors", f"{charter.conformance.vectors} · {len(report.vectors)} vectors calling {report.call}")
        models = "models on (local only)" if charter.constraints.models else "models off"
        line("limits", f"static only: the subject is never run · no network · {models}")
    for notice in report.notices:
        line("notice", notice)
    for error in report.errors:
        line("error", error)
    if not report.ok or charter is None or report.digest is None:
        raise typer.Exit(EXIT_INVALID)
    ws = Workspace(project_root())
    try:
        if ws.is_acknowledged(report.digest):
            line("ack", "already acknowledged")
            return
        if not sys.stdin.isatty():
            line("ack", "not acknowledged; run this command in an interactive terminal to acknowledge")
            raise typer.Exit(EXIT_INVALID)
        if not typer.confirm("Acknowledge this charter?", default=False):
            line("ack", "not acknowledged")
            raise typer.Exit(EXIT_INVALID)
        summary = {"subjects": {s.path: s.sha256 for s in charter.subjects}, "file": str(file)}
        ws.acknowledge(report.digest, charter.metadata.name, summary)
        line("ack", "acknowledged")
    finally:
        ws.close()


@analyze_app.command("run")
@refreshes
def analyze_run(
    charter: Annotated[
        Path, typer.Option("--charter", help="Charter file (acknowledged with `veritas charter check`).")
    ],
) -> None:
    """Analyze the charter's subjects statically and write a behavior spec draft for review."""
    try:
        result = asyncio.run(analyze(charter, project_root(), AnalyzeOptions(log=line)))
    except AnalyzeError as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    spec = result.document["spec"]
    line("run", f"{result.run_id} · {result.outcome} · {result.document['duration_s']} s")
    for text in result.document["limitations"]:
        line("limit", text)
    line("spec", f"{spec['claims']} claims · {spec['gate']['passed']} passed the gate · {spec['gate']['blocked']} "
                 f"blocked · {spec['digest'][:19]}…")  # fmt: skip
    for finding in result.code:
        where = f"{finding['file']}:{finding['line']}" if finding["line"] else finding["file"]
        if finding["function"]:
            where += f" · {finding['function']}"  # a function, or for a recording the endpoint or origin
        live = f" · confirm with {finding['confirms_with']}" if finding["confirms_with"] else ""
        line(finding["if_confirmed"]["severity"].upper(), f"{finding['id']} {finding['title']} · {where}{live}")
    line("reports", f".veritas/runs/{result.run_id}/ (report.md, spec.json, code-findings.sarif)")
    line("next", f"veritas spec show {result.run_id} · veritas spec approve {result.run_id}")


@spec_app.command("show")
def spec_show(run_id: Annotated[str, typer.Argument(metavar="RUN")]) -> None:
    """Print the spec exactly as it would cross into a clean room."""
    ws = Workspace(project_root())
    try:
        approved = load_spec(ws, run_id)
        state = "approved" if ws.spec_approved(run_id, approved.digest) else "not approved"
    except (KeyError, NotApproved, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()
    line("spec", f"{run_id} · {approved.digest} · {state}")
    for interface in approved.clean["interfaces"]:
        typer.echo("")
        line(interface["id"], interface["title"])
        for claim in interface["claims"]:
            line(claim["kind"][:8], f"{claim['text']}  ({claim['id']})")
    conformance = approved.clean["conformance"]
    typer.echo("")
    line("vectors", f"{len(conformance['vectors'])} operator-owned vectors calling {conformance['call']}")


@spec_app.command("approve")
@refreshes
def spec_approve(run_id: Annotated[str, typer.Argument(metavar="RUN")]) -> None:
    """Approve one spec version for the clean room. Interactive only: a person types the run ID."""
    ws = Workspace(project_root())
    try:
        approved = load_spec(ws, run_id)
        if ws.spec_approved(run_id, approved.digest):
            line("spec", "already approved")
            return
        if not sys.stdin.isatty():
            line("spec", "not approved; run this command in an interactive terminal")
            raise typer.Exit(EXIT_INVALID)
        claims = sum(len(i["claims"]) for i in approved.clean["interfaces"])
        line("spec", f"{run_id} · {approved.digest}")
        line("crosses", f"{claims} claims and {len(approved.clean['conformance']['vectors'])} operator-owned vectors; "
                        f"no evidence, subject code, or internal names")  # fmt: skip
        answer = typer.prompt(f"Type {run_id} to approve, anything else to stop", default="", show_default=False)
        if answer.strip() != run_id:
            line("spec", "not approved")
            raise typer.Exit(EXIT_INVALID)
        ws.approve_spec(run_id, approved.digest)
        approved.run.audit.append("spec.approved", digest=approved.digest, claims=claims, actor="operator")
        line("spec", "approved")
    except (KeyError, NotApproved, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()


def _harness(root: Path, run_id: str) -> HarnessLauncher:
    image = read_lock(root).get("images", {}).get(CONFORMANCE_JS_IMAGE)
    if image is None:
        line("error", "the conformance harness image is missing; run `veritas images build`")
        raise typer.Exit(EXIT_INVALID)
    sandbox = f"{run_id}-{secrets.token_hex(3)}"
    return lambda impl, samples: (harness_argv(sandbox, image, impl, samples), {})


def _report(result: Verification) -> None:
    line("vectors", f"{result.passed}/{result.total} passed (target {PASS_TARGET:.0%})"
                    + (f" · {result.error}" if result.error else ""))  # fmt: skip
    for r in result.results:
        if not r["pass"]:
            line("failed", f"{r['id']}: got {r['got']}")
    sim = result.similarity
    line("similar", f"{sim['overall']:.0%} of the code's fingerprints occur in the subject (limit {sim['limit']:.0%}) "
                    f"· operator only")  # fmt: skip
    line("result", "verified" if result.verified else "not verified")


@cleanroom_app.command("verify")
@refreshes
def cleanroom_verify(
    run_id: Annotated[str, typer.Argument(metavar="RUN")],
    impl: Annotated[Path, typer.Option("--impl", help="Directory with the clean-room implementation.")],
    entry: Annotated[str, typer.Option(help="Module inside --impl that exports the vectors' function.")] = "index.mjs",
) -> None:
    """Run an implementation against the approved spec's vectors, and audit its similarity to the subject."""
    root = project_root()
    ws = Workspace(root)
    try:
        approved = load_approved(ws, run_id)
        count = len(list((approved.run.dir / "cleanroom").glob("verify-*"))) + 1
        result = verify(ws, approved, impl, entry, _harness(root, run_id), f"verify-{count}")
    except (KeyError, NotApproved, DirtyInput, JobError, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()
    _report(result)
    if not result.verified:
        raise typer.Exit(EXIT_FINDINGS)


@cleanroom_app.command("draft")
@refreshes
def cleanroom_draft(
    run_id: Annotated[str, typer.Argument(metavar="RUN")],
    rounds: Annotated[
        int,
        typer.Option(
            min=1,
            max=8,
            help="Drafts to try, each told only which vectors failed. Small models are "
            "cheap per round, so more rounds can pay off.",
        ),
    ] = 3,
) -> None:
    """Have a local model write an implementation from the approved spec alone, then verify it.

    The `code` route writes it: a small coding model if you chose one (`veritas models route code <name>`),
    otherwise the model that serves `analysis`.
    """
    root = project_root()
    lock = read_lock(root)
    image = lock.get("images", {}).get(MODEL_IMAGE)
    routing = load_routing(root, load_models(lock))
    try:
        served = routing.resolve("code")
    except RouteUnavailable as exc:
        line("error", f"no local model: {exc}")
        raise typer.Exit(EXIT_INVALID) from None
    via = f" (the code route is aliased to {served.serving})" if served.aliased else ""
    line("model", f"{served.model.name} · {served.model.quantization} · {served.model.license}{via}")
    if image is None:
        line("error", "the model server is missing; run `veritas images build --models`")
        raise typer.Exit(EXIT_INVALID)
    ws = Workspace(root)
    try:
        approved = load_approved(ws, run_id)
        service = ModelService(routing, image, f"{run_id}-{secrets.token_hex(3)}", approved.run.audit,
                               ResponseCache(root), TokenBudget(2_000_000), log=line)  # fmt: skip

        async def main() -> list[Draft]:
            try:
                return await draft(ws, approved, service, _harness(root, run_id), rounds)
            finally:
                await service.close()

        drafts = asyncio.run(main())
    except (KeyError, NotApproved, DirtyInput, JobError, OSError) as exc:
        line("error", str(exc))
        raise typer.Exit(EXIT_INVALID) from None
    finally:
        ws.close()
    for d in drafts:
        line("draft", f"{d.task} · {d.status}" + (f" ({d.reason})" if d.reason else ""))
        if d.verification is not None:
            _report(d.verification)
    final = drafts[-1].verification if drafts else None
    if final is None or not final.verified:
        raise typer.Exit(EXIT_FINDINGS)
