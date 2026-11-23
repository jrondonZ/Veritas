"""The Assess pipeline (docs/architecture.md §8.1).

scope check -> lab check -> sandbox up -> recon -> plan -> gate (policy, approvals)
-> probes (attempts, oracles) -> findings -> teardown, capture ingest, lab reset.
"""

from __future__ import annotations

import copy
import os
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..agents.enrich import enrich
from ..core.canonical import digest, sha256_hex
from ..core.impact import Impact
from ..core.tokens import new_run_key
from ..environments import Lab
from ..findings import Finding
from ..findings.lint import drop_unsupported, lint_document
from ..gateway.admission import GatewayConfig, GatewayIdentity, GatewayTarget
from ..imports.har import Catalog, HarError, parse_har
from ..models import ModelService, ResponseCache, RouteUnavailable, TokenBudget, load_models, load_routing
from ..plugins.host import start_plugin
from ..plugins.manifest import load_manifest
from ..reports import write_reports
from ..reports.sarif import web_objects
from ..sandbox import EXECUTOR_IMAGE, GATEWAY_IMAGE, SENSOR_IMAGE, RunSandbox, read_lock, remove_labeled
from ..sandbox.images import ACTIVITY_SENSOR_IMAGE, MODEL_IMAGE
from ..scope import ScopeReport, check_scope
from ..scope.model import AssessmentScope, Identity, Sensor, Target
from ..store import EXCHANGE_MEDIA_TYPE, Run, Workspace, ingest_gateway_capture
from .checks import CHECKS, Check, OracleResult, PlanContext, SensorCheck, run_oracle
from .evidence import CaptureEvidence, EvidenceSource, SensorRecord, WorkspaceEvidence
from .executor import Executor
from .outcomes import AttemptResult, blocked_finding, build_finding, coverage, number, summary
from .policy import ApprovalRequest, Approver, Decision, approval_digest, decide, deny_all
from .probes import Probe, outside_scope, probe_impact
from .recon import ReconResult, run_recon
from .sensors import SensorError, SensorHub, SensorSession

SCHEMA = "veritas/findings/v1alpha1"
EXECUTOR_MANIFEST = Path("plugins") / "http-executor" / "veritas-plugin.yaml"
# sensor kind -> (image, manifest, where the sensor sees its read-only volume)
SENSOR_PLUGINS = {
    "query-log": (SENSOR_IMAGE, Path("plugins") / "query-log-sensor" / "veritas-plugin.yaml", "/inputs/query-log"),
    "activity-log": (
        ACTIVITY_SENSOR_IMAGE, Path("plugins") / "activity-log-sensor" / "veritas-plugin.yaml", "/inputs/app-logs",
    ),
}  # fmt: skip
Log = Callable[[str, str], None]


class RunError(Exception):
    """The run cannot start: an invalid or unacknowledged scope, missing images, or a stopped lab."""


@dataclass
class RunOptions:
    attempts: int = 3
    approver: Approver = deny_all
    log: Log = field(default=lambda label, text: None)
    models: bool | None = None  # None follows the scope's policy.models; finding status is the same either way


@dataclass
class RunResult:
    run_id: str
    outcome: str
    findings: list[Finding]
    document: dict[str, Any]
    leftovers: list[str] = field(default_factory=list)


@dataclass
class _Item:
    check: Check
    probe: Probe
    impact: Impact
    decision: Decision
    approval: str | None = None

    @property
    def runs(self) -> bool:
        return self.decision.verdict == "allow" or self.approval is not None


def load_recordings(report: ScopeReport, target: Target) -> list[Catalog]:
    """The target's recordings, each checked against the hash in the scope digest, then read in memory.

    Their raw bytes hold live credentials, so they're never copied into the workspace; recon keeps routes only.
    """
    out = []
    for n, name in enumerate(target.recordings):
        data = (report.path.parent / name).read_bytes()
        if "sha256:" + sha256_hex(data) != report.files.get(f"targets.{target.id}.recordings.{n}"):
            raise RunError(f"{name} changed after the scope was checked")
        try:
            out.append(parse_har(data))
        except HarError as exc:
            raise RunError(f"{name} isn't a HAR recording Veritas can read: {exc}") from exc
    return out


def gateway_config(report: ScopeReport, target: Target, identities: tuple[Identity, ...], run_id: str) -> GatewayConfig:
    pinned = next(p for p in report.pinned if p.id == target.id)
    gateway_target = GatewayTarget(
        id=target.id,
        scheme=target.scheme,
        host=target.host,
        port=target.port,
        addresses=pinned.addresses,
        allow_paths=list(target.allow.paths),
        allow_methods=list(target.allow.methods),
        deny_paths=list(target.deny.paths),
        unsafe_get=list(target.unsafe_get),
        rps=target.limits.rps,
        concurrency=target.limits.concurrency,
        max_requests=target.limits.max_requests,
    )
    gateway_identities = [
        GatewayIdentity(
            id=i.id,
            target=i.target,
            login_path=i.login.path,
            username=i.login.username,
            username_field=i.login.username_field,
            password_field=i.login.password_field,
        )
        for i in identities
    ]
    return GatewayConfig(run=run_id, targets=[gateway_target], identities=gateway_identities)


def _secrets(identities: tuple[Identity, ...], lab: Lab) -> dict[str, str]:
    lab_values = lab.secrets()
    found = {}
    for identity in identities:
        scheme, _, name = identity.secret.partition(":")
        value = (os.environ.get(name) or lab_values.get(name)) if scheme == "env" else None
        if not value:
            raise RunError(f"identity {identity.id}: secret {identity.secret} is not available")
        found[identity.id] = value
    return found


def _gate(
    planned: list[tuple[Check, Probe]], scope: AssessmentScope, scope_digest: str, run: Run, options: RunOptions
) -> list[_Item]:
    target = scope.targets[0]
    items = []
    for check, probe in planned:
        impact = probe_impact(check.info.impact, probe.steps, target)
        items.append(_Item(check, probe, impact, decide(impact, scope, outside_scope(probe.steps, target))))
    batches: dict[tuple[str, str], list[_Item]] = {}
    for item in items:
        if item.decision.verdict == "needs_approval":
            batches.setdefault((item.check.id, str(item.impact)), []).append(item)
    for n, ((check_id, impact_name), group) in enumerate(sorted(batches.items()), 1):
        probes = tuple(g.probe for g in group)
        batch_impact = Impact(impact_name)
        request = ApprovalRequest(
            f"A-{n:04d}",
            run.id,
            check_id,
            batch_impact,
            probes,
            options.attempts,
            approval_digest(run.id, scope_digest, check_id, batch_impact, probes, options.attempts),
        )
        run.audit.append(
            "approval.requested",
            approval=request.id,
            digest=request.digest,
            check=check_id,
            impact=impact_name,
            probes=len(probes),
        )
        granted = options.approver(request)
        run.audit.append(
            "approval.granted" if granted else "approval.denied", approval=request.id, digest=request.digest
        )
        for item in group:
            if granted:
                item.approval = request.id
            else:
                item.decision = Decision(
                    "needs_approval",
                    item.decision.rule,
                    f"{item.decision.reason}; approval {request.id} was not granted",
                )
    return items


async def _probe(
    item: _Item, executor: Executor, evidence: EvidenceSource, sensors: SensorHub | None, attempts: int
) -> list[AttemptResult]:
    check, probe = item.check, item.probe
    results: list[AttemptResult] = []
    if probe.passive:
        for n, evidence_id in enumerate(probe.evidence, 1):
            exchange = evidence.get(evidence_id)
            results.append(AttemptResult(n, check.evaluate(probe, [exchange], n), [exchange], None))
        return results
    sensing = check if isinstance(check, SensorCheck) else None
    if sensing is not None and (sensors is None or sensing.sensor not in sensors.kinds):
        raise SensorError(f"{check.id} needs a {sensing.sensor} sensor, and none is running")
    for n in range(1, attempts + 1):
        since = await sensors.mark(sensing.sensor) if sensing and sensors else 0
        exchanges = await executor.run(
            check.steps_for(probe, n), item.impact, f"{check.id}: {probe.description} (attempt {n})", item.approval
        )
        signals: tuple[SensorRecord, ...] = ()
        if sensing and sensors:
            signals = (await sensors.collect(sensing.sensor, sensing.markers(probe, n), since),)
        captured = [e for e in exchanges if e is not None]
        if len(captured) < len(exchanges):
            result = OracleResult.errored("a request was refused or failed; see the audit log")
        else:
            result = run_oracle(check, probe, captured, signals, n)
        results.append(AttemptResult(n, result, list(exchanges), executor.last_tid, signals))
        if result.verdict != "pass":
            break  # only a pass is reproduced
    return results


async def _enrich(
    document: dict[str, Any],
    ws: Workspace,
    run: Run,
    scope: AssessmentScope,
    root: Path,
    images: dict[str, str],
    sandbox_id: str,
    log: Log,
) -> dict[str, Any]:
    """Stage 9 with models (§8.1). Without a usable model the run is exactly a rules-only run."""
    image = images.get(MODEL_IMAGE)
    if image is None:
        return {"status": "unavailable", "reason": "the model-server image is missing; run `veritas images build`"}
    routing = load_routing(root, load_models(read_lock(root)))
    try:
        served = routing.resolve("analysis")
    except RouteUnavailable as exc:
        return {"status": "unavailable", "reason": str(exc)}
    log("models", f"{served.model.name} · {served.model.quantization} · {served.model.license} · "
                  f"profile {routing.profile.name}")  # fmt: skip
    service = ModelService(
        routing,
        image,
        sandbox_id,
        run.audit,
        ResponseCache(root),
        TokenBudget(scope.budgets.model_tokens),
        redact_prompts=scope.policy.prompt_redaction,
        log=log,
    )
    draft = copy.deepcopy(document)  # committed only if the whole stage finishes
    try:
        result = await enrich(draft, WorkspaceEvidence(ws), service, routing)
    except Exception as exc:  # model trouble never fails a run: findings stay as the rules wrote them
        run.audit.append("model.abort", reason=f"{type(exc).__name__}: {exc}")
        return {"status": "error", "reason": f"{type(exc).__name__}: {exc}"}
    finally:
        await service.close()
    document.update(draft)
    log("enrich", f"{result['calls']} model calls · {result['cache_hits']} cached · {result['tokens']} tokens · "
                  f"{result['duration_s']} s")  # fmt: skip
    return {"status": "on", **result}


async def _start_sensors(
    sandbox: RunSandbox, sensors: list[Sensor], lab: Lab, images: dict[str, str], root: Path, ws: Workspace, run: Run
) -> SensorHub:
    started: list[SensorSession] = []
    try:
        for sensor in sensors:
            image_tag, manifest_path, mount = SENSOR_PLUGINS[sensor.kind]
            manifest = load_manifest(root / manifest_path)
            argv = sandbox.sensor_argv(images[image_tag], manifest, sensor.id, lab.volume(sensor.volume), mount)
            session = await start_plugin(argv, manifest)
            started.append(SensorSession(sensor.id, sensor.kind, session, images[image_tag]))
    except BaseException:
        for s in started:
            await s.session.close()
        raise
    run.audit.append("sensor.start", sensors=[{"id": s.sensor_id, "plugin": s.ref, "image": s.image} for s in started])
    return SensorHub(started, ws, run)


def _recon_summary(recon: ReconResult | None) -> dict[str, Any] | None:
    if recon is None:
        return None
    return {
        "routes": [r.label for r in recon.routes],
        "auth": [r.label for r in recon.routes if r.auth],
        "fetches": len(recon.pages),
        "logins": sorted(recon.logins),
        "external_links": recon.external_links,
        "skipped": recon.skipped,
    }


async def assess(
    scope_path: Path, root: Path, options: RunOptions, only: list[tuple[Check, Probe]] | None = None
) -> RunResult:
    """Run the pipeline. With `only`, skip recon and planning and run just those probes (reproduce)."""
    report = check_scope(scope_path)
    if not report.ok or report.scope is None or report.digest is None:
        raise RunError("the scope is invalid: " + "; ".join(report.errors))
    scope, scope_digest = report.scope, report.digest
    if len(scope.targets) != 1:
        raise RunError("Phase 1 assesses exactly one target per scope")
    if scope.environment.provider != "compose" or not scope.environment.compose_file:
        raise RunError("Phase 1 runs only against compose lab environments")
    target = scope.targets[0]
    identities = tuple(sorted((i for i in scope.identities if i.target == target.id), key=lambda i: i.id))
    sensors = sorted((s for s in scope.sensors if s.target == target.id), key=lambda s: s.id)
    ws = Workspace(root)
    try:
        if not ws.is_acknowledged(scope_digest):
            raise RunError("this scope digest is not acknowledged; run `veritas scope check` in a terminal first")
        images = read_lock(root).get("images", {})
        needed = [GATEWAY_IMAGE, EXECUTOR_IMAGE, *(SENSOR_PLUGINS[s.kind][0] for s in sensors)]
        if any(tag not in images for tag in needed):
            raise RunError("first-party images are missing; run `veritas images build`")
        lab = Lab.from_compose(scope_path.parent / scope.environment.compose_file, root)
        try:
            lab.health()
        except Exception as exc:
            raise RunError(f"the lab is not running; start it with `veritas lab up {lab.name}`") from exc
        identity_secrets = _secrets(identities, lab)
        return await _run(
            ws,
            report,
            scope,
            scope_digest,
            target,
            identities,
            sensors,
            lab,
            images,
            identity_secrets,
            root,
            options,
            only,
        )
    finally:
        ws.close()


async def _run(
    ws: Workspace,
    report: ScopeReport,
    scope: AssessmentScope,
    scope_digest: str,
    target: Target,
    identities: tuple[Identity, ...],
    sensors: list[Sensor],
    lab: Lab,
    images: dict[str, str],
    identity_secrets: dict[str, str],
    root: Path,
    options: RunOptions,
    only: list[tuple[Check, Probe]] | None,
) -> RunResult:
    log, started_at, started = options.log, datetime.now(UTC), time.monotonic()
    run = ws.create_run("assess" if only is None else "reproduce", scope_digest)
    sandbox_id = f"{run.id}-{secrets.token_hex(3)}"  # Docker names must be unique across workspaces
    key = new_run_key()
    config = gateway_config(report, target, identities, sandbox_id)
    sandbox = RunSandbox(
        sandbox_id,
        run.dir,
        images[GATEWAY_IMAGE],
        config,
        key,
        target_networks=lab.networks(),
        identity_secrets=identity_secrets,
    )
    run.audit.append(
        "run.start",
        scope=scope_digest,
        scope_name=scope.metadata.name,
        veritas=__version__,
        sandbox=sandbox_id,
        images=images,
        gateway_config=digest(config.model_dump(mode="json")),
        sensors=[s.id for s in sensors],
    )
    ctx = PlanContext(
        target, identities, tag=scope_digest.removeprefix("sha256:")[:12], sensors=frozenset(s.kind for s in sensors)
    )
    findings: list[Finding] = []
    recon: ReconResult | None = None
    outcome, message, mutated = "completed", "", False
    leftovers: list[str] = []
    try:
        log("sandbox", f"{run.id} · starting the gateway and the executor")
        sandbox.up()
        manifest = load_manifest(root / EXECUTOR_MANIFEST)
        session = await start_plugin(
            sandbox.plugin_argv(images[EXECUTOR_IMAGE], manifest, "exec"), manifest, env=sandbox.executor_env()
        )
        hub: SensorHub | None = None
        try:
            evidence = CaptureEvidence(sandbox.capture_dir)
            executor = Executor(session, sandbox, key, target, evidence, run.audit, manifest.ref)
            if only is None:
                recordings = load_recordings(report, target)
                if recordings:
                    run.audit.append("recon.recordings", target=target.id, files={
                        name: report.files[f"targets.{target.id}.recordings.{n}"]
                        for n, name in enumerate(target.recordings)})  # fmt: skip
                recon = await run_recon(executor, target, identities, recordings)
                recorded = sum(r.source == "recording" for r in recon.routes)
                log(
                    "recon",
                    f"{len(recon.routes)} routes ({recorded} from recordings) · {len(recon.pages)} fetches · "
                    f"{len(recon.logins)} sign-ins · {len(recon.external_links)} external links recorded, not fetched",
                )
                planned = [(c, p) for c in CHECKS for p in c.plan(recon, ctx)]
            else:
                planned = only
            items = _gate(planned, scope, scope_digest, run, options)
            log(
                "plan",
                f"{len(items)} probes · {sum(i.decision.verdict == 'allow' for i in items)} auto-approved · "
                f"{sum(i.approval is not None for i in items)} approved · {sum(not i.runs for i in items)} blocked",
            )
            if any(i.runs and isinstance(i.check, SensorCheck) for i in items):
                hub = await _start_sensors(sandbox, sensors, lab, images, root, ws, run)
                log("sensor", f"{', '.join(sorted(hub.kinds))} · no network, read-only volume")
            for item in items:
                if not item.runs:
                    findings.append(blocked_finding(item.check, item.probe, ctx, item.decision.reason))
                    continue
                mutated = mutated or item.impact in (Impact.MUTATE, Impact.SENSITIVE)
                results = await _probe(item, executor, evidence, hub, options.attempts)
                findings.append(build_finding(item.check, item.probe, results, ctx))
        finally:
            if hub is not None:
                await hub.close()
            await session.close()
    except Exception as exc:  # every failure still ends the run with a named outcome
        outcome, message = "aborted", f"{type(exc).__name__}: {exc}"
        run.audit.append("run.abort", reason=message)
    finally:
        leftovers = sandbox.down()
        ingest_gateway_capture(ws, run, sandbox.capture_dir)
        if mutated:
            log("reset", f"restoring {lab.name} from snapshot s-01")
            lab.reset()
            run.audit.append("environment.reset", lab=lab.name, snapshot="s-01")
    findings = number(findings)
    if outcome == "completed" and any(f.status in ("blocked", "error") for f in findings):
        outcome = "completed_with_gaps"
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "run": run.id,
        "veritas": __version__,
        "outcome": outcome,
        "message": message,
        "started": started_at.isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - started, 1),
        "scope": {"name": scope.metadata.name, "digest": scope_digest},
        "target": {"id": target.id, "base_url": target.base_url, "addresses": config.targets[0].addresses},
        "summary": summary(findings),
        "coverage": coverage(findings),
        "recon": _recon_summary(recon),
        "findings": [f.to_json() for f in findings],
    }
    use_models = scope.policy.models if options.models is None else options.models
    if not use_models:
        document["models"] = {"status": "off"}
    elif outcome == "aborted":
        document["models"] = {"status": "skipped", "reason": "the run was aborted"}
    else:
        document["models"] = await _enrich(document, ws, run, scope, root, images, sandbox_id, log)
        leftovers += remove_labeled(sandbox_id)  # a model sandbox that outlived its stage
    # No unsupported claim reaches a report: every claim is typed and every reference resolves (§10.4).
    problems = lint_document(document, ws.evidence_ids(run.id).__contains__)
    dropped = drop_unsupported(document, problems)
    findings = [Finding.from_json(f) for f in document["findings"]]
    document["summary"] = summary(findings)  # a model-adjusted CVSS score can change a severity
    document["duration_s"] = round(time.monotonic() - started, 1)
    document["lint"] = {
        "claims": sum(len(f.claims) for f in findings),
        "dropped": dropped,
        "problems": [str(p) for p in problems],
    }
    run.audit.append("report.lint", claims=document["lint"]["claims"], dropped=dropped, problems=len(problems))
    stored = WorkspaceEvidence(ws)
    web: dict[str, Any] = {}
    for finding in findings:
        exchange_ids = (e for c in finding.claims for e in c.evidence if stored.media_type(e) == EXCHANGE_MEDIA_TYPE)
        first = next(exchange_ids, None)
        if first and finding.status in ("confirmed", "inconclusive"):
            web[first] = web_objects(stored.get(first))
    write_reports(run.dir, document, web)
    run.audit.append("run.end", outcome=outcome, findings=len(findings), leftovers=leftovers)
    ws.set_outcome(run.id, outcome)
    return RunResult(run.id, outcome, findings, document, leftovers)
