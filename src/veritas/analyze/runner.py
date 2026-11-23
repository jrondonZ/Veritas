"""The Analyze pipeline (docs/architecture.md §8.3).

charter check -> acknowledgment -> intake -> engines (sandboxed, no network) -> Program Model
-> mechanical spec draft -> claim lint -> spec gate filters -> clean view and its digest -> reports.

Everything up to the gate is dirty. The clean view is what may cross boundary B5, and only
after a person approves its digest (`veritas spec approve`). The subject itself is never
executed (the charter's `execute_subject` is always false in this phase).
"""

from __future__ import annotations

import json
import secrets
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .. import __version__
from ..core.canonical import canonical_bytes
from ..findings.lint import lint_claims
from ..imports.har import HarError, parse_har
from ..imports.osv import open_advisories
from ..plugins.host import start_plugin
from ..plugins.manifest import PluginManifest, load_manifest
from ..sandbox import read_lock
from ..sandbox.engine import engine_argv
from ..sandbox.images import BINARY_ENGINE_IMAGE, JS_ENGINE_IMAGE
from ..store import Run, Workspace
from .charter import AnalysisCharter, CharterReport, check_charter
from .dependencies import dependency_candidates
from .gate import Gate, GateResult, clean_view, spec_digest
from .intake import SUBJECT_MEDIA_TYPE, Subject, stage
from .program import FileModel
from .report import render_analysis
from .sarif import render_code_sarif
from .sbom import render_sbom
from .security import code_findings
from .security import summary as code_summary
from .sources import SourceError, subject_sources
from .spec import build_spec

PROGRAM_MEDIA_TYPE = "application/vnd.veritas.program-model+json"
SCHEMA = "veritas/analysis/v1alpha1"


@dataclass(frozen=True)
class EngineSpec:
    image: str
    manifest: Path
    entry: str  # the plugin's script, run directly by the local launcher
    runtime: str  # "node" or "python"


_JS = EngineSpec(JS_ENGINE_IMAGE, Path("plugins") / "js-engine" / "veritas-plugin.yaml", "plugin.mjs", "node")
_BINARY = EngineSpec(BINARY_ENGINE_IMAGE, Path("plugins") / "binary-engine" / "veritas-plugin.yaml", "plugin.py",
                     "python")  # fmt: skip
# subject type -> engine. Electron archives go to the JavaScript engine, which reads them in memory; .NET assemblies
# are PE files, and the binary engine reads their metadata.
ENGINES = {"javascript": _JS, "asar": _JS, "pe": _BINARY, "elf": _BINARY, "macho": _BINARY}
COMPILED = {"pe", "elf", "macho"}


def _read_har(data: bytes) -> dict[str, Any]:
    try:
        return parse_har(data).to_json()
    except HarError as err:
        return {"error": f"not read as a HAR recording: {err}"}


# subject type -> reader for recordings: data, not code, parsed in-process by the standard library. Their raw bytes
# hold live secrets, so only what the reader keeps is stored.
READERS: dict[str, Callable[[bytes], dict[str, Any]]] = {"har": _read_har}


def _binary_notes(path: str, facts: dict[str, Any]) -> tuple[dict[str, int], list[str]]:
    """A compiled subject's counts, and what the analysis of it can't do."""
    managed = facts.get("dotnet") or {}
    counts = {"sections": len(facts.get("sections") or []), "libraries": len(facts.get("libraries") or []),
              "imports": len(facts.get("imports") or [])}  # fmt: skip
    if managed:
        counts |= {"types": managed.get("types", 0), "methods": managed.get("methods", 0)}
    notes = [f"{path}: compiled code isn't disassembled, so the clean-room similarity audit has no source to compare; "
             "an implementation of it is checked against vectors and hashes only"]  # fmt: skip
    if facts.get("withheld"):
        notes.append(f"{path}: {facts['withheld']} string(s) that mention licensing or copy protection were withheld")
    undecoded = (managed.get("il") or {}).get("undecoded", 0)
    if undecoded:
        notes.append(f"{path}: {undecoded} method bod(ies) couldn't be decoded, so their calls weren't checked")
    if facts.get("slices"):
        notes.append(f"{path}: a universal binary; only its first architecture ({facts['slices'][0]}) was read")
    if facts.get("encrypted"):
        notes.append(f"{path}: its code is encrypted, so strings and symbols may be missing")
    packed = [s["name"] for s in facts.get("sections") or [] if s.get("entropy", 0) > 7.2 and s.get("size", 0) > 4096]
    if packed:
        notes.append(
            f"{path}: section(s) {', '.join(packed[:4])} look compressed or encrypted (packed code hides facts)"
        )
    return counts, notes


def _har_counts(facts: dict[str, Any]) -> dict[str, int]:
    endpoints = facts.get("endpoints") or []
    return {"entries": facts.get("entries", 0), "endpoints": len(endpoints),
            "origins": len(facts.get("origins") or [])}  # fmt: skip


Log = Callable[[str, str], None]
# (sandbox id, subject type, manifest, staged inputs) -> (argv, extra environment)
Launcher = Callable[[str, str, PluginManifest, Path], tuple[list[str], dict[str, str]]]


class AnalyzeError(Exception):
    """The analysis cannot start or cannot trust an engine's answer."""


@dataclass
class AnalyzeOptions:
    log: Log = field(default=lambda label, text: None)
    launcher: Launcher | None = None  # None runs engines in Docker sandboxes from the image lock


@dataclass
class AnalyzeResult:
    run_id: str
    outcome: str
    document: dict[str, Any]
    draft: dict[str, Any]  # dirty: every claim, with evidence and the gate's decisions
    clean: dict[str, Any]  # what may cross B5 once approved
    gate: GateResult
    code: list[dict[str, Any]] = field(default_factory=list)  # candidate security findings in the subject's code


def docker_launcher(root: Path) -> Launcher:
    images = read_lock(root).get("images", {})

    def launch(sandbox_id: str, kind: str, manifest: PluginManifest, inputs: Path) -> tuple[list[str], dict[str, str]]:
        tag = ENGINES[kind].image
        if tag not in images:
            raise AnalyzeError(f"the {kind} engine image is missing; run `veritas images build`")
        return engine_argv(sandbox_id, images[tag], manifest, inputs, kind), {}

    return launch


def local_launcher(root: Path, node: str = "node") -> Launcher:
    """Run engines as local processes (tests and development only; no sandbox)."""

    def launch(sandbox_id: str, kind: str, manifest: PluginManifest, inputs: Path) -> tuple[list[str], dict[str, str]]:
        spec = ENGINES[kind]
        interpreter = node if spec.runtime == "node" else sys.executable
        return [interpreter, str(root / spec.manifest.parent / spec.entry)], {"VERITAS_INPUTS": str(inputs)}

    return launch


async def analyze(charter_path: Path, root: Path, options: AnalyzeOptions) -> AnalyzeResult:
    report = check_charter(charter_path)
    if not report.ok or report.charter is None or report.digest is None:
        raise AnalyzeError("the charter is invalid: " + "; ".join(report.errors))
    ws = Workspace(root)
    try:
        if not ws.is_acknowledged(report.digest):
            raise AnalyzeError(
                "this charter digest is not acknowledged; run `veritas charter check` in a terminal first"
            )
        launcher = options.launcher or docker_launcher(root)
        return await _run(ws, report, report.charter, report.digest, root, launcher, options.log)
    finally:
        ws.close()


async def _engine(
    kind: str, group: list[Subject], manifest: PluginManifest, argv_env: tuple[list[str], dict[str, str]]
) -> list[dict[str, Any]]:
    argv, env = argv_env
    session = await start_plugin(argv, manifest, env=env)
    try:
        reply = await session.call("analyze", {"files": [{"path": s.staged, "sha256": s.sha256} for s in group]})
    finally:
        await session.close()
    results = reply.get("results")
    if not isinstance(results, list) or len(results) != len(group):
        raise AnalyzeError(f"the {kind} engine returned {len(results or [])} results for {len(group)} files")
    for subject, result in zip(group, results, strict=True):
        if not isinstance(result, dict) or result.get("path") != subject.staged:
            raise AnalyzeError(f"the {kind} engine answered for a different file than {subject.path}")
        if not result.get("error") and result.get("sha256") != subject.sha256:
            raise AnalyzeError(f"the {kind} engine analyzed content that doesn't match {subject.path}")
    return results


async def _run(
    ws: Workspace,
    report: CharterReport,
    charter: AnalysisCharter,
    charter_digest: str,
    root: Path,
    launcher: Launcher,
    log: Log,
) -> AnalyzeResult:
    started_at, started = datetime.now(UTC), time.monotonic()
    run = ws.create_run("analyze", charter_digest)
    sandbox_id = f"{run.id}-{secrets.token_hex(3)}"
    run.audit.append(
        "run.start",
        charter=charter_digest,
        charter_name=charter.metadata.name,
        basis=charter.basis,
        purpose=charter.purpose,
        veritas=__version__,
        subjects=[s.path for s in charter.subjects],
    )
    inputs = run.dir / "inputs"
    staged: list[Subject] = []
    evidence_of: dict[str, str | None] = {}
    held: dict[str, bytes] = {}  # recordings, kept in memory for their reader and never stored
    for pinned in charter.subjects:
        subject, data = stage(report.base, pinned.path, inputs)
        if subject.sha256 != pinned.sha256:
            raise AnalyzeError(f"{pinned.path} changed after the charter was checked")
        if subject.staged:
            evidence_of[subject.path] = ws.add_evidence(run.id, data, SUBJECT_MEDIA_TYPE, "dirty:subject")
        else:
            evidence_of[subject.path], held[subject.path] = None, data
        run.audit.append("subject.intake", path=subject.path, sha256=subject.sha256, subject_type=subject.type,
                         size=subject.size, evidence=evidence_of[subject.path],
                         stored=bool(subject.staged))  # fmt: skip
        staged.append(subject)
    log("intake", f"{len(staged)} subject(s) · " + ", ".join(f"{s.path} ({s.type})" for s in staged))

    files: list[FileModel] = []
    limitations: list[str] = []
    subjects_out: list[dict[str, Any]] = []
    for kind in sorted({s.type for s in staged}):
        group = [s for s in staged if s.type == kind]
        if kind in READERS:
            ref = f"veritas.reader.{kind}@{__version__}"
            log("reader", f"{ref} · {len(group)} file(s) · in memory, values stripped, nothing stored raw")
            results = [READERS[kind](held[s.path]) for s in group]
        elif kind in ENGINES:
            manifest = load_manifest(root / ENGINES[kind].manifest)
            ref = manifest.ref
            log("engine", f"{ref} · {len(group)} file(s) · no network, inputs read-only")
            results = await _engine(kind, group, manifest, launcher(sandbox_id, kind, manifest, inputs))
        else:
            limitations += [f"{s.path}: no engine analyzes {kind} subjects in this phase" for s in group]
            subjects_out += [{"path": s.path, "sha256": s.sha256, "type": kind, "evidence": evidence_of[s.path],
                              "staged": s.staged} for s in group]  # fmt: skip
            continue
        for subject, result in zip(group, results, strict=True):
            entry: dict[str, Any] = {"path": subject.path, "sha256": subject.sha256, "type": kind,
                                     "evidence": evidence_of[subject.path], "engine": ref,
                                     "staged": subject.staged}  # fmt: skip
            if result.get("error"):
                limitations.append(f"{subject.path}: {result['error']}")
                subjects_out.append({**entry, "error": result["error"]})
                continue
            record = canonical_bytes({"v": 1, "kind": "program-model", "subject": subject.sha256, "path": subject.path,
                                      "engine": ref, "facts": result})  # fmt: skip
            facts_id = ws.add_evidence(run.id, record, PROGRAM_MEDIA_TYPE, f"dirty:engine:{ref}")
            if result.get("archive") == "asar":
                models, extra, notes = _archive(subject, facts_id, result)
                files += models
                limitations += notes
                entry |= extra
                parts = [m.facts for m in models[1:]]
            else:
                files.append(FileModel(subject.path, subject.sha256, facts_id, result))
                parts = [result]
                if result.get("kind") == "har":
                    entry["counts"] = _har_counts(result)
                    limitations += [f"{subject.path}: {n} entr{'y' if n == 1 else 'ies'} skipped ({why})"
                                    for why, n in (result.get("skipped") or {}).items()]  # fmt: skip
                if kind in COMPILED:
                    entry["counts"], notes = _binary_notes(subject.path, result)
                    limitations += notes
            counts = {k: n for k in ("functions", "exports", "strings", "reads", "writes")
                      if (n := sum(len(p.get(k) or []) for p in parts)) or kind == "javascript"}  # fmt: skip
            excluded = [e["function"] for p in parts for e in p.get("excluded") or []]
            run.audit.append("engine.facts", engine=ref, path=subject.path, evidence=facts_id,
                             counts=entry.get("counts", {}) | counts, excluded=excluded)  # fmt: skip
            truncated: dict[str, int] = {}
            for p in parts:
                for k, n in (p.get("truncated") or {}).items():
                    truncated[k] = truncated.get(k, 0) + n
            subjects_out.append({**entry, "facts": facts_id, "counts": entry.get("counts", {}) | counts,
                                 "excluded": len(excluded), "truncated": truncated})  # fmt: skip
    try:
        sources = subject_sources(inputs, subjects_out)
    except SourceError as err:
        raise AnalyzeError(str(err)) from err

    store = open_advisories(ws.root)  # imported offline by `veritas advisories import`; None if nothing is
    try:
        bundled, notes, dependencies = dependency_candidates(
            subjects_out, store, lambda data, media, source: ws.add_evidence(run.id, data, media, source)
        )
    finally:
        if store is not None:
            store.close()
    limitations += notes
    if dependencies["bundled"]:
        run.audit.append("advisories.match", **dependencies)
        log("deps", f"{dependencies['bundled']} bundled · " + (f"{dependencies['matched']} matched an advisory"
                    if dependencies["checked"] else "not checked: no advisories imported"))  # fmt: skip

    draft = build_spec(files)
    resolves = ws.evidence_ids(run.id).__contains__
    problems = lint_claims("spec", draft["claims"], resolves)
    if problems:
        raise AnalyzeError("the draft spec failed the claim linter: " + "; ".join(str(p) for p in problems[:3]))
    candidates = code_findings(files, bundled)
    problems = lint_claims("code", [c for f in candidates for c in f["claims"]], resolves)
    if problems:
        raise AnalyzeError("code findings failed the claim linter: " + "; ".join(str(p) for p in problems[:3]))
    code = code_summary(candidates)
    run.audit.append("code.findings", candidates=len(candidates), by_rule=code["by_rule"])
    by_rule = ", ".join(f"{n} {r}" for r, n in code["by_rule"].items()) or "none"
    log("code", f"{len(candidates)} candidate finding(s) · {by_rule}")
    gate = Gate(files, sources).run(draft["claims"])
    vectors = [
        {"id": v.id, "sample": v.sample, "sha256": report.files[f"sample:{v.sample}"], "expect": v.expect}
        for v in report.vectors
    ]
    clean = clean_view(draft, gate.passed, vectors, report.call)
    clean["digest"] = spec_digest(clean)
    draft["gate"] = {**gate.summary(), "blocked": gate.blocked}
    log("spec", f"{len(draft['claims'])} claims · gate passed {len(gate.passed)}, blocked {len(gate.blocked)} · "
                f"{clean['digest'][:19]}…")  # fmt: skip
    outcome = "completed_with_gaps" if limitations else "completed"
    document: dict[str, Any] = {
        "schema": SCHEMA,
        "run": run.id,
        "veritas": __version__,
        "outcome": outcome,
        "started": started_at.isoformat(timespec="seconds"),
        "duration_s": round(time.monotonic() - started, 1),
        "charter": {
            "name": charter.metadata.name,
            "digest": charter_digest,
            "basis": charter.basis,
            "purpose": charter.purpose.strip(),
            "deliverables": list(charter.deliverables),
            "path": _relative(report.path, ws.root.parent),  # what the clean room resolves samples against
        },
        "subjects": subjects_out,
        "limitations": limitations,
        "spec": {
            "claims": len(draft["claims"]),
            "gate": gate.summary(),
            "digest": clean["digest"],
            "approved": False,
            "vectors": len(vectors),
        },
    }
    document["code"] = code
    document["dependencies"] = dependencies
    _write(run, document, draft, clean, candidates)
    run.audit.append("spec.draft", claims=len(draft["claims"]), digest=clean["digest"], gate=gate.summary())
    run.audit.append("run.end", outcome=outcome)
    ws.set_outcome(run.id, outcome)
    return AnalyzeResult(run.id, outcome, document, draft, clean, gate, candidates)


def _archive(
    subject: Subject, facts_id: str, result: dict[str, Any]
) -> tuple[list[FileModel], dict[str, Any], list[str]]:
    """An Electron archive becomes a file model for the app (pages, dependencies) plus one per analyzed member.

    Members are named `<archive>!/<path inside it>`, and every model cites the archive's engine record. What the
    engine didn't read is said in the limitations.
    """
    app = {k: result.get(k) for k in ("pages", "dependencies", "package", "csp_in_code")}
    models = [FileModel(subject.path, subject.sha256, facts_id, app)]
    notes: list[str] = []
    members: list[dict[str, Any]] = []
    for member in result.get("members") or []:
        name = f"{subject.path}!/{member['path']}"
        if member.get("error"):
            notes.append(f"{name}: {member['error']}")
            continue
        models.append(FileModel(name, subject.sha256, facts_id, member))
        members.append({k: member.get(k) for k in ("path", "offset", "size", "sha256")})
    skipped = result.get("skipped") or {}
    for count, text in (
        (result.get("unpacked"), "stored unpacked next to the archive, so not analyzed"),
        (result.get("refused"), "with a name or offset that can't be trusted, so not read"),
        (skipped.get("too_large"), "too large to analyze"),
        (skipped.get("limit"), "past the per-archive analysis limit"),
    ):
        if count:
            notes.append(f"{subject.path}: {count} file(s) {text}")
    dependencies = [{"name": d.get("name"), "version": d.get("version"), "path": d.get("path")}
                    for d in app["dependencies"] or []]  # fmt: skip
    counts = {"members": len(members), "pages": len(app["pages"] or []), "dependencies": len(dependencies)}
    extra = {"members": members, "counts": counts, "package": app["package"], "dependencies": dependencies}
    return models, extra, notes


def _relative(path: Path, root: Path) -> str:
    """The charter's path relative to the project root when it's inside it (documents stay portable)."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return str(path.resolve())


def _dump(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True) + "\n"


def _write(
    run: Run, document: dict[str, Any], draft: dict[str, Any], clean: dict[str, Any], candidates: list[dict[str, Any]]
) -> None:
    (run.dir / "analysis.json").write_text(_dump(document), encoding="utf-8")
    (run.dir / "spec-draft.json").write_text(_dump(draft), encoding="utf-8")  # dirty: stays with the operator
    (run.dir / "spec.json").write_text(_dump(clean), encoding="utf-8")  # crosses B5 once approved
    code = {"schema": "veritas/code-findings/v1alpha1", "run": run.id, "summary": document["code"],
            "findings": candidates}  # fmt: skip
    (run.dir / "code-findings.json").write_text(_dump(code), encoding="utf-8")  # dirty: names internal code
    (run.dir / "code-findings.sarif").write_text(_dump(render_code_sarif(candidates, run.id)), encoding="utf-8")
    sbom = render_sbom(run.id, document["subjects"])
    if sbom["components"]:
        (run.dir / "sbom.cdx.json").write_text(_dump(sbom), encoding="utf-8")
    (run.dir / "report.md").write_text(render_analysis(document, draft, clean, candidates), encoding="utf-8")
