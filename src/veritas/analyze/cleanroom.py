"""The clean room (docs/architecture.md §8.3 steps 7 and 8): replicate from the approved spec, then verify it.

A clean-room context holds only clean artifacts:

- the approved spec, whose digest a person approved (`veritas spec approve`);
- the operator-owned samples that crossed with it, each checked against the spec's hash;
- for verification, the implementation under test.

The builder refuses anything else. The subject, the Program Model, the draft spec, and
similarity results are dirty and never enter, even as a copy under another name, since
subjects are recognized by hash. Every input's hash goes to the audit chain, so the
chain shows exactly what each clean-room task saw.

Verification runs the implementation against the vectors in a sandbox with no network,
then audits its similarity to the subject's source. Similarity results go to the
operator only and never back into a clean room.
"""

from __future__ import annotations

import json
import shutil
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from ..agents import implementer
from ..core.canonical import sha256_hex
from ..models.calls import ModelService
from ..sandbox.engine import run_job
from ..store import AuditChain, Run, Workspace
from .gate import spec_digest
from .similarity import fingerprints, overlap, tokens
from .sources import subject_sources

PASS_TARGET = 0.90  # Phase 3 exit criterion
SIMILARITY_LIMIT = 0.25  # share of the implementation's normalized fingerprints found in the subject
CODE_K = 12  # tokens per k-gram for code: long enough that shared idioms don't count as copying
MAX_FILES, MAX_FILE = 200, 1024 * 1024
CODE_SUFFIXES = (".js", ".mjs", ".cjs", ".ts")
DIRTY_FILES = ("spec-draft.json", "analysis.json", "report.md")
# (implementation dir, samples dir) -> (argv, extra environment)
HarnessLauncher = Callable[[Path, Path], tuple[list[str], dict[str, str]]]


class DirtyInput(Exception):
    """Something dirty was offered to a clean-room context."""


class NotApproved(Exception):
    """The spec has no approval for its current digest."""


@dataclass(frozen=True)
class CleanInput:
    role: str  # spec, sample, implementation
    name: str
    sha256: str


@dataclass
class CleanContext:
    run_dir: Path
    subject_hashes: frozenset[str]
    inputs: list[CleanInput] = field(default_factory=list)

    def admit(self, role: str, path: Path, name: str) -> bytes:
        resolved = path.resolve()
        dirty_dir = (self.run_dir / "inputs").resolve()
        if resolved == dirty_dir or dirty_dir in resolved.parents:
            raise DirtyInput(f"{name} is a staged subject")
        if resolved.parent == self.run_dir.resolve() and resolved.name in DIRTY_FILES:
            raise DirtyInput(f"{name} is a dirty analysis artifact")
        data = path.read_bytes()
        digest = sha256_hex(data)
        if digest in self.subject_hashes:
            raise DirtyInput(f"{name} has the same content as a subject")
        self.inputs.append(CleanInput(role, name, digest))
        return data

    def record(self, audit: AuditChain, task: str) -> None:
        audit.append("cleanroom.context", task=task, inputs=[asdict(i) for i in self.inputs])


@dataclass
class Approved:
    run: Run
    document: dict[str, Any]
    clean: dict[str, Any]
    root: Path  # the project root that relative charter paths resolve against

    @property
    def digest(self) -> str:
        return str(self.clean["digest"])

    @property
    def charter_dir(self) -> Path:
        return (self.root / str(self.document["charter"]["path"])).parent

    @property
    def subject_hashes(self) -> frozenset[str]:
        return frozenset(s["sha256"] for s in self.document["subjects"])


def load_spec(ws: Workspace, run_id: str) -> Approved:
    run = ws.open_run(run_id)
    document = json.loads((run.dir / "analysis.json").read_text(encoding="utf-8"))
    clean = json.loads((run.dir / "spec.json").read_text(encoding="utf-8"))
    body = {k: v for k, v in clean.items() if k != "digest"}
    if spec_digest(body) != clean.get("digest"):
        raise NotApproved("spec.json was changed after the analysis wrote it")
    return Approved(run, document, clean, ws.root.parent)


def load_approved(ws: Workspace, run_id: str) -> Approved:
    approved = load_spec(ws, run_id)
    if not ws.spec_approved(run_id, approved.digest):
        raise NotApproved(f"spec {approved.digest[:19]}… is not approved; run `veritas spec approve {run_id}`")
    return approved


def clean_context(approved: Approved, work: Path) -> CleanContext:
    """Admit the approved spec and stage its samples (hash-checked) into `work/samples`."""
    ctx = CleanContext(approved.run.dir, approved.subject_hashes)
    ctx.admit("spec", approved.run.dir / "spec.json", "spec.json")
    for vector in approved.clean["conformance"]["vectors"]:
        data = ctx.admit("sample", approved.charter_dir / vector["sample"], vector["sample"])
        if f"sha256:{sha256_hex(data)}" != vector["sha256"]:
            raise DirtyInput(f"sample {vector['sample']} differs from the approved spec")
        target = work / "samples" / vector["sample"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return ctx


def similarity(implementation: dict[str, str], subject_sources: list[str]) -> dict[str, Any]:
    """Normalized-token winnowing: renaming identifiers or literals doesn't hide copied structure."""
    reference: set[int] = set()
    for source in subject_sources:
        reference |= fingerprints(tokens(source, normalize=True), CODE_K)
    files = {
        name: round(overlap(text, reference, normalize=True, k=CODE_K), 3) for name, text in implementation.items()
    }
    mine: set[int] = set()
    for text in implementation.values():
        mine |= fingerprints(tokens(text, normalize=True), CODE_K)
    share = round(len(mine & reference) / len(mine), 3) if mine else 0.0
    return {
        "limit": SIMILARITY_LIMIT,
        "k": CODE_K,
        "overall": share,
        "files": files,
        "similar": share >= SIMILARITY_LIMIT,
    }


@dataclass
class Verification:
    task: str
    passed: int
    total: int
    results: list[dict[str, Any]]
    similarity: dict[str, Any]  # operator only
    loaded: bool
    error: str | None

    @property
    def rate(self) -> float:
        return self.passed / self.total if self.total else 0.0

    @property
    def verified(self) -> bool:
        return self.loaded and self.rate >= PASS_TARGET and not self.similarity["similar"]

    def clean_feedback(self, limit: int = 6) -> list[str]:
        """What a clean-room implementer may be told: failing vectors and their results, never similarity."""
        failing = [r for r in self.results if not r["pass"]]
        return [f"vector {r['id']}: got {json.dumps(r['got'])[:300]}" for r in failing[:limit]]


def _copy_implementation(ctx: CleanContext, source: Path, target: Path) -> dict[str, str]:
    files = [p for p in sorted(source.rglob("*")) if p.is_file()]
    if len(files) > MAX_FILES:
        raise DirtyInput(f"the implementation has more than {MAX_FILES} files")
    code: dict[str, str] = {}
    for path in files:
        if path.stat().st_size > MAX_FILE:
            raise DirtyInput(f"{path.name} is larger than {MAX_FILE} bytes")
        name = path.relative_to(source).as_posix()
        data = ctx.admit("implementation", path, f"impl/{name}")
        out = target / name
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        if path.suffix in CODE_SUFFIXES:
            code[name] = data.decode("utf-8", "replace")
    return code


def verify(
    ws: Workspace, approved: Approved, implementation: Path, entry: str, launcher: HarnessLauncher, task: str
) -> Verification:
    work = approved.run.dir / "cleanroom" / task
    if work.exists():
        shutil.rmtree(work)
    ctx = clean_context(approved, work)
    code = _copy_implementation(ctx, implementation, work / "impl")
    ctx.record(approved.run.audit, task)
    vectors = approved.clean["conformance"]["vectors"]
    job = {"entry": entry, "call": approved.clean["conformance"]["call"],
           "vectors": [{k: v[k] for k in ("id", "sample", "expect")} for v in vectors]}  # fmt: skip
    argv, env = launcher(work / "impl", work / "samples")
    outcome = run_job(argv, env, job)
    results = outcome.get("results") or []
    subjects = subject_sources(approved.run.dir / "inputs", approved.document["subjects"])
    result = Verification(
        task=task,
        passed=sum(1 for r in results if r.get("pass")),
        total=len(vectors),
        results=results,
        similarity=similarity(code, subjects),
        loaded=bool(outcome.get("loaded")),
        error=outcome.get("error"),
    )
    record = {"task": task, "passed": result.passed, "total": result.total, "results": results}
    (work / "conformance.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    (work / "similarity.json").write_text(
        json.dumps(result.similarity, indent=2) + "\n", encoding="utf-8"
    )  # operator only
    approved.run.audit.append(
        "cleanroom.verify",
        task=task,
        spec=approved.digest,
        passed=result.passed,
        total=result.total,
        similarity=result.similarity["overall"],
        verified=result.verified,
    )
    return result


@dataclass
class Draft:
    task: str
    status: str  # the implementer's ModelResult status
    reason: str
    verification: Verification | None = None


async def draft(
    ws: Workspace, approved: Approved, service: ModelService, launcher: HarnessLauncher, rounds: int = 3
) -> list[Draft]:
    """Ask the implementer for a module, verify it, and retry with the failing vectors (clean feedback only)."""
    drafts: list[Draft] = []
    failures: list[str] = []
    for n in range(1, rounds + 1):
        name = f"draft-{n}"
        work = approved.run.dir / "cleanroom" / name
        if work.exists():
            shutil.rmtree(work)
        ctx = clean_context(approved, work)
        samples = {
            v["sample"]: (work / "samples" / v["sample"]).read_bytes() for v in approved.clean["conformance"]["vectors"]
        }
        ctx.record(approved.run.audit, name)  # exactly what the implementer saw
        result = await service.run(implementer.task(approved.clean, samples, failures))
        if result.status != "answered" or result.output is None:
            drafts.append(Draft(name, result.status, result.reason))
            break
        module = work / "module"
        module.mkdir(parents=True)
        (module / "index.mjs").write_text(str(result.output["module"]), encoding="utf-8")
        verification = verify(ws, approved, module, "index.mjs", launcher, f"{name}-verify")
        drafts.append(Draft(name, result.status, result.reason, verification))
        if verification.verified:
            break
        failures = verification.clean_feedback()  # never the similarity result
    return drafts
