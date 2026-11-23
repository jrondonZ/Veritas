"""Analysis charter v1alpha1 (docs/architecture.md §5.3): what may be analyzed, why, and what may be produced.

A charter pins every subject by SHA-256, records the operator's basis and purpose, and
names the operator-owned conformance vectors. Its digest covers the parsed charter and
every file it references (subjects, the authorization reference, vectors, and each
sample), and a person acknowledges a digest before anything runs. Veritas records the
basis but can't verify it; whether analysis is permitted is the operator's judgment.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from ..core.canonical import digest, file_digest
from ..documents import load_yaml

API_VERSION = "veritas/v1alpha1"
SLUG = r"^[a-z][a-z0-9-]{0,62}$"
SHA256 = r"^[0-9a-f]{64}$"
MAX_SUBJECT = 256 * 1024 * 1024
Basis = Literal[
    "owned", "license-permits", "interoperability", "security-research",
    "migration", "accessibility", "preservation", "education",
]  # fmt: skip
Deliverable = Literal["behavior-spec", "clean-room-plan", "implementation"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Metadata(_Strict):
    name: str = Field(pattern=SLUG)


class Reference(_Strict):
    file: str


class Subject(_Strict):
    path: str = Field(min_length=1)
    sha256: str = Field(pattern=SHA256)


class Conformance(_Strict):
    vectors: str = Field(min_length=1)


class Constraints(_Strict):
    execute_subject: Literal[False] = False  # the detonate tier arrives in Phase 4
    network: Literal["none"] = "none"
    models: bool = True


class AnalysisCharter(_Strict):
    api_version: Literal["veritas/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["AnalysisCharter"]
    metadata: Metadata
    basis: Basis
    reference: Reference | None = None
    purpose: str = Field(min_length=20, max_length=2000)
    subjects: list[Subject] = Field(min_length=1, max_length=20)
    conformance: Conformance | None = None
    deliverables: list[Deliverable] = Field(min_length=1)
    constraints: Constraints = Constraints()

    @field_validator("subjects")
    @classmethod
    def _unique(cls, subjects: list[Subject]) -> list[Subject]:
        paths = [s.path for s in subjects]
        if len(set(paths)) != len(paths):
            raise ValueError("a subject is listed twice")
        return subjects


@dataclass
class Vector:
    id: str
    sample: str  # path relative to the charter
    expect: dict[str, object]


@dataclass
class CharterReport:
    path: Path
    charter: AnalysisCharter | None = None
    errors: list[str] = field(default_factory=list)
    notices: list[str] = field(default_factory=list)
    files: dict[str, str] = field(default_factory=dict)  # role -> "sha256:<hex>"
    vectors: list[Vector] = field(default_factory=list)
    call: str | None = None  # the exported function the vectors exercise
    digest: str | None = None

    @property
    def ok(self) -> bool:
        return self.charter is not None and not self.errors

    @property
    def base(self) -> Path:
        return self.path.parent


def _messages(exc: ValidationError) -> list[str]:
    return [f"{'.'.join(str(p) for p in e['loc']) or '(root)'}: {e['msg'].removeprefix('Value error, ')}"
            for e in exc.errors()]  # fmt: skip


def _load_vectors(report: CharterReport, path: Path) -> None:
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        entries = doc["vectors"]
        report.vectors = [Vector(str(v["id"]), str(v["sample"]), dict(v["expect"])) for v in entries]
        report.call = str(doc["call"])
    except (OSError, ValueError, KeyError, TypeError) as exc:
        report.errors.append(f"conformance.vectors: cannot read {path.name}: {exc}")
        return
    if not report.call.isidentifier():
        report.errors.append("conformance.vectors: `call` must name the exported function the vectors exercise")
    ids = [v.id for v in report.vectors]
    if len(set(ids)) != len(ids):
        report.errors.append("conformance.vectors: vector ids must be unique")
    for vector in report.vectors:
        sample = report.base / vector.sample
        if not sample.is_file():
            report.errors.append(f"conformance vector {vector.id}: sample not found: {vector.sample}")
        else:
            report.files[f"sample:{vector.sample}"] = file_digest(str(sample))


def check_charter(path: str | Path) -> CharterReport:
    path = Path(path)
    report = CharterReport(path=path)
    try:
        raw = load_yaml(path)
    except (OSError, yaml.YAMLError) as exc:
        report.errors.append(f"cannot read charter file: {exc}")
        return report
    try:
        charter = AnalysisCharter.model_validate(raw)
    except ValidationError as exc:
        report.errors.extend(_messages(exc))
        return report
    report.charter = charter
    if charter.reference is not None:
        ref = report.base / charter.reference.file
        if ref.is_file():
            report.files["reference"] = file_digest(str(ref))
        else:
            report.errors.append(f"reference.file not found: {ref}")
    else:
        report.notices.append("no authorization reference file is recorded")
    for subject in charter.subjects:
        file = report.base / subject.path
        if not file.is_file():
            report.errors.append(f"subject not found: {subject.path}")
            continue
        if file.stat().st_size > MAX_SUBJECT:
            report.errors.append(f"subject {subject.path} is larger than {MAX_SUBJECT // 2**20} MiB")
            continue
        actual = file_digest(str(file))
        if actual != f"sha256:{subject.sha256}":
            report.errors.append(f"subject {subject.path} does not match its pinned sha256 (now {actual})")
        report.files[f"subject:{subject.path}"] = actual
    if charter.conformance is not None:
        vectors = report.base / charter.conformance.vectors
        if vectors.is_file():
            report.files["conformance"] = file_digest(str(vectors))
            _load_vectors(report, vectors)
        else:
            report.errors.append(f"conformance.vectors not found: {vectors}")
    if "implementation" in charter.deliverables and charter.conformance is None:
        report.errors.append("an implementation deliverable needs conformance vectors to verify it")
    if not report.errors:
        report.digest = digest(
            {"schema": API_VERSION, "charter": charter.model_dump(mode="json", by_alias=True), "files": report.files}
        )
    return report
