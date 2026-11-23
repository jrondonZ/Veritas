"""Assessment scope v1alpha1 schema (docs/architecture.md §5.1 and §5.2)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..core.impact import Impact
from ..core.netpolicy import any_path_matches, pattern_problem
from ..documents import parse_duration

API_VERSION = "veritas/v1alpha1"
SLUG = r"^[a-z][a-z0-9-]{0,62}$"
MAX_RPS = 50
MAX_CONCURRENCY = 16
MAX_REQUESTS = 100_000
DEFAULT_PORTS = {"http": 80, "https": 443}

Method = Literal["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]


FIELD = r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$"


def _check_patterns(patterns: list[str]) -> list[str]:
    for p in patterns:
        problem = pattern_problem(p)
        if problem:
            raise ValueError(f"path pattern {p!r} {problem}")
    return patterns


def _check_literal_path(path: str | None) -> str | None:
    if path is not None and (pattern_problem(path) or "*" in path):
        raise ValueError(f"{path!r} must be a literal absolute path")
    return path


def _check_relative_files(paths: list[str]) -> list[str]:
    """Files next to the scope: relative, inside its directory, and named plainly."""
    for p in paths:
        parts = p.replace("\\", "/").split("/")
        if not p or p.startswith(("/", "\\")) or ":" in p or ".." in parts or not parts[-1]:
            raise ValueError(f"{p!r} must be a relative path inside the scope's directory")
    return paths


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Reference(_Strict):
    file: str | None = None
    id: str | None = Field(default=None, min_length=1)

    @model_validator(mode="after")
    def _exactly_one(self) -> Reference:
        if (self.file is None) == (self.id is None):
            raise ValueError("set exactly one of 'file' or 'id'")
        return self


class Window(_Strict):
    start: datetime
    end: datetime

    @model_validator(mode="after")
    def _ordered(self) -> Window:
        for name in ("start", "end"):
            if getattr(self, name).tzinfo is None:
                raise ValueError(f"{name} must include a timezone, e.g. 2026-11-18T00:00:00Z")
        if self.end <= self.start:
            raise ValueError("end must be after start")
        return self


class Authorization(_Strict):
    basis: Literal["owned", "written-permission"]
    reference: Reference
    window: Window


class Environment(_Strict):
    kind: Literal["disposable", "local-dev", "staging"]
    provider: Literal["compose", "none"] = "none"
    compose_file: str | None = None
    reset: Literal["snapshot", "none"] = "none"

    @field_validator("kind", mode="before")
    @classmethod
    def _no_production(cls, v: Any) -> Any:
        if isinstance(v, str) and v.strip().lower() == "production":
            raise ValueError("production environments are not supported by Veritas")
        return v

    @model_validator(mode="after")
    def _provider_fields(self) -> Environment:
        if self.provider == "compose" and not self.compose_file:
            raise ValueError("provider 'compose' requires compose_file")
        if self.provider != "compose" and self.compose_file:
            raise ValueError("compose_file requires provider 'compose'")
        if self.reset == "snapshot" and self.provider != "compose":
            raise ValueError("reset 'snapshot' requires an env provider")
        return self


class Allow(_Strict):
    paths: list[str] = Field(min_length=1)
    methods: list[Method] = Field(min_length=1)
    _patterns = field_validator("paths")(_check_patterns)


class Deny(_Strict):
    paths: list[str] = []
    _patterns = field_validator("paths")(_check_patterns)


class Limits(_Strict):
    rps: float = Field(gt=0, le=MAX_RPS)
    concurrency: int = Field(ge=1, le=MAX_CONCURRENCY)
    max_requests: int = Field(ge=1, le=MAX_REQUESTS)


class Target(_Strict):
    id: str = Field(pattern=SLUG)
    base_url: str
    addresses: list[str] | None = Field(default=None, min_length=1)
    source: str | None = None
    allow: Allow
    deny: Deny = Deny()
    unsafe_get: list[str] = []
    limits: Limits
    openapi: str | None = None  # path of an OpenAPI document that recon imports
    # HAR recordings of this target, relative to the scope file. Recon adds the routes they show on this origin and
    # in scope; it never replays or fetches anything from them. Their contents are hashed into the scope digest.
    recordings: list[str] = Field(default=[], max_length=10)
    _patterns = field_validator("unsafe_get")(_check_patterns)
    _openapi = field_validator("openapi")(_check_literal_path)
    _recordings = field_validator("recordings")(_check_relative_files)

    def permits(self, method: str, path: str) -> bool:
        """Whether the scope allows this method on this path (deny rules win)."""
        return (
            method in self.allow.methods
            and any_path_matches(self.allow.paths, path)
            and not any_path_matches(self.deny.paths, path)
        )

    @field_validator("base_url")
    @classmethod
    def _origin_only(cls, v: str) -> str:
        parts = urlsplit(v)
        if parts.scheme not in DEFAULT_PORTS:
            raise ValueError("scheme must be http or https")
        if not parts.hostname:
            raise ValueError("host is required")
        if parts.username or parts.password:
            raise ValueError("must not contain credentials")
        if parts.query or parts.fragment or parts.path not in ("", "/"):
            raise ValueError("must be an origin such as http://host:8080")
        _ = parts.port  # raises ValueError for an invalid port
        return v

    @property
    def scheme(self) -> str:
        return urlsplit(self.base_url).scheme

    @property
    def host(self) -> str:
        return (urlsplit(self.base_url).hostname or "").rstrip(".")

    @property
    def port(self) -> int:
        return urlsplit(self.base_url).port or DEFAULT_PORTS[self.scheme]


class FormLogin(_Strict):
    """The gateway signs in by POSTing these form fields to `path` on the identity's target."""

    type: Literal["form"]
    path: str
    username: str = Field(min_length=1)
    username_field: str = Field(default="username", pattern=FIELD)
    password_field: str = Field(default="password", pattern=FIELD)
    _path = field_validator("path")(_check_literal_path)


class Identity(_Strict):
    id: str = Field(pattern=SLUG)
    kind: Literal["synthetic"]
    target: str = Field(pattern=SLUG)
    login: FormLogin
    secret: str = Field(pattern=r"^(env|keychain):[A-Za-z_][A-Za-z0-9_.-]*$")
    # A string seeded into this identity's records; authorization oracles look for it.
    canary: str | None = Field(default=None, min_length=4)


class Sensor(_Strict):
    """Runtime signals from an owned app, read without network access (docs/architecture.md §6.1, §9.4).

    `volume` names a volume in the environment's compose file; the sensor mounts it read-only.
    """

    id: str = Field(pattern=SLUG)
    kind: Literal["query-log", "activity-log"]
    target: str = Field(pattern=SLUG)
    volume: str = Field(pattern=SLUG)


class Policy(_Strict):
    auto_approve: list[Impact] = [Impact.OBSERVE, Impact.PROBE]
    models: bool = True
    prompt_redaction: bool = True


class Budgets(_Strict):
    wall_clock: int = 1800
    model_tokens: int = Field(default=2_000_000, ge=0)
    _duration = field_validator("wall_clock", mode="before")(parse_duration)


class Metadata(_Strict):
    name: str = Field(pattern=SLUG)


class AssessmentScope(_Strict):
    api_version: Literal["veritas/v1alpha1"] = Field(alias="apiVersion")
    kind: Literal["AssessmentScope"]
    metadata: Metadata
    authorization: Authorization
    environment: Environment
    targets: list[Target] = Field(min_length=1)
    identities: list[Identity] = []
    sensors: list[Sensor] = []
    policy: Policy = Policy()
    budgets: Budgets = Budgets()

    @model_validator(mode="after")
    def _cross_field_rules(self) -> AssessmentScope:
        env = self.environment
        for label, ids in (
            ("target", [t.id for t in self.targets]),
            ("identity", [i.id for i in self.identities]),
            ("sensor", [s.id for s in self.sensors]),
        ):
            dupes = sorted({i for i in ids if ids.count(i) > 1})
            if dupes:
                raise ValueError(f"duplicate {label} ids: {', '.join(dupes)}")
        origins = [(t.scheme, t.host, t.port) for t in self.targets]
        if len(set(origins)) != len(origins):
            raise ValueError("two targets share the same origin")
        auto = set(self.policy.auto_approve)
        if Impact.SENSITIVE in auto:
            raise ValueError("policy.auto_approve: sensitive actions always need approval")
        if Impact.MUTATE in auto and not (env.kind == "disposable" and env.reset != "none"):
            raise ValueError(
                "policy.auto_approve: mutate can be auto-approved only in a disposable environment with a reset method"
            )
        if not self.policy.prompt_redaction and env.kind != "disposable":
            raise ValueError("policy.prompt_redaction can be turned off only for disposable environments")
        for t in self.targets:
            if "DELETE" in t.allow.methods and env.kind != "disposable":
                raise ValueError(f"target {t.id}: DELETE is allowed only in disposable environments")
            if env.provider == "compose" and t.addresses is None:
                raise ValueError(f"target {t.id}: lab targets must declare pinned addresses")
            if t.openapi is not None and not t.permits("GET", t.openapi):
                raise ValueError(f"target {t.id}: openapi path {t.openapi} must be allowed for GET")
        targets = {t.id: t for t in self.targets}
        for i in self.identities:
            target = targets.get(i.target)
            if target is None:
                raise ValueError(f"identity {i.id}: unknown target {i.target!r}")
            if not target.permits("POST", i.login.path):
                raise ValueError(f"identity {i.id}: login path {i.login.path} must be allowed for POST")
        for s in self.sensors:
            if env.kind not in ("disposable", "local-dev") or env.provider != "compose":
                raise ValueError(f"sensor {s.id}: sensors run only in disposable or local-dev compose environments")
            if s.target not in targets:
                raise ValueError(f"sensor {s.id}: unknown target {s.target!r}")
        return self
