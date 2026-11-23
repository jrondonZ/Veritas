"""Plugin manifest v1alpha1 (docs/architecture.md §6.1 and §6.2)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..core.impact import Impact, impact_allows
from ..documents import load_yaml, parse_duration, parse_size

KIND_MAX_IMPACT = {
    # Runs kernel-written request scripts; each script's token sets the real, usually lower, ceiling.
    "executor": Impact.SENSITIVE,
    "recon": Impact.PROBE,
    "check": Impact.MUTATE,
    "validator": Impact.SENSITIVE,
    "sensor": Impact.OBSERVE,
    "engine": Impact.OBSERVE,
    "patcher": Impact.OBSERVE,
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)


class Operation(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,62}$")
    impact: Impact
    input: str | None = None
    output: list[str] = []


class Runtime(_Strict):
    image: str
    command: list[str] = []


class Capabilities(_Strict):
    network: Literal["none", "target-scope"]
    identities: Literal["none", "declared"] = "none"
    filesystem: dict[str, str] = {}


class Resources(_Strict):
    cpu: float = Field(gt=0, le=8)
    memory: str = "256Mi"
    pids: int = Field(default=64, ge=8, le=4096)
    timeout: int = 120
    output_max: str = "16Mi"
    _timeout = field_validator("timeout", mode="before")(parse_duration)

    @field_validator("memory", "output_max")
    @classmethod
    def _size(cls, v: str) -> str:
        parse_size(v)
        return v

    @property
    def memory_bytes(self) -> int:
        return parse_size(self.memory)


class PluginManifest(_Strict):
    api_version: Literal["veritas/plugin/v1alpha1"] = Field(alias="apiVersion")
    id: str = Field(pattern=r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")
    kind: Literal["executor", "recon", "check", "validator", "sensor", "engine", "patcher"]
    runtime: Runtime
    protocol: Literal["vpp/1"]
    operations: list[Operation] = Field(min_length=1)
    capabilities: Capabilities
    resources: Resources
    determinism: Literal["deterministic", "seeded", "nondeterministic"]
    defaults: dict[str, Any] = {}
    standards: dict[str, Any] = {}

    @model_validator(mode="after")
    def _impact_rules(self) -> PluginManifest:
        names = [op.name for op in self.operations]
        if len(set(names)) != len(names):
            raise ValueError("operation names must be unique")
        ceiling = KIND_MAX_IMPACT[self.kind]
        for op in self.operations:
            if not impact_allows(ceiling, op.impact):
                raise ValueError(f"operation {op.name}: a {self.kind} plugin may not exceed {ceiling}")
            if self.capabilities.network == "none" and op.impact != Impact.OBSERVE:
                raise ValueError(f"operation {op.name}: without network access the impact must be observe")
        return self

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.version}"

    def operation(self, name: str) -> Operation:
        for op in self.operations:
            if op.name == name:
                return op
        raise KeyError(name)


def load_manifest(path: str | Path) -> PluginManifest:
    return PluginManifest.model_validate(load_yaml(Path(path)))
