"""Hardware profiles and routing (docs/architecture.md §10.2, ADR 0007).

A route resolves to a registered model in this order: the workspace's explicit choice
(`veritas models route`), then the profile's default, which comes from a documented
routing eval. Aliases are explicit too: a profile states that `deep` is served by
`analysis`, and the report says so. Nothing is aliased automatically.

The `code` route writes clean-room implementations. A small coding model (1 to 2 B
parameters, about 1 GB) can serve it, and a task it fails twice moves up to `analysis`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from ..sandbox.model import ModelLimits
from .registry import RegisteredModel

ROUTES = ("triage", "analysis", "deep", "code")
ESCALATION = {"triage": "analysis", "analysis": "deep", "code": "analysis"}  # §10.3: the next configured route
SMALL_MODEL = int(1.5 * 2**30)  # weights below this get the longer context
SMALL_CONTEXT = 8192


@dataclass(frozen=True)
class Profile:
    name: str
    hardware: str
    limits: ModelLimits
    defaults: dict[str, str | None]  # route -> default model name, from the routing eval (docs/evals/)
    aliases: dict[str, str] = field(default_factory=dict)  # route -> the route that serves it
    eval: str | None = None  # the eval report the defaults come from
    small_context: int | None = None  # the context a small model gets instead, in the same memory

    def limits_for(self, model: RegisteredModel) -> ModelLimits:
        """A small model can get a longer context in the same memory: its KV cache per token is a fraction of a 4B
        model's, and clean-room prompts (spec plus vectors) run long."""
        if self.small_context and model.size < SMALL_MODEL and self.limits.context < self.small_context:
            return replace(self.limits, context=self.small_context)
        return self.limits


PROFILES = {
    "laptop": Profile(
        name="laptop",
        hardware="6 cores, 16 GB RAM, no usable GPU (ADR 0007)",
        # A 3-4B Q4_K_M model needs about 2.5 GB of weights, 0.9 GB of KV cache at 6K tokens, and some buffers.
        limits=ModelLimits(memory="4500m", cpus=6, threads=6, context=6144),
        defaults={"analysis": None},  # set from the routing eval (`veritas models eval`)
        aliases={"triage": "analysis", "deep": "analysis", "code": "analysis"},
        small_context=SMALL_CONTEXT,  # a 1.5B model's KV cache at 8K tokens is about 0.25 GB
    ),
}


class RouteUnavailable(Exception):
    pass


@dataclass(frozen=True)
class Resolved:
    route: str  # what was asked for
    serving: str  # the route that answers, after explicit aliases
    model: RegisteredModel
    source: str  # "workspace" or "profile:<name>"

    @property
    def aliased(self) -> bool:
        return self.route != self.serving


@dataclass
class Routing:
    profile: Profile
    choices: dict[str, str]  # route -> model name chosen in the workspace
    models: dict[str, RegisteredModel]

    def resolve(self, route: str) -> Resolved:
        if route not in ROUTES:
            raise RouteUnavailable(f"unknown route {route!r}")
        serving = route
        seen = {route}
        while serving in self.profile.aliases and serving not in self.choices:
            serving = self.profile.aliases[serving]
            if serving in seen:
                raise RouteUnavailable(f"route aliases loop at {serving}")
            seen.add(serving)
        name, source = self.choices.get(serving), "workspace"
        if name is None:
            name, source = self.profile.defaults.get(serving), f"profile:{self.profile.name}"
        if name is None:
            raise RouteUnavailable(
                f"no model is chosen for the {serving} route; run `veritas models route {serving} <name>`"
            )
        model = self.models.get(name)
        if model is None:
            raise RouteUnavailable(f"the {serving} route uses {name}, which is not registered (`veritas models add`)")
        return Resolved(route, serving, model, source)

    def escalate(self, route: str) -> str | None:
        """The next configured route above `route` that a different setting serves, if any."""
        here = self._target(route)
        nxt = ESCALATION.get(route)
        while nxt is not None:
            if self._target(nxt) != here:
                return nxt
            nxt = ESCALATION.get(nxt)
        return None

    def _target(self, route: str) -> str | None:
        try:
            return self.resolve(route).model.name
        except RouteUnavailable:
            return None


def config_path(root: Path) -> Path:
    return root / ".veritas" / "routing.json"


def load_routing(root: Path, models: dict[str, RegisteredModel]) -> Routing:
    path = config_path(root)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
    profile = PROFILES.get(str(data.get("profile") or "laptop"))
    if profile is None:
        raise RouteUnavailable(f"unknown hardware profile {data.get('profile')!r}")
    return Routing(profile, {str(k): str(v) for k, v in (data.get("routes") or {}).items()}, models)


def save_routing(root: Path, profile: str, choices: dict[str, str]) -> None:
    path = config_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"profile": profile, "routes": choices}, indent=2, sort_keys=True) + "\n", "utf-8")
