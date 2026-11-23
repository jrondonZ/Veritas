"""Local model routing (docs/architecture.md §10): local weights, a no-network model sandbox, and the call contract.

There is no hosted-model adapter. Models only propose; the kernel validates every output.
"""

from .cache import ResponseCache
from .calls import ModelResult, ModelService, ModelTask, TokenBudget, answer_envelope
from .profiles import PROFILES, ROUTES, Resolved, RouteUnavailable, Routing, load_routing
from .prompts import Prompt, untrusted
from .registry import RegisteredModel, load_models

__all__ = [
    "PROFILES",
    "ROUTES",
    "ModelResult",
    "ModelService",
    "ModelTask",
    "Prompt",
    "RegisteredModel",
    "Resolved",
    "ResponseCache",
    "RouteUnavailable",
    "Routing",
    "TokenBudget",
    "answer_envelope",
    "load_models",
    "load_routing",
    "untrusted",
]
