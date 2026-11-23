"""Assessment scopes: the schema, validation rules, address pinning, and digest (docs/architecture.md §5)."""

from .check import PinnedTarget, Resolver, ScopeReport, check_scope, system_resolver
from .model import API_VERSION, AssessmentScope, Target

__all__ = [
    "API_VERSION",
    "AssessmentScope",
    "PinnedTarget",
    "Resolver",
    "ScopeReport",
    "Target",
    "check_scope",
    "system_resolver",
]
