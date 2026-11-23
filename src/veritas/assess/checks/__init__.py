"""The check registry. Order matters: it fixes finding IDs, so runs are comparable. New checks go last."""

from .app_activity import CommandFromInput, PathFromInput, RequestFromInput
from .base import Check, CheckInfo, Observation, OracleResult, PlanContext, SensorCheck, run_oracle
from .cookie_attributes import CookieAttributes
from .cors import CrossOriginReads
from .csrf import CrossSiteRequestForgery
from .error_disclosure import ErrorDisclosure
from .headers import ContentSecurityPolicy, ContentTypeOptions, FramingProtection, ServerBanner, StrictTransportSecurity
from .mass_assignment import MassAssignment
from .object_authz import ObjectAuthorization
from .open_redirect import OpenRedirect
from .reflected_html import ReflectedHtml
from .sql_string_built import StringBuiltQuery

CHECKS: tuple[Check, ...] = (
    ObjectAuthorization(),
    ReflectedHtml(),
    CookieAttributes(),
    ErrorDisclosure(),
    MassAssignment(),
    CrossSiteRequestForgery(),
    StringBuiltQuery(),
    OpenRedirect(),
    CrossOriginReads(),
    ContentSecurityPolicy(),
    FramingProtection(),
    ContentTypeOptions(),
    StrictTransportSecurity(),
    ServerBanner(),
    PathFromInput(),
    CommandFromInput(),
    RequestFromInput(),
)
BY_ID = {c.id: c for c in CHECKS}

__all__ = [
    "BY_ID",
    "CHECKS",
    "Check",
    "CheckInfo",
    "Observation",
    "OracleResult",
    "PlanContext",
    "SensorCheck",
    "run_oracle",
]
