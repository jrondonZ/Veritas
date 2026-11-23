"""Address classes and path patterns shared by the scope validator and the gateway."""

from __future__ import annotations

import ipaddress
import re

# Until Phase 4 only these ranges may be targets.
_ALLOWED_V4 = [ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
_ALLOWED_V6 = [ipaddress.ip_network(n) for n in ("::1/128", "fc00::/7")]
_LINK_LOCAL = [ipaddress.ip_network(n) for n in ("169.254.0.0/16", "fe80::/10")]


def classify_address(text: str) -> tuple[bool, str]:
    """Return (allowed, label) for a target address."""
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return False, "not an IP address"
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    if any(addr in n for n in _LINK_LOCAL):
        return False, "link-local (never allowed; includes cloud metadata endpoints)"
    nets = _ALLOWED_V4 if addr.version == 4 else _ALLOWED_V6
    for net in nets:
        if addr in net:
            return True, "loopback" if addr.is_loopback else "private"
    return False, "public or reserved address (not allowed before Phase 4)"


# Path patterns: '/'-separated segments; '*' matches within one segment, '**' matches
# zero or more whole segments.
_SEGMENT_RE = re.compile(r"^[A-Za-z0-9._~!$&'()+,;=:@%*-]*$")


def pattern_problem(pattern: str) -> str | None:
    if not pattern.startswith("/"):
        return "must start with '/'"
    if any(c in pattern for c in "?#\\"):
        return "must not contain '?', '#', or '\\'"
    for seg in pattern.split("/")[1:]:
        if seg in (".", ".."):
            return "must not contain '.' or '..' segments"
        if "**" in seg and seg != "**":
            return "'**' must be a whole segment"
        if not _SEGMENT_RE.match(seg):
            return f"invalid characters in segment {seg!r}"
    return None


def _segment_match(pattern: str, segment: str) -> bool:
    if "*" not in pattern:
        return pattern == segment
    regex = "^" + ".*".join(re.escape(part) for part in pattern.split("*")) + "$"
    return re.match(regex, segment) is not None


def _match(pats: list[str], segs: list[str]) -> bool:
    if not pats:
        return not segs
    head, rest = pats[0], pats[1:]
    if head == "**":
        return any(_match(rest, segs[i:]) for i in range(len(segs) + 1))
    return bool(segs) and _segment_match(head, segs[0]) and _match(rest, segs[1:])


def path_matches(pattern: str, path: str) -> bool:
    """Match a normalized path against a pattern."""
    return _match(pattern.split("/")[1:], path.split("/")[1:])


def any_path_matches(patterns: list[str], path: str) -> bool:
    return any(path_matches(p, path) for p in patterns)


_AMBIGUOUS_RE = re.compile(r"%(2e|2f|5c|00)", re.IGNORECASE)


def path_ambiguity(path: str) -> str | None:
    """Reasons the gateway refuses a request path outright, or None if it is unambiguous."""
    if not path.startswith("/"):
        return "path must be absolute"
    if "\\" in path or "\x00" in path:
        return "backslash or NUL in path"
    if _AMBIGUOUS_RE.search(path):
        return "encoded dot, slash, backslash, or NUL in path"
    if any(seg in (".", "..") for seg in path.split("/")):
        return "dot segment in path"
    if "//" in path:
        return "empty path segment"
    return None
