"""Canonical JSON (RFC 8785, JCS) and SHA-256 helpers.

Every digest Veritas computes (scopes, tokens, audit entries, approvals) is taken
over this canonical form, so two semantically equal documents always hash alike.
"""

from __future__ import annotations

import hashlib
import math
from decimal import Decimal
from typing import Any

_MAX_SAFE_INT = 2**53


class CanonicalizationError(ValueError):
    pass


def _format_number(value: float) -> str:
    """ECMAScript Number::toString, as RFC 8785 section 3.2.2.3 requires."""
    if math.isnan(value) or math.isinf(value):
        raise CanonicalizationError("NaN and Infinity are not valid JSON numbers")
    if value == 0:
        return "0"  # covers -0.0 as well
    sign = "-" if value < 0 else ""
    # repr() yields the shortest round-tripping digit string, as ECMAScript does.
    _, digit_tuple, exponent = Decimal(repr(abs(value))).as_tuple()
    if not isinstance(exponent, int):  # only NaN and Infinity have a non-integer exponent
        raise CanonicalizationError("non-finite number")
    digits = "".join(map(str, digit_tuple)).rstrip("0")
    exponent += len(digit_tuple) - len(digits)
    k = len(digits)
    n = exponent + k  # value = 0.digits * 10**n
    if k <= n <= 21:
        body = digits + "0" * (n - k)
    elif 0 < n <= 21:
        body = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        exp = ("+" if e >= 0 else "-") + str(abs(e))
        body = digits[0] + ("." + digits[1:] if k > 1 else "") + "e" + exp
    return sign + body


_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _format_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be")


def _serialize(value: Any, out: list[str]) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise CanonicalizationError(f"integer {value} exceeds the IEEE 754 safe range")
        out.append(str(value))
    elif isinstance(value, float):
        out.append(_format_number(value))
    elif isinstance(value, str):
        out.append(_format_string(value))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _serialize(item, out)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalizationError(f"object keys must be strings, got {type(key).__name__}")
        out.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_key)):
            if i:
                out.append(",")
            out.append(_format_string(key))
            out.append(":")
            _serialize(value[key], out)
        out.append("}")
    else:
        raise CanonicalizationError(f"cannot canonicalize {type(value).__name__}")


def canonical_json(value: Any) -> str:
    out: list[str] = []
    _serialize(value, out)
    return "".join(out)


def canonical_bytes(value: Any) -> bytes:
    return canonical_json(value).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def digest(value: Any) -> str:
    """'sha256:<hex>' over the canonical JSON form of value."""
    return "sha256:" + sha256_hex(canonical_bytes(value))


def file_digest(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()
