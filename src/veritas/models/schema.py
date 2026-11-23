"""The JSON Schema subset role outputs may use, and a validator for it (docs/architecture.md §10.4).

llama-server compiles a request's schema into a decoding grammar, so outputs already
match. The kernel validates them again anyway (models are untrusted), and `supported`
keeps role schemas inside what the grammar compiler handles: CI checks every role schema.
"""

from __future__ import annotations

import re
from typing import Any

KEYWORDS = frozenset(
    {
        "type", "properties", "required", "additionalProperties", "items", "enum", "const",
        "minLength", "maxLength", "minItems", "maxItems", "minimum", "maximum", "pattern", "description",
    }
)  # fmt: skip
TYPES: dict[str, type | tuple[type, ...]] = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "number": (int, float),
    "boolean": bool,
    "null": type(None),
}


def supported(schema: Any, path: str = "$") -> list[str]:
    """Keywords outside the subset, by location. Every object must close its properties."""
    problems: list[str] = []
    if not isinstance(schema, dict):
        return [f"{path}: a schema must be an object"]
    problems += [f"{path}: unsupported keyword {k!r}" for k in sorted(set(schema) - KEYWORDS)]
    if schema.get("type") == "object":
        if schema.get("additionalProperties") is not False:
            problems.append(f"{path}: objects must set additionalProperties to false")
        for name, sub in (schema.get("properties") or {}).items():
            problems += supported(sub, f"{path}.{name}")
    if schema.get("type") == "array" and "items" in schema:
        problems += supported(schema["items"], f"{path}[]")
    return problems


def _type_ok(value: Any, expected: Any) -> bool:
    names = expected if isinstance(expected, list) else [expected]
    for name in names:
        kind = TYPES.get(name)
        if kind is None:
            continue
        if name in ("integer", "number") and isinstance(value, bool):
            continue
        if isinstance(value, kind):
            return True
    return False


def validate(schema: dict[str, Any], value: Any, path: str = "$") -> list[str]:
    problems: list[str] = []
    if "type" in schema and not _type_ok(value, schema["type"]):
        return [f"{path}: expected {schema['type']}"]
    if "const" in schema and value != schema["const"]:
        problems.append(f"{path}: must be {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        problems.append(f"{path}: must be one of {schema['enum']}")
    if isinstance(value, str):
        if len(value) < schema.get("minLength", 0):
            problems.append(f"{path}: shorter than {schema['minLength']} characters")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            problems.append(f"{path}: longer than {schema['maxLength']} characters")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            problems.append(f"{path}: does not match {schema['pattern']}")
    if isinstance(value, int | float) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            problems.append(f"{path}: below {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            problems.append(f"{path}: above {schema['maximum']}")
    if isinstance(value, list):
        if len(value) < schema.get("minItems", 0):
            problems.append(f"{path}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            problems.append(f"{path}: more than {schema['maxItems']} items")
        for i, item in enumerate(value):
            problems += validate(schema.get("items") or {}, item, f"{path}[{i}]")
    if isinstance(value, dict):
        properties = schema.get("properties") or {}
        problems += [f"{path}: missing {k!r}" for k in schema.get("required", []) if k not in value]
        if schema.get("additionalProperties") is False:
            problems += [f"{path}: unexpected {k!r}" for k in sorted(set(value) - set(properties))]
        for k, sub in properties.items():
            if k in value:
                problems += validate(sub, value[k], f"{path}.{k}")
    return problems
