"""Loading operator-authored documents: scope files, charters, plugin manifests, compose files.

YAML is parsed with a SafeLoader that rejects duplicate keys. Quietly keeping the
last of two `allow:` blocks in a scope file would be a policy bug.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

_DURATION_RE = re.compile(r"^(\d+)(s|m|h)$")
_SIZE_RE = re.compile(r"^(\d+)(Ki|Mi|Gi)$")


class _UniqueKeyLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys instead of keeping the last one."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


def load_yaml(path: Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return yaml.load(f, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass


def parse_duration(value: Any) -> int:
    """'90s', '20m', '2h', or a positive integer number of seconds."""
    if isinstance(value, int) and not isinstance(value, bool) and value > 0:
        return value
    if isinstance(value, str):
        m = _DURATION_RE.match(value.strip())
        if m and int(m.group(1)) > 0:
            return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600}[m.group(2)]
    raise ValueError("duration must look like 90s, 20m, or 2h")


def parse_size(value: str) -> int:
    """'512Ki', '128Mi', or '2Gi', in bytes."""
    m = _SIZE_RE.match(value)
    if not m:
        raise ValueError("size must look like 512Ki, 128Mi, or 2Gi")
    return int(m.group(1)) * {"Ki": 1 << 10, "Mi": 1 << 20, "Gi": 1 << 30}[m.group(2)]
