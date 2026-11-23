"""A CycloneDX 1.5 inventory of the dependencies bundled inside Electron archives.

It lists what each archive carries, by name and version, so an advisory database the
operator keeps locally can be matched against it. Nothing is fetched, and the inventory
makes no claim that any dependency is vulnerable.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .. import __version__


def purl(name: str, version: str | None) -> str:
    scope, _, base = name.rpartition("/")
    path = (quote(scope, safe="") + "/" if scope else "") + quote(base, safe="")
    return f"pkg:npm/{path}" + (f"@{quote(version, safe='')}" if version else "")


def render_sbom(run_id: str, subjects: list[dict[str, Any]]) -> dict[str, Any]:
    components = []
    for s in subjects:
        for d in s.get("dependencies") or []:
            if not d.get("name"):
                continue
            component = {"type": "library", "bom-ref": f"{s['path']}!{d['name']}@{d.get('version') or ''}",
                         "name": d["name"], "purl": purl(d["name"], d.get("version"))}  # fmt: skip
            if d.get("version"):
                component["version"] = d["version"]
            components.append(component)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": "Veritas Analyze", "version": __version__}]},
            "properties": [{"name": "veritas:run", "value": run_id}],
        },
        "components": components,
    }
