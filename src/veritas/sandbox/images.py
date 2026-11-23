"""First-party images: built locally from this repo and pinned by image ID in the workspace lockfile."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .. import __version__
from .docker import DockerError, docker

GATEWAY_IMAGE = f"veritas/gateway:{__version__}"
SELFTEST_IMAGE = f"veritas/selftest:{__version__}"
EXECUTOR_IMAGE = f"veritas/http-executor:{__version__}"
SENSOR_IMAGE = f"veritas/query-log-sensor:{__version__}"
ACTIVITY_SENSOR_IMAGE = f"veritas/activity-log-sensor:{__version__}"
BINARY_ENGINE_IMAGE = f"veritas/binary-engine:{__version__}"
MODEL_IMAGE = f"veritas/model-server:{__version__}"
JS_ENGINE_IMAGE = f"veritas/js-engine:{__version__}"
CONFORMANCE_JS_IMAGE = f"veritas/conformance-js:{__version__}"
# tag -> (Dockerfile, build context), relative to the project root. The core images are small
# (python:3.12-slim and node:24-alpine bases) and always built.
IMAGES = {
    GATEWAY_IMAGE: ("docker/gateway/Dockerfile", "."),
    SELFTEST_IMAGE: ("plugins/selftest/Dockerfile", "plugins/selftest"),
    EXECUTOR_IMAGE: ("plugins/http-executor/Dockerfile", "plugins/http-executor"),
    SENSOR_IMAGE: ("plugins/query-log-sensor/Dockerfile", "plugins/query-log-sensor"),
    ACTIVITY_SENSOR_IMAGE: ("plugins/activity-log-sensor/Dockerfile", "plugins/activity-log-sensor"),
    JS_ENGINE_IMAGE: ("plugins/js-engine/Dockerfile", "plugins/js-engine"),
    BINARY_ENGINE_IMAGE: ("plugins/binary-engine/Dockerfile", "plugins/binary-engine"),
    CONFORMANCE_JS_IMAGE: ("plugins/conformance-js/Dockerfile", "plugins/conformance-js"),
}
# Opt-in: the model server's base image alone is about 800 MB, so it is built only on request.
OPTIONAL_IMAGES = {
    "models": {MODEL_IMAGE: ("docker/model-server/Dockerfile", "docker/model-server")},
}


def build_images(root: Path, extras: tuple[str, ...] = ()) -> dict[str, str]:
    """Build the core images plus any opt-in groups in `extras`; return tag -> immutable image ID."""
    selected = dict(IMAGES)
    for group in extras:
        selected.update(OPTIONAL_IMAGES[group])
    ids = {}
    for tag, (dockerfile, context) in selected.items():
        docker(
            "build", "--quiet", "--label", f"org.opencontainers.image.version={__version__}",
            "-t", tag, "-f", str(root / dockerfile), str(root / context),
            timeout=900,
        )  # fmt: skip
        ids[tag] = docker("image", "inspect", "--format", "{{.Id}}", tag)
    return ids


def lock_path(root: Path) -> Path:
    # Locally built image IDs differ per machine, so the lock lives in the ignored workspace.
    return root / ".veritas" / "veritas.lock"


def write_lock(root: Path, images: dict[str, str], plugins: dict[str, Any] | None = None) -> Path:
    """Record built image IDs. Previously built opt-in images stay locked when a core-only build runs."""
    path = lock_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    current: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"version": 1}
    optional = {tag for group in OPTIONAL_IMAGES.values() for tag in group}
    kept = {tag: i for tag, i in (current.get("images") or {}).items() if tag in optional and tag not in images}
    current["images"] = {**kept, **images}
    if plugins is not None:
        current["plugins"] = plugins
    path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def read_lock(root: Path) -> dict[str, Any]:
    path = lock_path(root)
    if not path.exists():
        raise DockerError("no image lock found; run `veritas images build` first")
    lock: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    return lock


def update_lock(root: Path, key: str, value: Any) -> Path:
    """Replace one top-level section of the lock (such as `models`), keeping the others."""
    path = lock_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    current: dict[str, Any] = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {"version": 1}
    current[key] = value
    path.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path
