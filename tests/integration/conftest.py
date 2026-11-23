"""Fixtures for tests that need a Docker engine (selected with `pytest -m docker`)."""

import shutil
import subprocess
from pathlib import Path

import pytest

from veritas.sandbox import build_images, write_lock


@pytest.fixture(scope="session")
def docker_engine() -> None:
    if shutil.which("docker") is None:
        pytest.skip("docker CLI not found")
    info = subprocess.run(["docker", "info"], capture_output=True, timeout=60, check=False)
    if info.returncode != 0:
        pytest.skip("Docker engine is not running")


@pytest.fixture(scope="session")
def images(docker_engine: None, repo_root: Path) -> dict[str, str]:
    """Build first-party images from the current source once per session, so tests never run stale images."""
    ids = build_images(repo_root)
    write_lock(repo_root, ids)
    return ids
