"""The `engine` sandbox profile (docs/architecture.md §6.6): no network, inputs mounted read-only.

Engines parse hostile files, so each runs in its own container with no network
interface besides loopback, a read-only root filesystem, no capabilities, and one
read-only input directory. Results come back as structured content on stdio.
"""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Any

from ..plugins.manifest import PluginManifest
from .docker import HARDENING, LABEL

INPUTS = "/inputs"


class JobError(RuntimeError):
    pass


def harness_argv(run_id: str, image: str, impl: Path, samples: Path) -> list[str]:
    """The conformance harness: runs a clean-room implementation, never the subject, with no network."""
    return [
        "docker", "run", "-i", "--rm", "--name", f"vrt-{run_id}-conformance", "--label", f"{LABEL}={run_id}",
        "--network", "none", *HARDENING,
        "--pids-limit", "64", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
        "--mount", f"type=bind,source={impl.resolve()},target=/impl,readonly",
        "--mount", f"type=bind,source={samples.resolve()},target=/samples,readonly",
        image,
    ]  # fmt: skip


def run_job(argv: list[str], env: dict[str, str], job: dict[str, Any], timeout: float = 300) -> dict[str, Any]:
    """Send one JSON job on stdin and read one JSON result from stdout."""
    try:
        proc = subprocess.run(  # noqa: S603 - argv is built here or by the caller's launcher, no shell
            argv,
            input=json.dumps(job),
            capture_output=True,
            text=True,
            timeout=timeout,
            env={**os.environ, **env},
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise JobError(f"the job did not finish within {timeout:.0f} s") from exc
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    if proc.returncode != 0 or not lines:
        raise JobError(f"the job failed ({proc.returncode}): {proc.stderr.strip()[-400:]}")
    result: dict[str, Any] = json.loads(lines[-1])
    return result


def engine_argv(run_id: str, image: str, manifest: PluginManifest, inputs: Path, name: str) -> list[str]:
    if manifest.capabilities.network != "none":
        raise ValueError(f"{manifest.ref} asks for network access, which engines never get")
    res = manifest.resources
    memory = f"{res.memory_bytes // (1 << 20)}m"
    return [
        "docker", "run", "-i", "--rm", "--name", f"vrt-{run_id}-engine-{name}", "--label", f"{LABEL}={run_id}",
        "--network", "none", *HARDENING,
        "--tmpfs", "/work:rw,noexec,nosuid,size=16m,mode=1777", "--workdir", "/work",
        "--pids-limit", str(res.pids), "--memory", memory, "--memory-swap", memory, "--cpus", str(res.cpu),
        "--mount", f"type=bind,source={inputs.resolve()},target={INPUTS},readonly",
        image, *manifest.runtime.command,
    ]  # fmt: skip
