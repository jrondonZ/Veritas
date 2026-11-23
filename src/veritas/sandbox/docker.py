"""Thin wrapper over the docker CLI, plus the hardening flags every sandboxed container gets."""

from __future__ import annotations

import json
import os
import subprocess

LABEL = "veritas.run"
SANDBOX_UID = "10001:10001"

# The `tool` profile (docs/architecture.md §6.6).
HARDENING = [
    "--read-only",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--user", SANDBOX_UID,
    "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m,mode=1777",  # noqa: S108 - a tmpfs inside the container
]  # fmt: skip
# For networked containers: no name resolution beyond the run's own containers.
# Docker rejects --dns together with --network none, so it is kept separate.
NO_EXTERNAL_DNS = ["--dns", "127.0.0.1"]


class DockerError(RuntimeError):
    pass


def docker(*args: str, env: dict[str, str] | None = None, timeout: float = 300, check: bool = True) -> str:
    proc = subprocess.run(  # noqa: S603 - fixed executable, argv list, no shell
        ["docker", *args],  # noqa: S607 - resolved from PATH like any docker client
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**os.environ, **(env or {})},
        check=False,
    )
    if check and proc.returncode != 0:
        raise DockerError(f"docker {' '.join(args[:3])} failed: {proc.stderr.strip()[-800:]}")
    return proc.stdout.strip()


def container_ip(name: str, network: str) -> str:
    networks = json.loads(docker("inspect", "--format", "{{json .NetworkSettings.Networks}}", name))
    return str(networks[network]["IPAddress"])


def remove_labeled(run_id: str) -> list[str]:
    """Remove every container and network labeled for a run; return whatever survived."""
    selector = f"label={LABEL}={run_id}"
    for cid in docker("ps", "-aq", "--filter", selector, check=False).split():
        docker("rm", "-f", cid, check=False)
    for net in docker("network", "ls", "-q", "--filter", selector, check=False).split():
        docker("network", "rm", net, check=False)
    leftovers = docker("ps", "-aq", "--filter", selector, check=False).split()
    leftovers += docker("network", "ls", "-q", "--filter", selector, check=False).split()
    return leftovers
