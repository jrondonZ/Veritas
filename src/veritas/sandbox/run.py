"""The per-run sandbox: an internal network, the egress gateway, and plugin containers.

Every container and network carries the label `veritas.run=<run id>`, so teardown
can prove nothing was left behind.
"""

from __future__ import annotations

import contextlib
import json
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..gateway.admission import GatewayConfig
from ..plugins.manifest import PluginManifest
from .docker import HARDENING, LABEL, NO_EXTERNAL_DNS, DockerError, container_ip, docker, remove_labeled

GATEWAY_PORT = 8080


@dataclass
class RunSandbox:
    """The internal sandbox network and the gateway for one run."""

    run_id: str
    run_dir: Path
    gateway_image: str
    config: GatewayConfig
    key: bytes
    target_networks: list[str] = field(default_factory=list)
    identity_secrets: dict[str, str] = field(default_factory=dict, repr=False)
    gateway_ip: str = ""
    _relay: subprocess.Popen[str] | None = field(default=None, repr=False)
    _relay_lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    @property
    def network(self) -> str:
        return f"vrt-{self.run_id}-sbx"

    @property
    def gateway(self) -> str:
        return f"vrt-{self.run_id}-gateway"

    @property
    def capture_dir(self) -> Path:
        return self.run_dir / "gateway"

    def up(self, ready_timeout: float = 20.0) -> None:
        self.capture_dir.mkdir(parents=True, exist_ok=True)
        config_path = self.run_dir / "gateway.json"
        config_path.write_text(self.config.model_dump_json(), encoding="utf-8")
        docker("network", "create", "--internal", "--label", f"{LABEL}={self.run_id}", self.network)
        docker(
            "run", "-d", "--name", self.gateway, "--label", f"{LABEL}={self.run_id}",
            "--network", self.network, *HARDENING, *NO_EXTERNAL_DNS,
            "--tmpfs", "/run/veritas:rw,nosuid,size=1m,mode=1777",
            "--pids-limit", "128", "--memory", "256m", "--memory-swap", "256m", "--cpus", "1",
            "--mount", f"type=bind,source={config_path},target=/etc/veritas/gateway.json,readonly",
            "--mount", f"type=bind,source={self.capture_dir},target=/capture",
            "-e", "VERITAS_RUN_KEY", "-e", "VERITAS_IDENTITY_SECRETS",
            self.gateway_image,
            env={"VERITAS_RUN_KEY": self.key.hex(), "VERITAS_IDENTITY_SECRETS": json.dumps(self.identity_secrets)},
        )  # fmt: skip
        for net in self.target_networks:
            docker("network", "connect", net, self.gateway)
        deadline = time.monotonic() + ready_timeout
        while "veritas-gateway ready" not in docker("logs", self.gateway, check=False):
            if time.monotonic() > deadline:
                raise DockerError("gateway did not become ready: " + docker("logs", self.gateway, check=False)[-800:])
            time.sleep(0.2)
        self.gateway_ip = container_ip(self.gateway, self.network)
        # One long-lived relay: a fresh `docker exec` per command can take seconds (docs/adr/0003).
        self._relay = subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            ["docker", "exec", "-i", self.gateway, "python", "-m", "veritas.gateway.ctl", "stdio"],  # noqa: S607
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        if not self.control({"op": "health"}).get("ok"):
            raise DockerError("gateway control relay did not answer")

    def control(self, msg: dict[str, Any]) -> dict[str, Any]:
        """One request over the persistent control relay."""
        relay = self._relay
        if relay is None or relay.poll() is not None or relay.stdin is None or relay.stdout is None:
            raise DockerError("gateway control relay is not running")
        with self._relay_lock:
            relay.stdin.write(json.dumps(msg) + "\n")
            relay.stdin.flush()
            line = relay.stdout.readline()
        if not line:
            raise DockerError("gateway control relay closed")
        reply: dict[str, Any] = json.loads(line)
        return reply

    def revoke(self, tid: str | None = None, everything: bool = False) -> dict[str, Any]:
        return self.control({"op": "revoke", "tid": tid, "all": everything})

    def plugin_argv(
        self, image: str, manifest: PluginManifest, task_id: str, command: list[str] | None = None
    ) -> list[str]:
        """argv for `docker run -i` of one plugin task; secrets travel in env, not argv."""
        res = manifest.resources
        network = self.network if manifest.capabilities.network == "target-scope" else "none"
        memory = f"{res.memory_bytes // (1 << 20)}m"
        return [
            "docker", "run", "-i", "--rm", "--name", f"vrt-{self.run_id}-{task_id}",
            "--label", f"{LABEL}={self.run_id}", "--network", network, *HARDENING,
            *(NO_EXTERNAL_DNS if network != "none" else []),
            "--tmpfs", "/work:rw,noexec,nosuid,size=64m,mode=1777", "--workdir", "/work",
            "--pids-limit", str(res.pids), "--memory", memory, "--memory-swap", memory, "--cpus", str(res.cpu),
            "-e", "VERITAS_TASK", "-e", "VERITAS_TOKEN", "-e", "VERITAS_PROXY_HOST", "-e", "VERITAS_PROXY_PORT",
            image, *(command if command is not None else manifest.runtime.command),
        ]  # fmt: skip

    def sensor_argv(self, image: str, manifest: PluginManifest, sensor_id: str, volume: str, mount: str) -> list[str]:
        """argv for a sensor: no network at all, and one volume mounted read-only (the `engine` profile)."""
        if manifest.kind != "sensor" or manifest.capabilities.network != "none":
            raise ValueError(f"{manifest.ref} is not a network-less sensor")
        res = manifest.resources
        memory = f"{res.memory_bytes // (1 << 20)}m"
        return [
            "docker", "run", "-i", "--rm", "--name", f"vrt-{self.run_id}-sensor-{sensor_id}",
            "--label", f"{LABEL}={self.run_id}", "--network", "none", *HARDENING,
            "--tmpfs", "/work:rw,noexec,nosuid,size=16m,mode=1777", "--workdir", "/work",
            "--pids-limit", str(res.pids), "--memory", memory, "--memory-swap", memory, "--cpus", str(res.cpu),
            "--mount", f"type=volume,source={volume},target={mount},readonly",
            image, *manifest.runtime.command,
        ]  # fmt: skip

    def executor_env(self) -> dict[str, str]:
        """The executor gets only the gateway's address; each script carries its own token."""
        return {"VERITAS_PROXY_HOST": self.gateway_ip, "VERITAS_PROXY_PORT": str(GATEWAY_PORT)}

    def plugin_env(self, task_id: str, token: str) -> dict[str, str]:
        return {
            "VERITAS_TASK": task_id,
            "VERITAS_TOKEN": token,
            "VERITAS_PROXY_HOST": self.gateway_ip,
            "VERITAS_PROXY_PORT": str(GATEWAY_PORT),
        }

    def down(self) -> list[str]:
        """Stop the gateway (it revokes everything on SIGTERM), remove all run resources, report leftovers."""
        if self._relay is not None:
            if self._relay.stdin is not None:
                with contextlib.suppress(Exception):
                    self._relay.stdin.close()
            with contextlib.suppress(Exception):
                self._relay.wait(timeout=10)
            if self._relay.poll() is None:
                self._relay.kill()
                self._relay.wait()
            if self._relay.stdout is not None:
                self._relay.stdout.close()
            self._relay = None
        docker("stop", "-t", "3", self.gateway, check=False)
        return remove_labeled(self.run_id)
