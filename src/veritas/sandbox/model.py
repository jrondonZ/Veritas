"""The `model` sandbox (docs/architecture.md §6.6, ADR 0008): llama-server with no network at all.

The server listens on 127.0.0.1 inside a container started with `--network none`, so
its namespace has only a loopback interface and nothing can leave it. The kernel
reaches the server through a relay script inside the same container (`docker exec -i`),
and weights come from the `veritas-models` volume, mounted read-only.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .docker import HARDENING, LABEL, docker

MODELS_VOLUME = "veritas-models"
MODEL_PORT = 8080


@dataclass(frozen=True)
class ModelLimits:
    memory: str  # container memory limit, e.g. "5g"
    cpus: float
    threads: int
    context: int  # tokens per server slot


@dataclass
class ModelSandbox:
    run_id: str
    image: str  # the model-server image ID
    weights: str  # file name inside the models volume
    limits: ModelLimits
    model: str  # the registered model name, for the container name

    @property
    def name(self) -> str:
        return f"vrt-{self.run_id}-model-{self.model}"[:120]

    def argv(self) -> list[str]:
        lim = self.limits
        return [
            "docker", "run", "-d", "--name", self.name, "--label", f"{LABEL}={self.run_id}",
            "--network", "none", *HARDENING,
            "--pids-limit", "256", "--memory", lim.memory, "--memory-swap", lim.memory, "--cpus", str(lim.cpus),
            "--mount", f"type=volume,source={MODELS_VOLUME},target=/models,readonly",
            self.image,
            "--model", f"/models/{self.weights}", "--host", "127.0.0.1", "--port", str(MODEL_PORT),
            "--ctx-size", str(lim.context), "--threads", str(lim.threads), "--parallel", "1", "--offline",
        ]  # fmt: skip

    def up(self) -> None:
        docker(*self.argv()[1:])

    def relay_argv(self) -> list[str]:
        return ["docker", "exec", "-i", self.name, "/veritas/relay.sh"]

    def logs(self) -> str:
        return docker("logs", "--tail", "40", self.name, check=False)

    def down(self) -> None:
        docker("rm", "-f", self.name, check=False)


def install_weights(image: str, source: Path, dest: str, sha256_hex: str) -> None:
    """Copy a weights file into the models volume; the copy is verified there before it becomes visible."""
    docker("volume", "create", "--label", "veritas.models=1", MODELS_VOLUME)
    docker(
        "run", "--rm", "--network", "none", *HARDENING,
        "--mount", f"type=bind,source={source.resolve().parent},target=/src,readonly",
        "--mount", f"type=volume,source={MODELS_VOLUME},target=/models",
        "--entrypoint", "/veritas/install.sh", image, source.name, dest, sha256_hex,
        timeout=1800,
    )  # fmt: skip


def remove_weights(image: str, dest: str) -> None:
    docker(
        "run", "--rm", "--network", "none", *HARDENING,
        "--mount", f"type=volume,source={MODELS_VOLUME},target=/models",
        "--entrypoint", "rm", image, "-f", "--", f"/models/{dest}",
    )  # fmt: skip
