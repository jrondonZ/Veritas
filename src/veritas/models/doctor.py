"""`veritas models doctor` (docs/architecture.md §10.2): measure this machine and each model, and propose a profile.

The model server runs in Docker, so what counts is the CPUs and memory Docker gives
its containers, not the host's totals. Each registered model is loaded in a model
sandbox and timed on a fixed prompt: load time, prompt and generation tokens per second.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from dataclasses import dataclass
from typing import Any

from ..sandbox.docker import docker
from ..sandbox.model import ModelLimits, ModelSandbox
from .calls import SAMPLING
from .registry import RegisteredModel
from .server import LlamaCppServer, RelayClient

BENCH_PROMPT = [
    {"role": "system", "content": "You summarize security findings in one sentence."},
    {
        "role": "user",
        "content": "Finding: GET /api/notes/{id} returns another user's note when called with that note's id. "
        "Evidence: as alice, GET /api/notes/4 (owned by bob) returned 200 with bob's canary. "
        "Write a one-sentence summary for a developer.",
    },
]
BENCH_SCHEMA = {
    "type": "object",
    "properties": {"summary": {"type": "string", "maxLength": 400}},
    "required": ["summary"],
    "additionalProperties": False,
}


@dataclass(frozen=True)
class DockerResources:
    cpus: int
    memory_gb: float


@dataclass(frozen=True)
class Benchmark:
    model: str
    load_s: float
    prompt_tps: float
    generate_tps: float
    memory_mb: float | None
    sample: str


def docker_resources() -> DockerResources:
    cpus, memory = docker("info", "--format", "{{.NCPU}} {{.MemTotal}}").split()
    return DockerResources(int(cpus), round(int(memory) / 2**30, 1))


def propose_profile(resources: DockerResources) -> tuple[str, str]:
    """(profile, why). GPU profiles need a GPU the model container can use, which doctor does not detect yet."""
    if resources.memory_gb >= 30 and resources.cpus >= 8:
        return "cpu", f"{resources.cpus} CPUs and {resources.memory_gb} GB for containers fit the cpu profile"
    return "laptop", (
        f"{resources.cpus} CPUs and {resources.memory_gb} GB for containers: one 3-4B model serves every route"
    )


def _memory_mb(container: str) -> float | None:
    usage = docker("stats", "--no-stream", "--format", "{{.MemUsage}}", container, check=False).split("/")[0].strip()
    for unit, factor in (("GiB", 1024.0), ("MiB", 1.0), ("KiB", 1 / 1024)):
        if usage.endswith(unit):
            try:
                return round(float(usage.removesuffix(unit)) * factor, 1)
            except ValueError:
                return None
    return None


async def benchmark(model: RegisteredModel, image: str, limits: ModelLimits, max_tokens: int = 64) -> Benchmark:
    sandbox = ModelSandbox(f"doctor-{secrets.token_hex(3)}", image, model.file, limits, model.name)
    started = time.monotonic()
    await asyncio.to_thread(sandbox.up)
    relay = RelayClient(sandbox.relay_argv())
    try:
        server = LlamaCppServer(relay)
        await server.wait_ready()
        load = time.monotonic() - started
        generation = await server.generate(BENCH_PROMPT, BENCH_SCHEMA, SAMPLING, max_tokens)
        memory = await asyncio.to_thread(_memory_mb, sandbox.name)
    finally:
        await relay.close()
        await asyncio.to_thread(sandbox.down)
    rate: dict[str, Any] = {
        "prompt": generation.prompt_tokens / (generation.prompt_ms / 1000) if generation.prompt_ms else 0.0,
        "generate": generation.completion_tokens / (generation.predicted_ms / 1000) if generation.predicted_ms else 0.0,
    }
    return Benchmark(
        model.name, round(load, 1), round(rate["prompt"], 1), round(rate["generate"], 1), memory, generation.text[:200]
    )
