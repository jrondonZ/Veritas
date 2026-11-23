"""Docker-backed sandboxes, per-run networks, and first-party images (docs/architecture.md §6.6).

The sandbox runner and env providers are the only kernel components that touch Docker.
"""

from .docker import HARDENING, LABEL, NO_EXTERNAL_DNS, DockerError, container_ip, docker, remove_labeled
from .images import (
    EXECUTOR_IMAGE,
    GATEWAY_IMAGE,
    IMAGES,
    SELFTEST_IMAGE,
    SENSOR_IMAGE,
    build_images,
    lock_path,
    read_lock,
    write_lock,
)
from .run import GATEWAY_PORT, RunSandbox

__all__ = [
    "EXECUTOR_IMAGE",
    "GATEWAY_IMAGE",
    "GATEWAY_PORT",
    "HARDENING",
    "IMAGES",
    "LABEL",
    "NO_EXTERNAL_DNS",
    "SELFTEST_IMAGE",
    "SENSOR_IMAGE",
    "DockerError",
    "RunSandbox",
    "build_images",
    "container_ip",
    "docker",
    "lock_path",
    "read_lock",
    "remove_labeled",
    "write_lock",
]
