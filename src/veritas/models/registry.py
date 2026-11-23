"""Registered model weights (docs/architecture.md §10.2): local files only, pinned by SHA-256 in the lock.

Veritas never downloads weights. `veritas models add <file>` hashes the file, reads its
GGUF metadata, records its license, and has the sandbox copy it into the models
volume, where the copy is verified against the same hash before it becomes visible.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .gguf import read_metadata

NAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
PERMISSIVE = frozenset({"apache-2.0", "mit", "bsd-2-clause", "bsd-3-clause"})

Installer = Callable[[Path, str, str], None]  # (source file, file name in the volume, sha256 hex)


class RegistryError(ValueError):
    pass


@dataclass(frozen=True)
class RegisteredModel:
    name: str
    sha256: str  # "sha256:<hex>"
    size: int
    file: str  # file name inside the models volume
    license: str
    quantization: str | None
    architecture: str | None
    context_length: int | None
    title: str | None  # general.name from the GGUF metadata
    added: str

    @property
    def digest_short(self) -> str:
        return self.sha256.removeprefix("sha256:")[:12]

    @property
    def permissive(self) -> bool:
        return self.license.lower() in PERMISSIVE

    def to_json(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> RegisteredModel:
        return cls(**data)


def default_name(path: Path) -> str:
    stem = re.sub(r"[^a-z0-9._-]+", "-", path.stem.lower()).strip("-.")
    return stem[:64] or "model"


def hash_file(path: Path, chunk: int = 4 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while block := f.read(chunk):
            h.update(block)
    return h.hexdigest()


def load_models(lock: dict[str, Any]) -> dict[str, RegisteredModel]:
    return {name: RegisteredModel.from_json(entry) for name, entry in sorted((lock.get("models") or {}).items())}


def register(
    path: Path, lock: dict[str, Any], install: Installer, name: str | None = None, license_id: str | None = None
) -> tuple[RegisteredModel, dict[str, Any]]:
    """Register one GGUF file; returns the entry and the lock's new `models` section."""
    if not path.is_file():
        raise RegistryError(f"no such file: {path}")
    name = name or default_name(path)
    if not NAME.match(name):
        raise RegistryError(f"model names are lowercase letters, digits, '.', '_' or '-': {name!r}")
    models = dict(lock.get("models") or {})
    if name in models:
        raise RegistryError(f"a model named {name} is already registered; remove it first or choose --name")
    info = read_metadata(path)
    if not info.chat_template:
        raise RegistryError("the file carries no chat template, which llama-server needs for chat requests")
    license_id = (license_id or info.license or "").strip().lower()
    if not license_id:
        raise RegistryError("the file declares no license; pass --license with its SPDX identifier")
    sha = hash_file(path)
    if any(m.get("sha256") == f"sha256:{sha}" for m in models.values()):
        raise RegistryError("these weights are already registered under another name")
    entry = RegisteredModel(
        name=name,
        sha256=f"sha256:{sha}",
        size=path.stat().st_size,
        file=f"{sha[:16]}.gguf",
        license=license_id,
        quantization=info.quantization,
        architecture=info.architecture,
        context_length=info.context_length,
        title=info.name,
        added=datetime.now(UTC).isoformat(timespec="seconds"),
    )
    install(path, entry.file, sha)
    models[name] = entry.to_json()
    return entry, models
