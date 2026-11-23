"""Bundled labs under `labs/<name>/`, run with Docker Compose on internal networks."""

from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..documents import load_yaml
from ..sandbox.docker import docker

_VAR_RE = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)")
_NAME_RE = re.compile(r"[a-z][a-z0-9-]*")


@dataclass
class Lab:
    name: str
    root: Path  # project root
    compose_path: Path | None = None  # defaults to labs/<name>/compose.yaml

    @classmethod
    def from_compose(cls, compose_file: Path, root: Path) -> Lab:
        """The lab a scope's `environment.compose_file` names (its directory name is the lab's name)."""
        return cls(compose_file.resolve().parent.name, root, compose_path=compose_file)

    @property
    def dir(self) -> Path:
        return self.compose_file.parent

    @property
    def compose_file(self) -> Path:
        return self.compose_path or self.root / "labs" / self.name / "compose.yaml"

    @property
    def project(self) -> str:
        return str(load_yaml(self.compose_file).get("name") or f"vrt-lab-{self.name}")

    def networks(self) -> list[str]:
        """Docker names of the lab's networks, which the gateway joins."""
        declared = load_yaml(self.compose_file).get("networks") or {}
        return sorted(str((cfg or {}).get("name") or f"{self.project}_{key}") for key, cfg in declared.items())

    def volume(self, key: str) -> str:
        """Docker name of a volume the compose file declares (sensors mount it read-only)."""
        declared = load_yaml(self.compose_file).get("volumes") or {}
        if key not in declared:
            raise KeyError(f"lab {self.name} declares no volume {key!r}")
        return str((declared[key] or {}).get("name") or f"{self.project}_{key}")

    @property
    def service(self) -> str:
        return str(next(iter(load_yaml(self.compose_file)["services"])))

    def check(self) -> None:
        if not _NAME_RE.fullmatch(self.name) or not self.compose_file.is_file():
            raise FileNotFoundError(f"no lab named {self.name!r} under {self.root / 'labs'}")

    def secrets(self) -> dict[str, str]:
        """Random secrets for every ${VAR} the compose file needs, generated once per workspace."""
        path = self.root / ".veritas" / "labs" / self.name / "secrets.env"
        values: dict[str, str] = {}
        if path.exists():
            for line in path.read_text(encoding="utf-8").splitlines():
                key, sep, value = line.partition("=")
                if sep:
                    values[key] = value
        needed = sorted(set(_VAR_RE.findall(self.compose_file.read_text(encoding="utf-8"))))
        missing = [k for k in needed if k not in values]
        if missing:
            values.update({k: secrets.token_urlsafe(18) for k in missing})
            path.parent.mkdir(parents=True, exist_ok=True)
            # Only this user may read it (POSIX); on Windows the user profile's ACL already limits it.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write("".join(f"{k}={v}\n" for k, v in sorted(values.items())))
            if os.name == "posix":
                os.chmod(path, 0o600)
        return values

    def compose(self, *args: str, timeout: float = 600) -> str:
        return docker(
            "compose", "-p", self.project, "-f", str(self.compose_file), *args, env=self.secrets(), timeout=timeout
        )

    def health(self) -> dict[str, Any]:
        reply: dict[str, Any] = json.loads(
            self.compose("exec", "-T", self.service, "wget", "-qO-", "http://127.0.0.1:8080/health")
        )
        return reply

    def up(self) -> dict[str, Any]:
        self.check()
        self.compose("up", "-d", "--build", "--wait", "--wait-timeout", "180")
        return self.health()

    def reset(self, snapshot: str = "s-01") -> dict[str, Any]:
        self.check()
        self.compose("stop", self.service)
        self.compose("run", "--rm", "--no-deps", "--entrypoint", "node", self.service, "reset.mjs", snapshot)
        self.compose("up", "-d", "--wait", "--wait-timeout", "120")
        return self.health()

    def down(self) -> list[str]:
        self.check()
        self.compose("down", "--volumes", "--remove-orphans")
        return self.leftovers()

    def leftovers(self) -> list[str]:
        selector = f"label=com.docker.compose.project={self.project}"
        found = []
        for kind, cmd in (
            ("container", ["ps", "-aq"]),
            ("network", ["network", "ls", "-q"]),
            ("volume", ["volume", "ls", "-q"]),
        ):
            found += [f"{kind}:{x}" for x in docker(*cmd, "--filter", selector, check=False).split()]
        return found
