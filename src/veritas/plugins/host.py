"""Plugin host: start a plugin process, enforce the handshake, call operations, close."""

from __future__ import annotations

import asyncio
import contextlib
import os
from dataclasses import dataclass, field
from typing import Any

from .. import __version__
from ..core.canonical import digest
from .manifest import PluginManifest
from .rpc import JsonRpcClient, ProtocolViolation, RpcError

PROTOCOL_VERSION = "2025-06-18"
MAX_MESSAGE = 4 * 1024 * 1024
# The handshake waits for the container to start too. That takes about 10 s on an idle Docker Desktop and over a minute
# on a busy one, so this is a liveness bound, not a performance target.
HANDSHAKE_TIMEOUT = 120.0


class PluginRefused(Exception):
    pass


@dataclass
class TaskReport:
    returncode: int | None
    stderr_tail: str
    violations: list[str]
    notifications: int


@dataclass
class PluginSession:
    manifest: PluginManifest
    process: asyncio.subprocess.Process
    client: JsonRpcClient
    tools_digest: str
    notifications: list[dict[str, Any]] = field(default_factory=list)
    _stderr: bytearray = field(default_factory=bytearray)
    _stderr_task: asyncio.Task[None] | None = None

    async def call(self, op: str, arguments: dict[str, Any], timeout: float | None = None) -> dict[str, Any]:
        self.manifest.operation(op)  # only declared operations can be called
        result = await self.client.request(
            "tools/call",
            {"name": op, "arguments": arguments},
            timeout=timeout or self.manifest.resources.timeout,
        )
        if not isinstance(result, dict) or "structuredContent" not in result:
            raise ProtocolViolation("tools/call result lacks structuredContent")
        if result.get("isError"):
            raise RpcError(-32000, f"operation {op} reported an error")
        content: dict[str, Any] = result["structuredContent"]
        return content

    async def close(self, timeout: float = 5.0) -> TaskReport:
        await self.client.close()
        if self.process.stdin is not None:
            with contextlib.suppress(Exception):
                self.process.stdin.close()
        try:
            await asyncio.wait_for(self.process.wait(), timeout)
        except TimeoutError:
            self.process.kill()
            await self.process.wait()
        if self._stderr_task:
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._stderr_task, 1)
        return TaskReport(
            self.process.returncode,
            self._stderr[-4000:].decode("utf-8", "replace"),
            list(self.client.violations),
            len(self.notifications),
        )


async def start_plugin(
    argv: list[str],
    manifest: PluginManifest,
    *,
    env: dict[str, str] | None = None,
    expected_tools_digest: str | None = None,
    handshake_timeout: float = HANDSHAKE_TIMEOUT,
) -> PluginSession:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=MAX_MESSAGE,
        env={**os.environ, **(env or {})},
    )
    stdin, stdout, stderr = proc.stdin, proc.stdout, proc.stderr
    if stdin is None or stdout is None or stderr is None:
        proc.kill()
        raise PluginRefused("plugin process has no stdio pipes")
    notifications: list[dict[str, Any]] = []
    client = JsonRpcClient(stdout, stdin, on_notification=notifications.append)
    session = PluginSession(manifest, proc, client, tools_digest="", notifications=notifications)

    async def drain_stderr() -> None:
        while chunk := await stderr.read(65536):
            session._stderr += chunk
            del session._stderr[:-65536]

    session._stderr_task = asyncio.create_task(drain_stderr())
    try:
        init = await client.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},  # no sampling, elicitation, or roots
                "clientInfo": {"name": "veritas", "version": __version__},
            },
            timeout=handshake_timeout,
        )
        if not isinstance(init, dict) or init.get("protocolVersion") != PROTOCOL_VERSION:
            raise PluginRefused(
                f"plugin speaks protocol {init.get('protocolVersion') if isinstance(init, dict) else init!r}"
            )
        await client.notify("notifications/initialized")
        listed = await client.request("tools/list", timeout=handshake_timeout)
        tools = listed.get("tools") if isinstance(listed, dict) else None
        if not isinstance(tools, list):
            raise PluginRefused("tools/list returned no tool list")
        names = sorted(t.get("name") for t in tools)
        declared = sorted(op.name for op in manifest.operations)
        if names != declared:
            raise PluginRefused(f"tools/list {names} does not match the manifest operations {declared}")
        session.tools_digest = digest(tools)
        if expected_tools_digest and session.tools_digest != expected_tools_digest:
            raise PluginRefused("tool schemas differ from the locked digest")
    except (TimeoutError, PluginRefused, ProtocolViolation, RpcError) as exc:
        await session.close(timeout=2)
        if isinstance(exc, PluginRefused):
            raise
        raise PluginRefused(f"handshake failed: {exc!r}") from exc
    return session
