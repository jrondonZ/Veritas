"""JSON-RPC 2.0 client over newline-delimited stdio, as in MCP's stdio transport.

The kernel declares no client capabilities, so any request a plugin sends to the
kernel (sampling, elicitation, roots, anything else) is answered with
"method not found" and recorded as a violation.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from collections.abc import Callable
from typing import Any


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(f"{code}: {message}")
        self.code, self.message = code, message


class ProtocolViolation(Exception):
    pass


class JsonRpcClient:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        on_notification: Callable[[dict[str, Any]], None] | None = None,
    ):
        self._reader, self._writer = reader, writer
        self._on_notification = on_notification
        self._next_id = 1
        self._pending: dict[int, asyncio.Future[Any]] = {}
        self.violations: list[str] = []
        self._loop_task = asyncio.create_task(self._read_loop())

    async def request(self, method: str, params: dict[str, Any] | None = None, timeout: float = 30.0) -> Any:
        msg_id = self._next_id
        self._next_id += 1
        future = asyncio.get_running_loop().create_future()
        self._pending[msg_id] = future
        await self._send({"jsonrpc": "2.0", "id": msg_id, "method": method, **({"params": params} if params else {})})
        try:
            return await asyncio.wait_for(future, timeout)
        finally:
            self._pending.pop(msg_id, None)

    async def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        await self._send({"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})})

    async def _send(self, msg: dict[str, Any]) -> None:
        self._writer.write(json.dumps(msg).encode() + b"\n")
        await self._writer.drain()

    def _fail_all(self, exc: Exception) -> None:
        for future in self._pending.values():
            if not future.done():
                future.set_exception(exc)

    async def _read_loop(self) -> None:
        try:
            while True:
                try:
                    line = await self._reader.readline()
                except (asyncio.LimitOverrunError, ValueError):
                    raise ProtocolViolation("message exceeds the size limit") from None
                if not line:
                    raise ProtocolViolation("plugin closed its output")
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    raise ProtocolViolation("plugin wrote a line that is not JSON") from None
                if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                    raise ProtocolViolation("not a JSON-RPC 2.0 message")
                if "method" in msg and "id" in msg:
                    self.violations.append(
                        f"plugin requested {msg['method']!r}; the kernel grants no client capabilities"
                    )
                    await self._send(
                        {"jsonrpc": "2.0", "id": msg["id"], "error": {"code": -32601, "message": "method not found"}}
                    )
                elif "method" in msg:
                    if self._on_notification:
                        self._on_notification(msg)
                elif msg.get("id") in self._pending:
                    future = self._pending[msg["id"]]
                    if "error" in msg:
                        err = msg["error"] or {}
                        future.set_exception(RpcError(int(err.get("code", -32000)), str(err.get("message", ""))))
                    else:
                        future.set_result(msg.get("result"))
                else:
                    raise ProtocolViolation(f"response to unknown request id {msg.get('id')!r}")
        except ProtocolViolation as exc:
            self.violations.append(str(exc))
            self._fail_all(exc)
        except asyncio.CancelledError:
            self._fail_all(ProtocolViolation("connection closed"))
            raise

    async def close(self) -> None:
        self._loop_task.cancel()
        with contextlib.suppress(asyncio.CancelledError, Exception):
            await self._loop_task
