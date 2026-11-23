"""Gateway control channel: a Unix socket inside the gateway container.

The kernel reaches it with `docker exec <gateway> python -m veritas.gateway.ctl ...`,
so the gateway listens on nothing outside the internal sandbox network.
"""

from __future__ import annotations

import asyncio
import json
import socket
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .proxy import Gateway

SOCKET_PATH = "/run/veritas/control.sock"


async def serve_control(gateway: Gateway, path: str = SOCKET_PATH) -> asyncio.Server:
    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        reply: dict[str, Any]
        try:
            msg = json.loads(await asyncio.wait_for(reader.readline(), 5))
            op = msg.get("op")
            if op == "revoke":
                reply = {"ok": True, "cut": gateway.revoke(msg.get("tid"), everything=bool(msg.get("all")))}
            elif op == "stats":
                reply = {
                    "ok": True,
                    "stats": {f"{verdict}:{code}": n for (verdict, code), n in gateway.stats.items()},
                    "live": {tid: len(tasks) for tid, tasks in gateway.live.items() if tasks},
                }
            elif op == "health":
                reply = {"ok": True}
            else:
                reply = {"ok": False, "error": f"unknown op {op!r}"}
        except Exception as exc:  # report, never crash the gateway
            reply = {"ok": False, "error": str(exc)}
        writer.write((json.dumps(reply) + "\n").encode())
        await writer.drain()
        writer.close()

    return await asyncio.start_unix_server(handle, path)


def call(msg: dict[str, Any], path: str = SOCKET_PATH, timeout: float = 5.0) -> dict[str, Any]:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(path)
        s.sendall(json.dumps(msg).encode() + b"\n")
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    reply: dict[str, Any] = json.loads(data)
    return reply
