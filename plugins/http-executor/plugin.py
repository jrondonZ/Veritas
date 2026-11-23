"""Veritas HTTP executor plugin (stdlib only).

Runs request scripts written by the kernel. Each `execute` call carries its own
task token, and the gateway admits only the exact requests that token's envelope
allows. The executor returns status codes and gateway evidence IDs, never bodies:
the kernel reads every response from the gateway's capture and decides findings
itself, so the executor can't fabricate one.
"""

from __future__ import annotations

import base64
import json
import os
import socket
import sys
import time
from urllib.parse import urlsplit

PROTOCOL_VERSION = "2025-06-18"
STEP_SCHEMA = {
    "type": "object",
    "properties": {
        "id": {"type": "string"},
        "method": {"type": "string"},
        "url": {"type": "string"},
        "identity": {"type": ["string", "null"]},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "body": {"type": "string"},
    },
    "required": ["id", "method", "url"],
    "additionalProperties": False,
}
TOOLS = [
    {
        "name": "execute",
        "description": "Send a request script through the gateway; return status codes and evidence IDs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tid": {"type": "string"},
                "token": {"type": "string"},
                "steps": {"type": "array", "items": STEP_SCHEMA},
            },
            "required": ["tid", "token", "steps"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {"results": {"type": "array", "items": {"type": "object"}}},
            "required": ["results"],
        },
    }
]
_FORBIDDEN_HEADERS = {"host", "proxy-authorization", "content-length", "transfer-encoding", "connection"}


def _send(step: dict, tid: str, token: str, timeout: float = 30.0) -> dict:
    url = step["url"]
    authority = urlsplit(url).netloc
    body = step.get("body", "").encode("utf-8")
    credentials = base64.b64encode(f"{tid}:{token}".encode()).decode()
    lines = [f"{step['method']} {url} HTTP/1.1", f"Host: {authority}", f"Proxy-Authorization: Basic {credentials}"]
    if step.get("identity"):
        lines.append(f"Veritas-Identity: {step['identity']}")
    lines += [f"{k}: {v}" for k, v in step.get("headers", {}).items() if k.lower() not in _FORBIDDEN_HEADERS]
    if body or step["method"] in ("POST", "PUT", "PATCH"):
        lines.append(f"Content-Length: {len(body)}")
    request = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
    proxy = (os.environ["VERITAS_PROXY_HOST"], int(os.environ["VERITAS_PROXY_PORT"]))
    with socket.create_connection(proxy, timeout=timeout) as s:
        s.sendall(request)
        chunks = []
        while chunk := s.recv(65536):
            chunks.append(chunk)
    head = b"".join(chunks).partition(b"\r\n\r\n")[0].decode("latin-1").split("\r\n")
    if not head[0]:
        return {"status": 0, "error": "connection closed without a response"}
    headers = {}
    for line in head[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return {"status": int(head[0].split()[1]), "evidence": headers.get("veritas-evidence"),
            "denied": headers.get("veritas-denied")}  # fmt: skip


def execute(tid: str, token: str, steps: list[dict]) -> list[dict]:
    results = []
    for step in steps:  # strictly in order: scripts are deterministic
        started = time.monotonic()
        try:
            outcome = _send(step, tid, token)
        except OSError as exc:
            outcome = {"status": 0, "error": f"{type(exc).__name__}: {exc}"}
        outcome.update(id=step["id"], elapsed_ms=int((time.monotonic() - started) * 1000))
        results.append(outcome)
    return results


def _reply(msg_id, result=None, error=None) -> None:
    msg = {"jsonrpc": "2.0", "id": msg_id}
    msg.update({"error": error} if error else {"result": result})
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def main() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue  # notifications need no reply
        if method == "initialize":
            _reply(msg_id, {"protocolVersion": PROTOCOL_VERSION, "capabilities": {"tools": {}},
                            "serverInfo": {"name": "veritas-http-executor", "version": "0.0.1"}})  # fmt: skip
        elif method == "tools/list":
            _reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call" and msg["params"]["name"] == "execute":
            args = msg["params"]["arguments"]
            results = execute(args["tid"], args["token"], args["steps"])
            _reply(msg_id, {"content": [{"type": "text", "text": json.dumps(results)}],
                            "structuredContent": {"results": results}, "isError": False})  # fmt: skip
        else:
            _reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


if __name__ == "__main__":
    main()
