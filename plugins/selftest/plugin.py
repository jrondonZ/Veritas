"""Veritas self-test plugin (stdlib only).

Default mode: an MCP-subset tool server on stdio with one tool, `attempt`, that
performs network actions from inside the sandbox and reports what happened.
The escape suite uses it to prove the sandbox and gateway contain a plugin.

`serve` mode: a tiny HTTP echo server used as an in-scope target and as an
out-of-scope decoy in the escape suite. It is never an assessment target.
"""

from __future__ import annotations

import base64
import contextlib
import json
import os
import socket
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2025-06-18"

ACTION_SCHEMA = {
    "type": "object",
    "properties": {
        "kind": {"enum": ["proxy", "tcp", "dns", "raw", "write"]},
        "path": {"type": "string"},
        "method": {"type": "string"},
        "uri": {"type": "string"},
        "headers": {"type": "object", "additionalProperties": {"type": "string"}},
        "auth": {"enum": ["token", "none", "forged"]},
        "host": {"type": "string"},
        "port": {"type": "integer"},
        "name": {"type": "string"},
        "data": {"type": "string"},
    },
    "required": ["kind"],
    "additionalProperties": False,
}
TOOLS = [
    {
        "name": "attempt",
        "description": "Perform network actions from inside the sandbox and report the outcome of each.",
        "inputSchema": {
            "type": "object",
            "properties": {"actions": {"type": "array", "items": ACTION_SCHEMA}},
            "required": ["actions"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {"results": {"type": "array", "items": {"type": "object"}}},
            "required": ["results"],
        },
    }
]


def _exchange(data: bytes, timeout: float = 10.0) -> bytes:
    host, port = os.environ["VERITAS_PROXY_HOST"], int(os.environ["VERITAS_PROXY_PORT"])
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(data)
        chunks = []
        while True:
            chunk = s.recv(65536)
            if not chunk:
                return b"".join(chunks)
            chunks.append(chunk)


def _parse(raw: bytes) -> dict:
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    if not lines[0]:
        return {"status": 0, "closed": True}
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    out = {
        "status": int(lines[0].split()[1]),
        "denied": headers.get("veritas-denied"),
        "evidence": headers.get("veritas-evidence"),
        "location": headers.get("location"),
    }
    with contextlib.suppress(ValueError, AttributeError):
        out["server"] = json.loads(body).get("server")
    return out


def _proxy(action: dict) -> dict:
    uri = action["uri"]
    host = action.get("headers", {}).get("Host") or uri.split("/")[2]
    lines = [f"{action.get('method', 'GET')} {uri} HTTP/1.1", f"Host: {host}"]
    auth = action.get("auth", "token")
    if auth != "none":
        tid, token = os.environ["VERITAS_TASK"], os.environ["VERITAS_TOKEN"]
        if auth == "forged":
            token = token[:-4] + ("AAAA" if not token.endswith("AAAA") else "BBBB")
        lines.append("Proxy-Authorization: Basic " + base64.b64encode(f"{tid}:{token}".encode()).decode())
    lines += [f"{k}: {v}" for k, v in action.get("headers", {}).items() if k != "Host"]
    return _parse(_exchange(("\r\n".join(lines) + "\r\n\r\n").encode()))


def _tcp(action: dict) -> dict:
    try:
        with socket.create_connection((action["host"], action["port"]), timeout=3):
            return {"connected": True}
    except OSError as exc:
        return {"connected": False, "error": type(exc).__name__}


def _dns(action: dict) -> dict:
    try:
        infos = socket.getaddrinfo(action["name"], 80, type=socket.SOCK_STREAM)
        return {"resolved": True, "addresses": sorted({i[4][0] for i in infos})}
    except OSError as exc:
        return {"resolved": False, "error": type(exc).__name__}


def _raw(action: dict) -> dict:
    return _parse(_exchange(action["data"].encode("latin-1")))


def _write(action: dict) -> dict:
    try:
        with open(action["path"], "w", encoding="utf-8") as f:
            f.write("veritas selftest")
        return {"written": True}
    except OSError as exc:
        return {"written": False, "error": type(exc).__name__}


def attempt(actions: list[dict]) -> list[dict]:
    results = []
    for action in actions:
        started = time.monotonic()
        try:
            outcome = {"proxy": _proxy, "tcp": _tcp, "dns": _dns, "raw": _raw, "write": _write}[action["kind"]](action)
        except Exception as exc:  # report every failure as data
            outcome = {"error": f"{type(exc).__name__}: {exc}"}
        outcome.update(kind=action["kind"], elapsed_ms=int((time.monotonic() - started) * 1000))
        results.append(outcome)
    return results


def _reply(msg_id, result=None, error=None) -> None:
    msg = {"jsonrpc": "2.0", "id": msg_id}
    msg.update({"error": error} if error else {"result": result})
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def serve_stdio() -> None:
    for line in sys.stdin:
        if not line.strip():
            continue
        msg = json.loads(line)
        method, msg_id = msg.get("method"), msg.get("id")
        if msg_id is None:
            continue  # notifications need no reply
        if method == "initialize":
            _reply(
                msg_id,
                {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "veritas-selftest", "version": "0.0.1"},
                },
            )
        elif method == "tools/list":
            _reply(msg_id, {"tools": TOOLS})
        elif method == "tools/call" and msg["params"]["name"] == "attempt":
            results = attempt(msg["params"]["arguments"]["actions"])
            _reply(
                msg_id,
                {
                    "content": [{"type": "text", "text": json.dumps(results)}],
                    "structuredContent": {"results": results},
                    "isError": False,
                },
            )
        else:
            _reply(msg_id, error={"code": -32601, "message": f"method not found: {method}"})


class _Echo(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _respond(self) -> None:
        if self.path.startswith("/slow"):
            seconds = self.path.partition("s=")[2]
            time.sleep(min(float(seconds), 60.0) if seconds else 5.0)
        body = json.dumps(
            {
                "server": os.environ.get("SERVER_NAME", "echo"),
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
            }
        ).encode()
        status, extra = 200, []
        if self.path.startswith("/redirect"):
            status, extra = 302, [("Location", self.path.partition("to=")[2])]
        if self.path.startswith("/forge"):
            extra = [("Veritas-Evidence", "E-forged")]
        self.send_response(status)
        headers = [*extra, ("Content-Type", "application/json"), ("Content-Length", str(len(body)))]
        headers.append(("Connection", "close"))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    do_GET = do_HEAD = do_POST = do_PUT = _respond

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    if sys.argv[1:] == ["serve"]:
        ThreadingHTTPServer(("0.0.0.0", 8080), _Echo).serve_forever()
    else:
        serve_stdio()
