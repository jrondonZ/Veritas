"""The llama.cpp adapter (docs/architecture.md §6.4 `ModelServer`, §10.4).

The kernel speaks HTTP to llama-server through the relay inside the model container
(`docker exec -i … relay.sh`): a byte count and the raw request on the relay's stdin,
one line of base64 back on its stdout. No socket is opened by the kernel, and the
server's namespace has no network at all.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import time
from dataclasses import dataclass
from typing import Any

import h11

MAX_RESPONSE = 16 * 1024 * 1024


class ModelServerError(Exception):
    pass


class NotReady(ModelServerError):
    """The server is not accepting connections, or is still loading its model."""


@dataclass(frozen=True)
class Sampling:
    """Reproducible mode (§10.4): greedy decoding with a fixed seed."""

    temperature: float = 0.0
    top_k: int = 1
    seed: int = 0

    def to_json(self) -> dict[str, Any]:
        return {"temperature": self.temperature, "top_k": self.top_k, "seed": self.seed}


@dataclass(frozen=True)
class Generation:
    text: str
    finish_reason: str
    prompt_tokens: int
    completion_tokens: int
    prompt_ms: float
    predicted_ms: float


def http_request(method: str, path: str, body: bytes | None = None) -> bytes:
    head = [f"{method} {path} HTTP/1.1", "Host: 127.0.0.1", "Connection: close", "Accept: application/json"]
    if body is not None:
        head += ["Content-Type: application/json", f"Content-Length: {len(body)}"]
    return ("\r\n".join(head) + "\r\n\r\n").encode("ascii") + (body or b"")


def parse_response(method: str, data: bytes) -> tuple[int, bytes]:
    """Status and body of one HTTP/1.1 response that ends when the server closes the connection."""
    conn = h11.Connection(h11.CLIENT, max_incomplete_event_size=64 * 1024)
    conn.send(h11.Request(method=method, target="/", headers=[("Host", "127.0.0.1")]))
    conn.send(h11.EndOfMessage())
    conn.receive_data(data)
    conn.receive_data(b"")
    status: int | None = None
    body = bytearray()
    while True:
        try:
            event = conn.next_event()
        except h11.RemoteProtocolError as exc:
            raise ModelServerError(f"malformed response from the model server: {exc}") from exc
        if isinstance(event, h11.Response):
            status = event.status_code
        elif isinstance(event, h11.Data):
            body += event.data
        elif isinstance(event, h11.EndOfMessage | h11.ConnectionClosed) or event is h11.NEED_DATA:
            break
    if status is None:
        raise ModelServerError("the model server sent no response")
    return status, bytes(body)


class RelayClient:
    """One long-lived relay process; requests are strictly sequential (one server slot, §10.6)."""

    def __init__(self, argv: list[str]):
        self.argv = argv
        self._proc: asyncio.subprocess.Process | None = None
        self._lock = asyncio.Lock()

    async def _start(self) -> asyncio.subprocess.Process:
        if self._proc is None or self._proc.returncode is not None:
            self._proc = await asyncio.create_subprocess_exec(
                *self.argv,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
                limit=MAX_RESPONSE * 2,
            )
        return self._proc

    async def request(self, method: str, path: str, body: Any = None, timeout: float = 600) -> tuple[int, bytes]:
        raw = http_request(method, path, None if body is None else json.dumps(body).encode())
        async with self._lock:
            proc = await self._start()
            if proc.stdin is None or proc.stdout is None:
                raise ModelServerError("the relay has no stdio pipes")
            proc.stdin.write(f"{len(raw)}\n".encode() + raw)
            await proc.stdin.drain()
            try:
                line = await asyncio.wait_for(proc.stdout.readline(), timeout)
            except TimeoutError:
                await self.close()
                raise ModelServerError(f"{method} {path}: no answer within {timeout:.0f} s") from None
        if not line:
            await self.close()
            raise ModelServerError("the relay exited")
        if not line.strip():
            raise NotReady("the model server is not accepting connections")
        return parse_response(method, base64.b64decode(line))

    async def close(self) -> None:
        proc, self._proc = self._proc, None
        if proc is None:
            return
        if proc.stdin is not None:
            with contextlib.suppress(Exception):
                proc.stdin.close()
        try:
            await asyncio.wait_for(proc.wait(), 5)
        except TimeoutError:
            proc.kill()
            await proc.wait()


class LlamaCppServer:
    """`ModelServer` over llama-server's OpenAI-compatible chat endpoint, with JSON-Schema-constrained output."""

    def __init__(self, relay: RelayClient):
        self.relay = relay

    async def _json(self, method: str, path: str, body: Any = None, timeout: float = 600) -> Any:
        status, data = await self.relay.request(method, path, body, timeout)
        if status == 503:
            raise NotReady("the model is still loading")
        if status != 200:
            raise ModelServerError(f"{method} {path} returned {status}: {data[:300]!r}")
        try:
            return json.loads(data)
        except ValueError as exc:
            raise ModelServerError(f"{method} {path} returned invalid JSON") from exc

    async def wait_ready(self, timeout: float = 300) -> None:
        deadline = time.monotonic() + timeout
        while True:
            try:
                await self._json("GET", "/health", timeout=30)
                return
            except NotReady:
                if time.monotonic() > deadline:
                    raise
                await asyncio.sleep(1)

    async def props(self) -> dict[str, Any]:
        reply: dict[str, Any] = await self._json("GET", "/props", timeout=30)
        return reply

    async def generate(
        self, messages: list[dict[str, str]], schema: dict[str, Any], sampling: Sampling, max_tokens: int
    ) -> Generation:
        body = {
            "messages": messages,
            **sampling.to_json(),
            "max_tokens": max_tokens,
            "cache_prompt": True,  # the shared prompt prefix is computed once per stage (§10.4)
            "response_format": {"type": "json_schema", "json_schema": {"name": "output", "schema": schema}},
        }
        reply = await self._json("POST", "/v1/chat/completions", body)
        try:
            choice = reply["choices"][0]
            usage, timings = reply.get("usage") or {}, reply.get("timings") or {}
            return Generation(
                text=str(choice["message"]["content"]),
                finish_reason=str(choice.get("finish_reason") or ""),
                prompt_tokens=int(usage.get("prompt_tokens") or 0),
                completion_tokens=int(usage.get("completion_tokens") or 0),
                prompt_ms=float(timings.get("prompt_ms") or 0.0),
                predicted_ms=float(timings.get("predicted_ms") or 0.0),
            )
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise ModelServerError(f"unexpected completion shape: {exc!r}") from exc

    async def count_tokens(self, messages: list[dict[str, str]]) -> int:
        """Prompt tokens as the model's own tokenizer counts them, after its chat template (§10.4 accounting)."""
        rendered = await self._json("POST", "/apply-template", {"messages": messages}, timeout=60)
        tokens = await self._json("POST", "/tokenize", {"content": rendered["prompt"]}, timeout=60)
        return len(tokens["tokens"])
