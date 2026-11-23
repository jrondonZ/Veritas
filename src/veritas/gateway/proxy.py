"""Asyncio HTTP/1.1 forward proxy built on h11.

One request per client connection (`Connection: close` both ways), so every
request is admitted, rate-limited, forwarded to a pinned address, captured, and
logged on its own. Responses are buffered (capped) so the evidence ID can be
content-derived and returned in the `Veritas-Evidence` header.
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import hmac
import json
import os
import tempfile
import time
from collections import Counter
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import h11

from ..core.canonical import canonical_bytes, canonical_json, sha256_hex
from .admission import (
    Admission,
    AdmissionState,
    Denied,
    GatewayConfig,
    GatewayIdentity,
    GatewayTarget,
    ProxyRequest,
    TokenBucket,
    admit,
    authority_of,
)

HeaderList = list[tuple[bytes, bytes]]
Reply = tuple[int, HeaderList, bytes, bytes]  # status, headers, body, reason

HOP_BY_HOP = frozenset(
    {
        b"connection",
        b"keep-alive",
        b"proxy-authorization",
        b"proxy-authenticate",
        b"proxy-connection",
        b"te",
        b"trailer",
        b"transfer-encoding",
        b"upgrade",
        b"content-length",
        b"host",
    }
)
SINGLETON_REQUEST_HEADERS = (b"host", b"proxy-authorization", b"veritas-identity")
MASKED_HEADERS = frozenset({b"authorization", b"cookie", b"set-cookie"})


class _BadRequest(Exception):
    pass


class _UpstreamError(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code)
        self.code, self.detail = code, detail


def _iso_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _update_jar(jar: dict[str, str], headers: Iterable[tuple[bytes, bytes]]) -> None:
    """Apply Set-Cookie headers to a cookie jar, honoring removals."""
    for name, value in headers:
        if name != b"set-cookie":
            continue
        pair, _, attributes = value.decode("latin-1").partition(";")
        cookie, eq, cookie_value = pair.strip().partition("=")
        if not eq or not cookie:
            continue
        attrs = attributes.lower().replace(" ", "")
        if not cookie_value or "max-age=0" in attrs or "expires=thu,01jan1970" in attrs:
            jar.pop(cookie, None)
        else:
            jar[cookie] = cookie_value


class CaptureSink:
    """Writes exchange records and the decision log into a capture directory."""

    def __init__(self, directory: Path, mask_key: bytes):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self._mask_key = mask_key
        # Held open for the sink's lifetime and closed in close().
        self._decisions = open(self.dir / "decisions.jsonl", "a", encoding="utf-8", newline="\n")  # noqa: SIM115

    def pseudonym(self, secret: str) -> str:
        """A stable stand-in for a secret: equal secrets get equal pseudonyms, and nothing is revealed."""
        digest = hmac.new(self._mask_key, secret.encode("latin-1"), hashlib.sha256).hexdigest()[:10]
        return f"<masked:{digest}>"

    def mask(self, name: bytes, value: bytes) -> str:
        text = value.decode("latin-1")
        pseudonym = self.pseudonym
        if name == b"set-cookie":
            pair, sep, attributes = text.partition(";")
            cookie, eq, val = pair.partition("=")
            return cookie + eq + pseudonym(val) + sep + attributes if eq else pseudonym(text)
        if name == b"cookie":
            parts = []
            for item in text.split(";"):
                cookie, eq, val = item.strip().partition("=")
                parts.append(cookie + eq + pseudonym(val) if eq else pseudonym(item))
            return "; ".join(parts)
        scheme, space, credential = text.partition(" ")
        return scheme + space + pseudonym(credential) if space else pseudonym(text)

    def headers(self, headers: list[tuple[bytes, bytes]]) -> list[list[str]]:
        return [
            [name.decode("latin-1"), self.mask(name, value) if name in MASKED_HEADERS else value.decode("latin-1")]
            for name, value in headers
        ]

    def exchange(self, record: dict[str, Any]) -> str:
        data = canonical_bytes(record)
        evidence_id = "E-" + sha256_hex(data)[:12]
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-")
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, self.dir / f"{evidence_id}.json")
        return evidence_id

    def decision(self, entry: dict[str, Any]) -> None:
        self._decisions.write(canonical_json(entry) + "\n")
        self._decisions.flush()

    def close(self) -> None:
        self._decisions.close()


class _Limiter:
    def __init__(self, rps: float, concurrency: int):
        self.bucket = TokenBucket(rps)
        self.slots = asyncio.Semaphore(concurrency)

    async def __aenter__(self) -> None:
        await self.slots.acquire()
        try:
            delay = self.bucket.reserve(time.monotonic())
            if delay > 0:
                await asyncio.sleep(delay)
        except BaseException:
            self.slots.release()
            raise

    async def __aexit__(self, *exc: object) -> None:
        self.slots.release()


class Gateway:
    def __init__(
        self,
        config: GatewayConfig,
        key: bytes,
        sink: CaptureSink,
        *,
        upstream_timeout: float = 30.0,
        connect_timeout: float = 5.0,
        request_timeout: float = 30.0,
        max_body: int = 8 * 1024 * 1024,
        max_clients: int = 64,
        clock: Callable[[], float] = time.time,
        secrets: dict[str, str] | None = None,
    ):
        self.config, self.key, self.sink, self.clock = config, key, sink, clock
        self._secrets = dict(secrets or {})  # identity id -> login secret; never logged or relayed
        self._sessions: dict[str, dict[str, str]] = {}  # identity id -> cookie jar
        self._failed_logins: set[str] = set()
        self._login_locks: dict[str, asyncio.Lock] = {}
        self.upstream_timeout, self.connect_timeout, self.request_timeout = (
            upstream_timeout,
            connect_timeout,
            request_timeout,
        )
        self.max_body = max_body
        self.state = AdmissionState()
        self.limiters = {t.id: _Limiter(t.rps, t.concurrency) for t in config.targets}
        self.live: dict[str, set[asyncio.Task[Any]]] = {}
        self.stats: Counter[tuple[str, str]] = Counter()
        self._clients = asyncio.Semaphore(max_clients)

    # Control ---------------------------------------------------------------

    def revoke(self, tid: str | None = None, *, everything: bool = False) -> int:
        """Refuse the token(s) from now on and cut their in-flight requests."""
        if everything:
            self.state.run_revoked = True
            tasks = [t for tasks in self.live.values() for t in tasks]
        else:
            if tid is None:
                raise ValueError("tid or everything=True is required")
            self.state.revoked.add(tid)
            tasks = list(self.live.get(tid, ()))
        for task in tasks:
            task.cancel()
        self.sink.decision({"ts": _iso_now(), "event": "revoke", "tid": tid, "all": everything, "cut": len(tasks)})
        return len(tasks)

    async def serve(self, host: str, port: int) -> asyncio.base_events.Server:
        return await asyncio.start_server(self.handle, host, port)

    # Request handling ------------------------------------------------------

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is None:
            raise RuntimeError("Gateway.handle must run inside an asyncio task")
        tid: str | None = None
        if self._clients.locked():
            await self._raw(writer, 503, "gateway_busy")
            writer.close()
            return
        async with self._clients:
            conn = h11.Connection(h11.SERVER, max_incomplete_event_size=64 * 1024)
            try:
                try:
                    request, body = await asyncio.wait_for(self._read_request(conn, reader), self.request_timeout)
                except (h11.RemoteProtocolError, _BadRequest) as exc:
                    self._log(verdict="deny", code="bad_request", detail=str(exc))
                    await self._raw(writer, 400, "bad_request")
                    return
                except TimeoutError:
                    self._log(verdict="deny", code="request_timeout")
                    return
                preq = self._proxy_request(request)
                try:
                    adm = admit(preq, self.config, self.key, self.state, self.clock())
                except Denied as denied:
                    self._log(req=preq, verdict="deny", code=denied.code, detail=denied.detail)
                    await self._send(writer, conn, *self._denial(denied))
                    return
                tid = adm.claims.tid
                self.live.setdefault(tid, set()).add(task)
                jar = None
                if adm.identity is not None:
                    jar = await self._session(adm)
                    if jar is None:
                        self._log(req=preq, verdict="error", code="identity_login_failed", tid=tid,
                                  target=adm.target.id, identity=adm.identity)  # fmt: skip
                        await self._send(writer, conn, *self._error(502, "identity_login_failed", adm.identity))
                        return
                try:
                    async with self.limiters[adm.target.id]:
                        sent, response, resp_body = await asyncio.wait_for(
                            self._forward(adm, request, body, jar), self.upstream_timeout
                        )
                except TimeoutError:
                    self._log(req=preq, verdict="error", code="upstream_timeout", tid=tid, target=adm.target.id)
                    await self._send(writer, conn, *self._error(504, "upstream_timeout"))
                    return
                except _UpstreamError as exc:
                    self._log(
                        req=preq, verdict="error", code=exc.code, detail=exc.detail, tid=tid, target=adm.target.id
                    )
                    await self._send(writer, conn, *self._error(502, exc.code, exc.detail))
                    return
                if jar is not None:
                    _update_jar(jar, response.headers)
                evidence = self.sink.exchange(self._record(adm, request.method, sent, body, response, resp_body))
                self._log(
                    req=preq,
                    verdict="allow",
                    code="ok",
                    tid=tid,
                    target=adm.target.id,
                    identity=adm.identity,
                    status=response.status_code,
                    evidence=evidence,
                )
                await self._send(writer, conn, *self._relay(request, response, resp_body, evidence))
            except asyncio.CancelledError:
                self._log(verdict="cut", code="revoked_in_flight", tid=tid)
                raise
            finally:
                if tid is not None:
                    self.live.get(tid, set()).discard(task)
                writer.close()
                with contextlib.suppress(Exception):
                    await writer.wait_closed()

    async def _read_request(self, conn: h11.Connection, reader: asyncio.StreamReader) -> tuple[h11.Request, bytes]:
        request, body = None, bytearray()
        while True:
            event = conn.next_event()
            if event is h11.NEED_DATA:
                conn.receive_data(await reader.read(65536))
            elif isinstance(event, h11.Request):
                request = event
                self._check_singletons(event.headers)
            elif isinstance(event, h11.Data):
                body += event.data
                if len(body) > self.max_body:
                    raise _BadRequest("request body too large")
            elif isinstance(event, h11.EndOfMessage) or event is h11.PAUSED:
                if request is None:
                    raise _BadRequest("no request")
                return request, bytes(body)
            elif isinstance(event, h11.ConnectionClosed):
                raise _BadRequest("client closed the connection")

    @staticmethod
    def _check_singletons(headers: Iterable[tuple[bytes, bytes]]) -> None:
        names = [name for name, _ in headers]
        for name in SINGLETON_REQUEST_HEADERS:
            if names.count(name) > 1:
                raise _BadRequest(f"duplicate {name.decode()} header")
        if b"content-length" in names and b"transfer-encoding" in names:
            # RFC 9112 §6.3: a likely smuggling attempt; refuse instead of picking one framing.
            raise _BadRequest("both Content-Length and Transfer-Encoding")

    @staticmethod
    def _proxy_request(request: h11.Request) -> ProxyRequest:
        headers = {name: value.decode("latin-1") for name, value in request.headers}
        return ProxyRequest(
            method=request.method.decode("ascii"),
            uri=request.target.decode("latin-1"),
            host_header=headers.get(b"host"),
            proxy_authorization=headers.get(b"proxy-authorization"),
            identity=headers.get(b"veritas-identity"),
        )

    async def _forward(
        self, adm: Admission, request: h11.Request, body: bytes, jar: dict[str, str] | None
    ) -> tuple[HeaderList, h11.Response, bytes]:
        """Send the request upstream; returns the headers actually sent, the response, and its body."""
        drop = set(HOP_BY_HOP)
        for name, value in request.headers:
            if name == b"connection":
                drop.update(token.strip().lower() for token in value.split(b","))
        if jar is not None:
            drop.add(b"cookie")  # the identity's session replaces whatever the plugin sent
        headers = [(b"host", adm.authority.encode("ascii"))]
        headers += [(n, v) for n, v in request.headers if n not in drop and not n.startswith(b"veritas-")]
        if jar:
            headers.append((b"cookie", "; ".join(f"{k}={v}" for k, v in jar.items()).encode("latin-1")))
        if body or request.method in (b"POST", b"PUT", b"PATCH"):
            headers.append((b"content-length", str(len(body)).encode()))
        headers.append((b"connection", b"close"))
        response, resp_body = await self._roundtrip(adm.target, request.method, adm.upstream_target, headers, body)
        return headers, response, resp_body

    async def _session(self, adm: Admission) -> dict[str, str] | None:
        """The identity's cookie jar, signing in on first use. Failed sign-ins are not retried."""
        identity = self.config.identity(adm.identity or "")
        if identity is None:
            return None
        lock = self._login_locks.setdefault(identity.id, asyncio.Lock())
        async with lock:
            if identity.id not in self._sessions and identity.id not in self._failed_logins:
                jar = await self._login(identity, adm.target)
                if jar is None:
                    self._failed_logins.add(identity.id)
                else:
                    self._sessions[identity.id] = jar
        return self._sessions.get(identity.id)

    async def _login(self, identity: GatewayIdentity, target: GatewayTarget) -> dict[str, str] | None:
        secret = self._secrets.get(identity.id)
        if secret is None:
            self._log(verdict="login", code="login_failed", detail="no secret", identity=identity.id, target=target.id)
            return None
        if self.state.target_counts[target.id] >= target.max_requests:
            self._log(verdict="login", code="target_budget_exhausted", identity=identity.id, target=target.id)
            return None
        self.state.target_counts[target.id] += 1
        fields = {identity.username_field: identity.username, identity.password_field: secret}
        body = urlencode(fields).encode("ascii")
        authority = authority_of(target)
        headers = [
            (b"host", authority.encode("ascii")),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"content-length", str(len(body)).encode()),
            (b"connection", b"close"),
        ]
        try:
            response, resp_body = await asyncio.wait_for(
                self._roundtrip(target, b"POST", identity.login_path, headers, body), self.upstream_timeout
            )
        except (TimeoutError, _UpstreamError) as exc:
            self._log(verdict="login", code="login_failed", detail=repr(exc), identity=identity.id, target=target.id)
            return None
        jar: dict[str, str] = {}
        _update_jar(jar, response.headers)
        ok = 200 <= response.status_code < 400 and bool(jar)
        masked = urlencode({**fields, identity.password_field: self.sink.pseudonym(secret)}).encode("ascii")
        record = {
            "v": 1,
            "ts": _iso_now(),
            "run": self.config.run,
            "kind": "login",
            "tid": None,
            "target": target.id,
            "identity": identity.id,
            "request": self._request_record("POST", authority, identity.login_path, headers, masked),
            "response": self._response_record(response, resp_body),
        }
        evidence = self.sink.exchange(record)
        self._log(verdict="login", code="ok" if ok else "login_failed", identity=identity.id, target=target.id,
                  status=response.status_code, evidence=evidence)  # fmt: skip
        return jar if ok else None

    async def _roundtrip(
        self, target: GatewayTarget, method: bytes, upstream_target: str, headers: HeaderList, body: bytes
    ) -> tuple[h11.Response, bytes]:
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        last_error: Exception | None = None
        for address in target.addresses:  # pinned at scope check; never re-resolved
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(address, target.port), self.connect_timeout
                )
                break
            except (TimeoutError, OSError) as exc:
                last_error = exc
        if reader is None or writer is None:
            raise _UpstreamError("upstream_unreachable", repr(last_error))
        try:
            client = h11.Connection(h11.CLIENT, max_incomplete_event_size=64 * 1024)
            data = client.send(h11.Request(method=method, target=upstream_target.encode("ascii"), headers=headers))
            if body:
                data += client.send(h11.Data(data=body))
            data += client.send(h11.EndOfMessage())
            writer.write(data)
            await writer.drain()
            response, resp_body = None, bytearray()
            while True:
                event = client.next_event()
                if event is h11.NEED_DATA:
                    client.receive_data(await reader.read(65536))
                elif isinstance(event, h11.Response):
                    response = event
                elif isinstance(event, h11.Data):
                    resp_body += event.data
                    if len(resp_body) > self.max_body:
                        raise _UpstreamError("response_too_large", f"over {self.max_body} bytes")
                elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
                    break
            if response is None:
                raise _UpstreamError("upstream_protocol_error", "no response")
            return response, bytes(resp_body)
        except h11.ProtocolError as exc:
            raise _UpstreamError("upstream_protocol_error", str(exc)) from None
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    # Responses -------------------------------------------------------------

    def _relay(self, request: h11.Request, response: h11.Response, body: bytes, evidence: str) -> Reply:
        bodiless = request.method == b"HEAD" or response.status_code in (204, 304)
        headers = [
            # Plugins never see cookie values: attributes stay, values become stable pseudonyms.
            (n, self.sink.mask(n, v).encode("latin-1") if n == b"set-cookie" else v)
            for n, v in response.headers
            if (n not in HOP_BY_HOP or (bodiless and n == b"content-length")) and not n.startswith(b"veritas-")
        ]
        headers.append((b"veritas-evidence", evidence.encode("ascii")))
        if not bodiless:
            headers.append((b"content-length", str(len(body)).encode()))
        headers.append((b"connection", b"close"))
        return response.status_code, headers, b"" if bodiless else body, response.reason

    @staticmethod
    def _error(status: int, code: str, detail: str = "") -> Reply:
        body = json.dumps({"error": code, "detail": detail}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"veritas-denied", code.encode()),
            (b"content-length", str(len(body)).encode()),
            (b"connection", b"close"),
        ]
        return status, headers, body, b""

    def _denial(self, denied: Denied) -> Reply:
        status, headers, body, reason = self._error(denied.status, denied.code, denied.detail)
        if denied.status == 407:
            headers.insert(0, (b"proxy-authenticate", b'Basic realm="veritas"'))
        return status, headers, body, reason

    @staticmethod
    async def _send(
        writer: asyncio.StreamWriter, conn: h11.Connection, status: int, headers: HeaderList, body: bytes, reason: bytes
    ) -> None:
        data = conn.send(h11.Response(status_code=status, headers=headers, reason=reason or b""))
        if body:
            data += conn.send(h11.Data(data=body))
        data += conn.send(h11.EndOfMessage())
        writer.write(data)
        await writer.drain()

    @staticmethod
    async def _raw(writer: asyncio.StreamWriter, status: int, code: str) -> None:
        body = json.dumps({"error": code}).encode()
        writer.write(
            b"HTTP/1.1 %d %s\r\nContent-Type: application/json\r\nVeritas-Denied: %s\r\n"
            b"Content-Length: %d\r\nConnection: close\r\n\r\n%s" % (status, b"Error", code.encode(), len(body), body)
        )
        with contextlib.suppress(Exception):
            await writer.drain()

    # Records ---------------------------------------------------------------

    def _record(
        self, adm: Admission, method: bytes, sent: HeaderList, body: bytes, response: h11.Response, resp_body: bytes
    ) -> dict[str, Any]:
        """The evidence record: what was actually sent upstream (secrets masked) and what came back."""
        return {
            "v": 1,
            "ts": _iso_now(),
            "run": self.config.run,
            "kind": "exchange",
            "tid": adm.claims.tid,
            "target": adm.target.id,
            "identity": adm.identity,
            "request": self._request_record(method.decode("ascii"), adm.authority, adm.upstream_target, sent, body),
            "response": self._response_record(response, resp_body),
        }

    def _request_record(
        self, method: str, authority: str, target: str, headers: HeaderList, body: bytes
    ) -> dict[str, Any]:
        return {
            "method": method,
            "authority": authority,
            "target": target,
            "headers": self.sink.headers(headers),
            "body_b64": base64.b64encode(body).decode("ascii"),
        }

    def _response_record(self, response: h11.Response, body: bytes) -> dict[str, Any]:
        return {
            "status": response.status_code,
            "reason": response.reason.decode("latin-1"),
            "headers": self.sink.headers(list(response.headers)),
            "body_b64": base64.b64encode(body).decode("ascii"),
        }

    def _log(
        self,
        *,
        verdict: str,
        code: str,
        req: ProxyRequest | None = None,
        detail: str = "",
        tid: str | None = None,
        target: str | None = None,
        identity: str | None = None,
        status: int | None = None,
        evidence: str | None = None,
    ) -> None:
        self.stats[(verdict, code)] += 1
        entry: dict[str, Any] = {"ts": _iso_now(), "verdict": verdict, "code": code}
        if req is not None:
            entry.update(method=req.method[:16], uri=req.uri[:2048])
        for name, value in (
            ("detail", detail),
            ("tid", tid),
            ("target", target),
            ("identity", identity),
            ("status", status),
            ("evidence", evidence),
        ):
            if value:
                entry[name] = value
        self.sink.decision(entry)
