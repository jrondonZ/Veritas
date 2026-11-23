"""In-process gateway tests: real sockets on 127.0.0.1, no Docker."""

import asyncio
import base64
import contextlib
import json
import time
from urllib.parse import parse_qsl

import h11

from veritas.core.tokens import NetGrant, TokenClaims, mint, new_run_key
from veritas.gateway.admission import GatewayConfig, GatewayIdentity, GatewayTarget
from veritas.gateway.proxy import CaptureSink, Gateway

KEY = new_run_key()


LOGINS = []  # form bodies the upstream received on /api/login


async def upstream_handler(reader, writer):
    conn = h11.Connection(h11.SERVER)
    request, request_body = None, b""
    while True:
        event = conn.next_event()
        if event is h11.NEED_DATA:
            conn.receive_data(await reader.read(65536))
        elif isinstance(event, h11.Request):
            request = event
        elif isinstance(event, h11.Data):
            request_body += event.data
        elif isinstance(event, (h11.EndOfMessage, h11.ConnectionClosed)):
            break
    path = request.target.decode()
    headers = [(b"connection", b"close")]
    if path.startswith("/api/slow"):
        await asyncio.sleep(5)
    if path == "/api/login":
        LOGINS.append(request_body)
        form = dict(parse_qsl(request_body.decode()))
        ok = form.get("password") == "pw-alice"
        status, body = (200, b"{}") if ok else (401, b"{}")
        if ok:
            headers.append((b"set-cookie", b"sid=sess-alice; Path=/"))
    elif path.startswith("/api/redirect"):
        status, body = 302, b""
        headers.append((b"location", b"http://decoy:8080/api/echo"))
    elif path.startswith("/api/forge"):
        status, body = 200, b"forged"
        headers += [(b"veritas-evidence", b"E-forged"), (b"set-cookie", b"sid=secret123; HttpOnly")]
    else:
        status = 200
        body = json.dumps(
            {
                "method": request.method.decode(),
                "target": path,
                "headers": [[n.decode(), v.decode()] for n, v in request.headers],
            }
        ).encode()
    headers.append((b"content-length", str(len(body)).encode()))
    data = conn.send(h11.Response(status_code=status, headers=headers))
    data += conn.send(h11.Data(data=body)) + conn.send(h11.EndOfMessage())
    writer.write(data)
    await writer.drain()
    writer.close()


def token(tid="t-0001", impact="probe", max_requests=50, paths=("/api/**",), methods=("GET", "HEAD"), identities=()):
    claims = TokenClaims(
        tid=tid,
        run="r-0001",
        exp=int(time.time()) + 300,
        plugin="test@0",
        impact_max=impact,
        net=[
            NetGrant(
                target="web",
                methods=list(methods),
                paths=list(paths),
                identities=list(identities),
                max_requests=max_requests,
            )
        ],
    )
    return mint(claims, KEY)


def raw_request(uri, token_value=None, tid="t-0001", method="GET", host=None, extra=b"", body=b""):
    host = host or (uri.split("/")[2] if "//" in uri else uri)
    lines = [f"{method} {uri} HTTP/1.1", f"Host: {host}"]
    if token_value is not None:
        cred = base64.b64encode(f"{tid}:{token_value}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {cred}")
    if body:
        lines.append(f"Content-Length: {len(body)}")
    return ("\r\n".join(lines) + "\r\n").encode() + extra + b"\r\n" + body


async def send(port, data):
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    writer.write(data)
    await writer.drain()
    raw = await reader.read()  # the gateway always closes after one response
    writer.close()
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1]) if lines[0] else 0
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.setdefault(name.strip().lower(), []).append(value.strip())
    return status, headers, body


@contextlib.asynccontextmanager
async def harness(tmp_path, rps=50, max_requests=1000):
    upstream = await asyncio.start_server(upstream_handler, "127.0.0.1", 0)
    up_port = upstream.sockets[0].getsockname()[1]
    config = GatewayConfig(
        run="r-0001",
        targets=[
            GatewayTarget(
                id="web",
                scheme="http",
                host="vuln-notes",
                port=up_port,
                addresses=["127.0.0.1"],
                allow_paths=["/api/**"],
                allow_methods=["GET", "HEAD", "POST"],
                rps=rps,
                concurrency=4,
                max_requests=max_requests,
            )
        ],
        identities=[
            GatewayIdentity(
                id=name,
                target="web",
                login_path="/api/login",
                username=f"{name}@lab.test",
                username_field="email",
                password_field="password",
            )
            for name in ("alice", "mallory")
        ],
    )
    sink = CaptureSink(tmp_path / "capture", mask_key=KEY)
    gateway = Gateway(config, KEY, sink, secrets={"alice": "pw-alice", "mallory": "wrong"})
    server = await gateway.serve("127.0.0.1", 0)
    gw_port = server.sockets[0].getsockname()[1]
    try:
        yield gateway, gw_port, up_port, tmp_path / "capture"
    finally:
        server.close()
        upstream.close()
        sink.close()


def test_allowed_request_is_forwarded_sanitized_and_captured(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, capture):
            extra = b"Veritas-Identity: alice\r\nCookie: sid=abc\r\nConnection: x-secret\r\nX-Secret: 1\r\n"
            tok = token(identities=["alice"])
            status, headers, body = await send(
                port, raw_request(f"http://vuln-notes:{up}/api/echo?q=1", tok, extra=extra)
            )
            return status, headers, json.loads(body), capture

    status, headers, seen, capture = asyncio.run(main())
    assert status == 200
    sent = dict(seen["headers"])
    assert seen["target"] == "/api/echo?q=1"
    assert sent["host"].startswith("vuln-notes:")
    assert "proxy-authorization" not in sent
    assert "veritas-identity" not in sent
    assert "x-secret" not in sent
    evidence = headers["veritas-evidence"][0]
    record = json.loads((capture / f"{evidence}.json").read_text(encoding="utf-8"))
    cookie = dict(record["request"]["headers"])["cookie"]
    assert "abc" not in cookie
    assert cookie.startswith("sid=<masked:")


def test_denials_are_answered_and_logged(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, capture):
            results = {
                "no_token": await send(port, raw_request(f"http://vuln-notes:{up}/api/echo")),
                "out_of_scope": await send(port, raw_request(f"http://decoy:{up}/api/echo", token())),
                "ip_literal": await send(port, raw_request(f"http://127.0.0.1:{up}/api/echo", token())),
                "connect": await send(port, raw_request(f"vuln-notes:{up}", token(), method="CONNECT")),
                "post_with_probe_token": await send(
                    port, raw_request(f"http://vuln-notes:{up}/api/echo", token(), method="POST", body=b"x")
                ),
                "smuggling": await send(
                    port,
                    raw_request(
                        f"http://vuln-notes:{up}/api/echo", token(), body=b"0", extra=b"Transfer-Encoding: chunked\r\n"
                    ),
                ),
                "duplicate_host": await send(
                    port,
                    raw_request(f"http://vuln-notes:{up}/api/echo", token(), extra=f"Host: decoy:{up}\r\n".encode()),
                ),
            }
            log = (capture / "decisions.jsonl").read_text(encoding="utf-8")
            return results, log

    results, log = asyncio.run(main())
    expected = {
        "no_token": (407, "auth_required"),
        "out_of_scope": (403, "out_of_scope"),
        "ip_literal": (403, "out_of_scope"),
        "connect": (405, "connect_unsupported"),
        "post_with_probe_token": (403, "impact_exceeds_token"),
        "smuggling": (400, "bad_request"),
        "duplicate_host": (400, "bad_request"),
    }
    for name, (status, code) in expected.items():
        got_status, headers, _ = results[name]
        assert (got_status, headers.get("veritas-denied", [None])[0]) == (status, code), name
        assert f'"code":"{code}"' in log


def test_redirect_out_of_scope_is_refused_on_the_next_hop(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, _capture):
            first = await send(port, raw_request(f"http://vuln-notes:{up}/api/redirect", token()))
            location = first[1]["location"][0]
            second = await send(port, raw_request(location, token()))
            return first, second

    first, second = asyncio.run(main())
    assert first[0] == 302
    assert (second[0], second[1]["veritas-denied"][0]) == (403, "out_of_scope")


def test_forged_evidence_header_is_replaced(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, _capture):
            return await send(port, raw_request(f"http://vuln-notes:{up}/api/forge", token()))

    status, headers, _ = asyncio.run(main())
    assert status == 200
    assert headers["veritas-evidence"] != ["E-forged"]
    assert len(headers["veritas-evidence"]) == 1


def test_revocation_cuts_in_flight_request_within_one_second(tmp_path):
    async def main():
        async with harness(tmp_path) as (gw, port, up, _capture):
            tok = token()
            slow = asyncio.create_task(send(port, raw_request(f"http://vuln-notes:{up}/api/slow", tok)))
            deadline = time.monotonic() + 3
            while not gw.live.get("t-0001") and time.monotonic() < deadline:
                await asyncio.sleep(0.02)
            started = time.monotonic()
            assert gw.revoke("t-0001") == 1
            status, _, _ = await slow
            elapsed = time.monotonic() - started
            after = await send(port, raw_request(f"http://vuln-notes:{up}/api/echo", tok))
            return status, elapsed, after

    status, elapsed, after = asyncio.run(main())
    assert status != 200
    assert elapsed < 1.0, elapsed
    assert (after[0], after[1]["veritas-denied"][0]) == (407, "revoked")


def test_rate_limit_spaces_requests(tmp_path):
    async def main():
        async with harness(tmp_path, rps=5) as (_gw, port, up, _capture):
            tok = token()
            started = time.monotonic()
            for _ in range(3):
                assert (await send(port, raw_request(f"http://vuln-notes:{up}/api/echo", tok)))[0] == 200
            return time.monotonic() - started

    assert asyncio.run(main()) >= 0.35


def test_task_budget_returns_429(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, _capture):
            tok = token(max_requests=2)
            return [(await send(port, raw_request(f"http://vuln-notes:{up}/api/echo", tok)))[0] for _ in range(3)]

    assert asyncio.run(main()) == [200, 200, 429]


def test_identity_session_is_injected_and_its_login_captured_without_the_password(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, capture):
            tok = token(identities=["alice"])
            extra = b"Veritas-Identity: alice\r\nCookie: sid=plugin-chosen\r\n"
            first = await send(port, raw_request(f"http://vuln-notes:{up}/api/echo", tok, extra=extra))
            second = await send(port, raw_request(f"http://vuln-notes:{up}/api/echo", tok, extra=extra))
            files = {p.name: p.read_text(encoding="utf-8") for p in capture.iterdir()}
            return first, second, files

    LOGINS.clear()
    first, second, files = asyncio.run(main())
    for status, _, body in (first, second):
        assert status == 200
        assert dict(json.loads(body)["headers"])["cookie"] == "sid=sess-alice"  # the jar, not the plugin's cookie
    assert len(LOGINS) == 1  # one sign-in serves the whole run
    assert not any("pw-alice" in text for text in files.values())
    logins = [json.loads(t) for name, t in files.items() if name.startswith("E-") and '"kind":"login"' in t]
    assert len(logins) == 1
    assert logins[0]["identity"] == "alice"
    assert '"code":"ok"' in files["decisions.jsonl"]


def test_set_cookie_values_are_masked_for_plugins(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, _capture):
            return await send(port, raw_request(f"http://vuln-notes:{up}/api/forge", token()))

    _, headers, _ = asyncio.run(main())
    (cookie,) = headers["set-cookie"]
    assert "secret123" not in cookie
    assert cookie.startswith("sid=<masked:")
    assert cookie.endswith("; HttpOnly")


def test_failed_login_is_reported_and_not_retried(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, _capture):
            tok = token(identities=["mallory"])
            extra = b"Veritas-Identity: mallory\r\n"
            return [await send(port, raw_request(f"http://vuln-notes:{up}/api/echo", tok, extra=extra)) for _ in "ab"]

    LOGINS.clear()
    results = asyncio.run(main())
    assert [(s, h["veritas-denied"][0]) for s, h, _ in results] == [(502, "identity_login_failed")] * 2
    assert len(LOGINS) == 1


def test_identity_unknown_to_the_gateway_is_refused(tmp_path):
    async def main():
        async with harness(tmp_path) as (_gw, port, up, _capture):
            tok = token(identities=["eve"])
            return await send(
                port, raw_request(f"http://vuln-notes:{up}/api/echo", tok, extra=b"Veritas-Identity: eve\r\n")
            )

    status, headers, _ = asyncio.run(main())
    assert (status, headers["veritas-denied"][0]) == (403, "unknown_identity")
