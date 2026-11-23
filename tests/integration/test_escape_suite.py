"""Phase 0 escape suite: a hostile plugin inside a real sandbox must not get out.

Needs a Docker engine (run: pytest -m docker). Images are rebuilt from the current
source once per session by the `images` fixture.
"""

import asyncio
import base64
import secrets
import time

import pytest

from veritas.core.tokens import NetGrant, TokenClaims, mint, new_run_key
from veritas.gateway.admission import GatewayConfig, GatewayTarget
from veritas.plugins.host import start_plugin
from veritas.plugins.manifest import load_manifest
from veritas.sandbox import (
    GATEWAY_IMAGE,
    HARDENING,
    LABEL,
    NO_EXTERNAL_DNS,
    SELFTEST_IMAGE,
    RunSandbox,
    container_ip,
    docker,
    remove_labeled,
)
from veritas.store import Workspace, ingest_gateway_capture

pytestmark = pytest.mark.docker
PATHS = ["/echo", "/slow", "/redirect", "/forge", "/admin/**"]


def start_echo(rid, image, network, name, alias=None):
    args = [
        "run",
        "-d",
        "--name",
        f"vrt-{rid}-{name}",
        "--label",
        f"{LABEL}={rid}",
        "--network",
        network,
        *HARDENING,
        *NO_EXTERNAL_DNS,
        "-e",
        f"SERVER_NAME={name}",
    ]
    if alias:
        args += ["--network-alias", alias]
    docker(*args, image, "serve")
    return container_ip(f"vrt-{rid}-{name}", network)


def grant_token(key, rid, tid, max_requests):
    claims = TokenClaims(
        tid=tid,
        run=rid,
        exp=int(time.time()) + 600,
        plugin="veritas.selftest@0.0.1",
        impact_max="probe",
        net=[NetGrant(target="web", methods=["GET", "HEAD"], paths=PATHS, max_requests=max_requests)],
    )
    return mint(claims, key)


async def suite(tmp_path, images, selftest_dir):
    gw_image, st_image = images[GATEWAY_IMAGE], images[SELFTEST_IMAGE]
    manifest = load_manifest(selftest_dir / "veritas-plugin.yaml")
    rid = "st" + secrets.token_hex(4)
    ws = Workspace(tmp_path)
    run = ws.create_run("selftest", None)
    sandbox = None
    try:
        target_net = f"vrt-{rid}-tgt"
        docker("network", "create", "--internal", "--label", f"{LABEL}={rid}", target_net)
        target_ip = start_echo(rid, st_image, target_net, "target")
        # The decoy answers to the target's hostname in Docker DNS: pinning must ignore DNS.
        decoy_ip = start_echo(rid, st_image, target_net, "decoy", alias="app.lab")
        config = GatewayConfig(
            run=rid,
            targets=[
                GatewayTarget(
                    id="web",
                    scheme="http",
                    host="app.lab",
                    port=8080,
                    addresses=[target_ip],
                    allow_paths=PATHS,
                    allow_methods=["GET", "HEAD", "POST"],
                    deny_paths=["/admin/**"],
                    rps=20,
                    concurrency=4,
                    max_requests=500,
                )
            ],
        )
        key = new_run_key()
        sandbox = RunSandbox(rid, run.dir, gw_image, config, key, target_networks=[target_net])
        sandbox.up()

        token = grant_token(key, rid, "t-0001", max_requests=40)
        auth = base64.b64encode(f"t-0001:{token}".encode()).decode()
        session = await start_plugin(
            sandbox.plugin_argv(st_image, manifest, "t-0001"), manifest, env=sandbox.plugin_env("t-0001", token)
        )
        named = {
            "pinned_target": {"kind": "proxy", "uri": "http://app.lab:8080/echo"},
            "direct_tcp_target": {"kind": "tcp", "host": target_ip, "port": 8080},
            "direct_tcp_decoy": {"kind": "tcp", "host": decoy_ip, "port": 8080},
            "gateway_other_port": {"kind": "tcp", "host": sandbox.gateway_ip, "port": 8081},
            "dns_external": {"kind": "dns", "name": "example.com"},
            "dns_target_name": {"kind": "dns", "name": "app.lab"},
            "decoy_by_name": {"kind": "proxy", "uri": "http://decoy:8080/echo"},
            "decoy_by_ip": {"kind": "proxy", "uri": f"http://{decoy_ip}:8080/echo"},
            "target_by_ip": {"kind": "proxy", "uri": f"http://{target_ip}:8080/echo"},
            "mapped_ipv6": {"kind": "proxy", "uri": f"http://[::ffff:{decoy_ip}]:8080/echo"},
            "redirect": {"kind": "proxy", "uri": "http://app.lab:8080/redirect?to=http://decoy:8080/echo"},
            "host_header_swap": {"kind": "proxy", "uri": "http://app.lab:8080/echo", "headers": {"Host": "decoy:8080"}},
            "post_with_probe_token": {"kind": "proxy", "method": "POST", "uri": "http://app.lab:8080/echo"},
            "denied_path": {"kind": "proxy", "uri": "http://app.lab:8080/admin/users"},
            "encoded_bypass": {"kind": "proxy", "uri": "http://app.lab:8080/%61dmin/users"},
            "traversal": {"kind": "proxy", "uri": "http://app.lab:8080/echo/../admin/users"},
            "no_token": {"kind": "proxy", "uri": "http://app.lab:8080/echo", "auth": "none"},
            "forged_token": {"kind": "proxy", "uri": "http://app.lab:8080/echo", "auth": "forged"},
            "forged_evidence": {"kind": "proxy", "uri": "http://app.lab:8080/forge"},
            "connect_tunnel": {
                "kind": "raw",
                "data": f"CONNECT app.lab:8080 HTTP/1.1\r\nHost: app.lab:8080\r\n"
                f"Proxy-Authorization: Basic {auth}\r\n\r\n",
            },
            "write_root_fs": {"kind": "write", "path": "/etc/veritas-selftest"},
            "write_work_dir": {"kind": "write", "path": "/work/ok.txt"},
        }
        results = (await session.call("attempt", {"actions": list(named.values())}))["results"]
        got = dict(zip(named, results, strict=True))
        followed = (
            await session.call("attempt", {"actions": [{"kind": "proxy", "uri": got["redirect"]["location"]}]})
        )["results"][0]

        # Revocation while a request is in flight (the target holds /slow?s=20 for 20 s).
        slow = asyncio.create_task(
            session.call(
                "attempt", {"actions": [{"kind": "proxy", "uri": "http://app.lab:8080/slow?s=20"}]}, timeout=60
            )
        )
        await asyncio.sleep(2.0)
        started = time.monotonic()
        revoke_reply = await asyncio.to_thread(sandbox.revoke, "t-0001")
        revoke_seconds = time.monotonic() - started
        slow_result = (await slow)["results"][0]
        after_revoke = (
            await session.call("attempt", {"actions": [{"kind": "proxy", "uri": "http://app.lab:8080/echo"}]})
        )["results"][0]
        report = await session.close()

        # A second task with a two-request envelope.
        token2 = grant_token(key, rid, "t-0002", max_requests=2)
        session2 = await start_plugin(
            sandbox.plugin_argv(st_image, manifest, "t-0002"), manifest, env=sandbox.plugin_env("t-0002", token2)
        )
        budget = (
            await session2.call("attempt", {"actions": [{"kind": "proxy", "uri": "http://app.lab:8080/echo"}] * 3})
        )["results"]
        await session2.close()

        ingested = ingest_gateway_capture(ws, run, sandbox.capture_dir)
        audit = ws.verify_run(run.id)
        return got, followed, revoke_reply, revoke_seconds, slow_result, after_revoke, report, budget, ingested, audit
    finally:
        leftovers = sandbox.down() if sandbox else remove_labeled(rid)
        ws.close()
        assert leftovers == [], f"resources left behind: {leftovers}"


def test_escape_suite(tmp_path, images, selftest_dir):
    outcome = asyncio.run(suite(tmp_path, images, selftest_dir))
    got, followed, revoke_reply, revoke_seconds, slow, after, report, budget, ingested, audit = outcome

    def denied(name, status, code):
        assert (got[name].get("status"), got[name].get("denied")) == (status, code), (name, got[name])

    # Pinning: the request reached the pinned target even though DNS names the decoy.
    assert got["pinned_target"]["status"] == 200
    assert got["pinned_target"]["server"] == "target"
    assert got["pinned_target"]["evidence"].startswith("E-")
    # Network: no route from the sandbox to anything but the gateway's proxy port; no DNS.
    for name in ("direct_tcp_target", "direct_tcp_decoy", "gateway_other_port"):
        assert got[name]["connected"] is False, (name, got[name])
    for name in ("dns_external", "dns_target_name"):
        assert got[name]["resolved"] is False, (name, got[name])
    # Gateway rules.
    for name in ("decoy_by_name", "decoy_by_ip", "target_by_ip", "mapped_ipv6"):
        denied(name, 403, "out_of_scope")
    assert got["redirect"]["status"] == 302
    assert (followed["status"], followed["denied"]) == (403, "out_of_scope")
    denied("host_header_swap", 400, "host_mismatch")
    denied("post_with_probe_token", 403, "impact_exceeds_token")
    denied("denied_path", 403, "path_denied")
    denied("encoded_bypass", 403, "path_denied")
    denied("traversal", 400, "path_ambiguous")
    denied("no_token", 407, "auth_required")
    denied("forged_token", 407, "auth_invalid")
    denied("connect_tunnel", 405, "connect_unsupported")
    assert got["forged_evidence"]["status"] == 200
    assert got["forged_evidence"]["evidence"] != "E-forged"
    # Filesystem: read-only root, writable scratch.
    assert got["write_root_fs"]["written"] is False
    assert got["write_work_dir"]["written"] is True
    # Revocation cut the in-flight request within 1 s, long before the target's 20 s delay,
    # and the token is refused afterwards.
    print(f"\nrevocation round trip: {revoke_seconds:.3f}s; in-flight request ended after {slow.get('elapsed_ms')} ms")
    assert revoke_reply == {"ok": True, "cut": 1}, revoke_reply
    assert revoke_seconds < 1.0, revoke_seconds
    assert slow["status"] != 200, slow
    assert slow["elapsed_ms"] < 15000, slow
    assert (after["status"], after["denied"]) == (407, "revoked")
    # Envelope overrun.
    assert [r["status"] for r in budget] == [200, 200, 429]
    # Everything was recorded, and the record verifies.
    assert report.violations == []
    assert ingested.decisions >= len(got)
    assert ingested.exchanges >= 3
    assert audit.ok, audit.problems
