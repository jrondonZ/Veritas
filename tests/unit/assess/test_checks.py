"""Oracle tests: every check's pass, fail, and ambiguous cases over synthetic exchanges and sensor records."""

import json

from veritas.assess.checks import PlanContext, run_oracle
from veritas.assess.checks.app_activity import CommandFromInput, PathFromInput, RequestFromInput
from veritas.assess.checks.cookie_attributes import CookieAttributes
from veritas.assess.checks.cors import CrossOriginReads
from veritas.assess.checks.csrf import CrossSiteRequestForgery
from veritas.assess.checks.error_disclosure import ErrorDisclosure
from veritas.assess.checks.headers import (
    ContentSecurityPolicy,
    ContentTypeOptions,
    FramingProtection,
    ServerBanner,
    StrictTransportSecurity,
)
from veritas.assess.checks.mass_assignment import MassAssignment
from veritas.assess.checks.object_authz import ObjectAuthorization
from veritas.assess.checks.open_redirect import OpenRedirect
from veritas.assess.checks.reflected_html import ReflectedHtml
from veritas.assess.checks.sql_string_built import StringBuiltQuery
from veritas.assess.evidence import SensorRecord
from veritas.assess.probes import Probe
from veritas.assess.recon import Fetched, ReconResult, Route
from veritas.core.canonical import sha256_hex

HTML = [("Content-Type", "text/html; charset=utf-8")]


def probe(check, route="GET /x", **params):
    return Probe(check.id, ("k",), route, "d", params=params)


def sensor_record(*entries, markers=("vrt-mk-q-1",), truncated=False, malformed=0):
    reply = {"entries": list(entries), "truncated": truncated, "malformed": malformed}
    data = SensorRecord.encode("veritas.sensor.query-log@0.0.1", "sha256:image", "queries", markers, reply)
    return SensorRecord.from_bytes("E-" + sha256_hex(data)[:12], data)


def test_object_authz(exchange):
    check = ObjectAuthorization()
    p = probe(check, owner="bob", reader="alice", owner_canary="vrt-seed-bob", path="/api/notes/4")
    owner = exchange(body='{"body": "vrt-seed-bob-1"}')
    result = check.evaluate(p, [owner, exchange(body='{"body": "vrt-seed-bob-1"}')], 1)
    assert result.verdict == "pass"
    assert "owned by bob" in result.observed[0].text
    assert check.evaluate(p, [owner, exchange(status=404, body="{}")], 1).verdict == "fail"
    assert check.evaluate(p, [exchange(status=401), exchange()], 1).verdict == "ambiguous"
    borrowed = probe(check, owner="bob", reader="alice", owner_canary="vrt-seed-bob", id_source="/api/notes")
    unknown_id = check.evaluate(borrowed, [exchange(status=404), exchange()], 1)
    assert (unknown_id.verdict, unknown_id.reason) == (
        "ambiguous",
        "bob's own request did not return bob's canary; the id came from GET /api/notes",
    )


def test_sql_string_built(exchange):
    check = StringBuiltQuery()
    p = probe(check, route="GET /api/search", canary="vrt-mk-q", param="q", path="/api/search", identity="alice")
    sent = exchange(path="/api/search?q=vrt-mk-q-1")
    concatenated = sensor_record({"sql": "SELECT id FROM notes WHERE title LIKE '%vrt-mk-q-1%'", "params": []})
    hit = check.evaluate_signals(p, [sent], [concatenated], 1)
    assert (hit.verdict, hit.reason) == ("pass", "the canary appeared inside SQL statement text")
    assert [o.evidence for o in hit.observed] == [(sent.id,), (concatenated.id,)]
    assert run_oracle(check, p, [sent], [concatenated], 1) == hit
    assert check.evaluate(p, [sent], 1).verdict == "error"  # without the sensor's records it cannot decide

    bound = sensor_record({"sql": "SELECT id FROM notes WHERE title LIKE ?", "params": ["%vrt-mk-q-1%"]})
    assert check.evaluate_signals(p, [sent], [bound], 1).reason == "the canary was bound as a query parameter"
    unused = check.evaluate_signals(p, [sent], [sensor_record()], 1)
    assert (unused.verdict, unused.reason) == ("fail", "no logged SQL statement used the parameter")
    assert check.evaluate_signals(p, [sent], [sensor_record(truncated=True)], 1).verdict == "ambiguous"
    assert check.evaluate_signals(p, [exchange(status=401)], [sensor_record()], 1).verdict == "ambiguous"
    # each attempt has its own canary, so an entry left over from attempt 1 cannot decide attempt 2
    assert check.evaluate_signals(p, [sent], [concatenated], 2).reason == "no logged SQL statement used the parameter"


def test_reflected_html(exchange):
    check = ReflectedHtml()
    p = probe(check, marker="vrt-mk-abc", param="q")
    hit = check.evaluate(p, [exchange(body="<p>Results for: <vrt-mk-abc></p>", headers=HTML)], 1)
    assert hit.verdict == "pass"
    assert any("Content-Security-Policy" in o.text for o in hit.observed)
    encoded = check.evaluate(p, [exchange(body="<p>&lt;vrt-mk-abc&gt;</p>", headers=HTML)], 1)
    assert (encoded.verdict, encoded.reason) == ("fail", "the marker was HTML-encoded")
    for container in ("textarea", "title", "script"):
        body = f"<{container}><vrt-mk-abc></{container}>"
        assert check.evaluate(p, [exchange(body=body, headers=HTML)], 1).verdict == "ambiguous", container
    as_json = check.evaluate(p, [exchange(body="<vrt-mk-abc>", headers=[("Content-Type", "application/json")])], 1)
    assert as_json.verdict == "fail"


def test_error_disclosure(exchange):
    check = ErrorDisclosure()
    p = probe(check, route="POST /api/notes")
    trace = "SyntaxError: bad\n    at JSON.parse (<anonymous>)\n    at parseInput (file:///app/server.mjs:52:15)"
    assert check.evaluate(p, [exchange(status=500, body=trace), exchange(status=500, body=trace)], 1).verdict == "pass"
    varying = [exchange(status=500, body='{"ref": "a"}'), exchange(status=500, body='{"ref": "b"}')]
    assert check.evaluate(p, varying, 1).reason == "500 bodies vary with input but match no error signature"
    assert check.evaluate(p, [exchange(status=400), exchange(status=400)], 1).verdict == "fail"
    same = [exchange(status=500, body="oops"), exchange(status=500, body="oops")]
    assert check.evaluate(p, same, 1).verdict == "fail"


def test_csrf(exchange):
    check = CrossSiteRequestForgery()
    p = probe(check, route="POST /api/notes", victim="alice")
    assert check.evaluate(p, [exchange(status=201)], 1).verdict == "pass"
    assert check.evaluate(p, [exchange(status=403)], 1).verdict == "fail"


def test_mass_assignment(exchange):
    check = MassAssignment()
    p = probe(check, field="role", sentinel="vrt-mk-s", method="PUT", path="/api/profile", actor="alice")

    def profile(role):
        return exchange(body=json.dumps({"role": role}))

    assert check.evaluate(p, [profile("user"), exchange(), profile("vrt-mk-s-1")], 1).verdict == "pass"
    assert check.evaluate(p, [profile("user"), exchange(), profile("user")], 1).verdict == "fail"
    assert check.evaluate(p, [profile("user"), exchange(status=400), profile("user")], 1).verdict == "fail"
    assert check.evaluate(p, [profile("vrt-mk-s-2"), exchange(), profile("vrt-mk-s-2")], 2).verdict == "ambiguous"
    assert [s.body for s in check.steps_for(p, 3) if s.body] == ['{"role": "vrt-mk-s-3"}']


def test_cookie_attributes(exchange):
    check = CookieAttributes()
    p = probe(check, route="POST /api/login")
    weak = check.evaluate(p, [exchange(headers=[("Set-Cookie", "sid=<masked:1>; Path=/")])], 1)
    assert weak.verdict == "pass"
    assert weak.observed[0].text == "The sid cookie set by POST /api/login lacks HttpOnly and SameSite."
    strong = [exchange(headers=[("Set-Cookie", "sid=<masked:1>; Path=/; HttpOnly; SameSite=Lax")])]
    assert check.evaluate(p, strong, 1).verdict == "fail"
    lax_none = [exchange(headers=[("Set-Cookie", "sid=x; HttpOnly; SameSite=None")])]
    assert check.evaluate(p, lax_none, 1).verdict == "pass"


def activity_record(*entries, markers=("vrt-mk-a-1",)):
    reply = {"entries": list(entries), "truncated": False, "malformed": 0}
    data = SensorRecord.encode("veritas.sensor.activity-log@0.0.1", "sha256:image", "activity", markers, reply)
    return SensorRecord.from_bytes("E-" + sha256_hex(data)[:12], data)


def activity_probe(check, route="GET /api/x"):
    return probe(check, route=route, canary="vrt-mk-a", param="name", path=route.split(" ")[1], identity="alice")


def test_path_from_input(exchange):
    check = PathFromInput()
    p = activity_probe(check, "GET /api/export")
    assert check.steps_for(p, 1)[0].path == "/api/export?name=vrt-mk-a-1%2Fvrt-mk-a-1"  # two segments, no "../"
    sent = exchange()
    opened = activity_record({"kind": "file", "op": "read", "path": "/data/exports/vrt-mk-a-1/vrt-mk-a-1"})
    kept = check.evaluate_signals(p, [sent], [opened], 1)
    assert (kept.verdict, kept.reason) == ("pass", "a file path the app opened kept the canary's slash")
    assert "path traversal is likely; it was not attempted" in kept.inferred[0]
    flattened = activity_record({"kind": "file", "op": "read", "path": "/data/exports/vrt-mk-a-1"})
    assert (
        check.evaluate_signals(p, [sent], [flattened], 1).reason == "the canary reached a file path only as a file name"
    )
    elsewhere = activity_record({"kind": "request", "method": "GET", "url": "http://x/vrt-mk-a-1/vrt-mk-a-1"})
    assert (
        check.evaluate_signals(p, [sent], [elsewhere], 1).reason
        == "the app used the canary only in other activity (request)"
    )
    assert check.evaluate_signals(p, [sent], [activity_record()], 1).verdict == "fail"
    assert check.evaluate_signals(p, [exchange(status=500)], [activity_record()], 1).verdict == "ambiguous"
    assert check.evaluate_signals(p, [exchange(status=302)], [activity_record()], 1).verdict == "fail"  # handled


def test_command_from_input(exchange):
    check = CommandFromInput()
    p = activity_probe(check, "GET /api/thumbnail")
    assert check.steps_for(p, 1)[0].path == "/api/thumbnail?name=vrt-mk-a-1"
    shell = activity_record({"kind": "exec", "shell": True, "command": "convert /data/vrt-mk-a-1 x.png"})
    assert (
        check.evaluate_signals(p, [exchange()], [shell], 1).reason == "the canary appeared inside a shell command line"
    )
    program = activity_record({"kind": "exec", "shell": False, "file": "/opt/vrt-mk-a-1", "args": []})
    assert check.evaluate_signals(p, [exchange()], [program], 1).reason == "the canary chose which program the app ran"
    argv = activity_record({"kind": "exec", "shell": False, "file": "convert", "args": ["/data/vrt-mk-a-1", "x.png"]})
    assert check.evaluate_signals(p, [exchange()], [argv], 1).verdict == "fail"


def test_request_from_input(exchange):
    check = RequestFromInput()
    p = activity_probe(check, "GET /api/preview")
    assert check.steps_for(p, 2)[0].path == "/api/preview?name=http%3A%2F%2Fvrt-mk-a-2.invalid%2F"
    chosen = activity_record({"kind": "request", "method": "GET", "url": "http://vrt-mk-a-1.invalid/"})
    assert check.evaluate_signals(p, [exchange()], [chosen], 1).reason == "the app tried to reach the canary's host"
    fixed = activity_record(
        {"kind": "request", "method": "GET", "url": "https://api.test/q?u=http://vrt-mk-a-1.invalid/"}
    )
    assert check.evaluate_signals(p, [exchange()], [fixed], 1).verdict == "fail"


def test_activity_checks_plan_only_with_an_activity_sensor(target, identities):
    recon = ReconResult(routes=[Route("GET", "/api/export", query_params=("name",), auth=True)])
    without = PlanContext(target=target, identities=identities, tag="test")
    sensed = PlanContext(target=target, identities=identities, tag="test", sensors=frozenset({"activity-log"}))
    for check in (PathFromInput(), CommandFromInput(), RequestFromInput()):
        assert check.plan(recon, without) == []
        (planned,) = check.plan(recon, sensed)
        assert (planned.route, planned.steps[0].identity) == ("GET /api/export", "alice")
        assert check.markers(planned, 2) == (f"{planned.params['canary']}-2",)


def test_open_redirect(exchange):
    check = OpenRedirect()
    p = probe(check, route="GET /go", host="vrt-mk-r.invalid", param="next")
    away = check.evaluate(p, [exchange(status=302, headers=[("Location", "http://vrt-mk-r.invalid/")])], 1)
    assert away.verdict == "pass"
    assert "Location: http://vrt-mk-r.invalid/" in away.observed[0].text
    scheme_relative = [exchange(status=302, headers=[("Location", "//vrt-mk-r.invalid/x")])]
    assert check.evaluate(p, scheme_relative, 1).verdict == "pass"
    assert (
        check.evaluate(p, [exchange(status=302, headers=[("Location", "/")])], 1).reason
        == "the redirect stayed on the site"
    )
    assert check.evaluate(p, [exchange(status=302, headers=[("Location", "http://other.test/")])], 1).verdict == "fail"
    assert check.evaluate(p, [exchange(status=200)], 1).reason == "the response was 200, not a redirect"
    assert check.evaluate(p, [exchange(status=302, headers=[("Location", "http://[::1")])], 1).verdict == "ambiguous"


def test_open_redirect_plans_only_destination_parameters(target, identities):
    routes = [
        Route("GET", "/go", query_params=("next",)),
        Route("GET", "/search", query_params=("q",)),
        Route("GET", "/a/{id}", path_params=("id",), query_params=("url",)),
    ]
    recon = ReconResult(routes=routes)
    ctx = PlanContext(target=target, identities=identities, tag="test")
    (planned,) = OpenRedirect().plan(recon, ctx)
    assert planned.route == "GET /go"
    assert planned.steps[0].path == f"/go?next=http%3A%2F%2F{planned.params['host']}%2F"
    assert planned.params["host"].endswith(".invalid")


def test_cors(exchange):
    check = CrossOriginReads()
    p = probe(check, route="GET /api/profile", origin="http://vrt-mk-o.invalid", reader="alice")

    def answer(origin=None, credentials="true", status=200):
        headers = [("Access-Control-Allow-Origin", origin)] if origin else []
        return exchange(status=status, headers=[*headers, ("Access-Control-Allow-Credentials", credentials)])

    echoed = check.evaluate(p, [answer("http://vrt-mk-o.invalid"), answer()], 1)
    assert echoed.verdict == "pass"
    assert "Access-Control-Allow-Origin: http://vrt-mk-o.invalid" in echoed.observed[0].text
    assert check.evaluate(p, [answer(), answer("null")], 1).verdict == "pass"  # trusting null is enough
    assert check.evaluate(p, [answer("*"), answer("*")], 1).verdict == "fail"  # browsers refuse * with credentials
    assert check.evaluate(p, [answer("http://vrt-mk-o.invalid", "false"), answer()], 1).verdict == "fail"
    assert check.evaluate(p, [answer("http://vuln-notes:8080"), answer()], 1).verdict == "fail"  # an allowlist
    assert check.evaluate(p, [answer("http://vrt-mk-o.invalid", status=401), answer()], 1).verdict == "fail"


def test_cors_sends_a_foreign_origin_then_null(target, identities):
    recon = ReconResult(routes=[Route("GET", "/api/profile", auth=True), Route("GET", "/public"),
                                Route("GET", "/api/notes/{id}", path_params=("id",), auth=True)])  # fmt: skip
    (planned,) = CrossOriginReads().plan(recon, PlanContext(target=target, identities=identities, tag="test"))
    origins = [dict(s.headers)["Origin"] for s in planned.steps]
    assert origins == [planned.params["origin"], "null"]
    assert origins[0].startswith("http://vrt-mk-")
    assert origins[0].endswith(".invalid")
    assert {s.identity for s in planned.steps} == {"alice"}


def test_page_header_checks(exchange):
    csp, framing = ContentSecurityPolicy(), FramingProtection()
    p = probe(csp, route="GET /")
    bare = exchange(headers=HTML, body="<p>hi</p>")
    assert csp.evaluate(p, [bare], 1).verdict == "pass"
    assert framing.evaluate(p, [bare], 1).verdict == "pass"
    policy = exchange(headers=[*HTML, ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")])
    assert csp.evaluate(p, [policy], 1).verdict == "fail"
    assert framing.evaluate(p, [policy], 1).verdict == "fail"
    meta = exchange(headers=HTML, body='<meta http-equiv="Content-Security-Policy" content="default-src \'self\'">')
    assert csp.evaluate(p, [meta], 1).reason == "the page sets a Content-Security-Policy in a meta tag"
    report_only = exchange(headers=[*HTML, ("Content-Security-Policy-Report-Only", "default-src 'self'")])
    assert "report-only" in csp.evaluate(p, [report_only], 1).observed[0].text
    assert framing.evaluate(p, [exchange(headers=[*HTML, ("X-Frame-Options", "DENY")])], 1).verdict == "fail"
    allow_from = exchange(headers=[*HTML, ("X-Frame-Options", "ALLOW-FROM https://x.test")])  # obsolete, unsupported
    assert framing.evaluate(p, [allow_from], 1).verdict == "pass"


def test_site_header_checks(exchange):
    nosniff, hsts, banner = ContentTypeOptions(), StrictTransportSecurity(), ServerBanner()
    p = probe(nosniff, route="GET /")
    assert nosniff.evaluate(p, [exchange()], 1).verdict == "pass"
    assert nosniff.evaluate(p, [exchange(headers=[("X-Content-Type-Options", "nosniff")])], 1).verdict == "fail"
    assert hsts.evaluate(p, [exchange(headers=[("Strict-Transport-Security", "max-age=0")])], 1).verdict == "pass"
    assert (
        hsts.evaluate(p, [exchange(headers=[("Strict-Transport-Security", "max-age=31536000")])], 1).verdict == "fail"
    )
    named = banner.evaluate(p, [exchange(headers=[("Server", "nginx/1.25.3"), ("X-Powered-By", "Express<script>")])], 1)
    expected = "The response to GET / names its software: Server: nginx/1.25.3; X-Powered-By: Expressscript."
    assert named.observed[0].text == expected
    unversioned = banner.evaluate(p, [exchange(headers=[("Server", "nginx")])], 1)
    assert unversioned.verdict == "fail"  # no version, and no X-Powered-By


def test_header_checks_judge_what_recon_fetched(target, identities):
    fetched = [
        Fetched("E-000000000001", "/", 200, "text/html"),
        Fetched("E-000000000002", "/openapi.json", 200, "application/json"),
        Fetched("E-000000000003", "/search", 200, "text/html"),
        Fetched("E-000000000004", "/gone", 404, "text/html"),
    ]
    recon = ReconResult(fetched=fetched)
    ctx = PlanContext(target=target, identities=identities, tag="test")
    assert [(p.route, p.evidence, p.passive) for p in ContentSecurityPolicy().plan(recon, ctx)] == [
        ("GET /", ("E-000000000001",), True), ("GET /search", ("E-000000000003",), True),
    ]  # fmt: skip
    assert [(p.route, p.evidence) for p in ContentTypeOptions().plan(recon, ctx)] == [("GET /", ("E-000000000001",))]
    assert StrictTransportSecurity().plan(recon, ctx) == []  # the target is served over http
    https = PlanContext(target=target.model_copy(update={"base_url": "https://vuln-notes:8443"}), identities=identities,
                        tag="test")  # fmt: skip
    assert [p.route for p in StrictTransportSecurity().plan(recon, https)] == ["GET /"]
