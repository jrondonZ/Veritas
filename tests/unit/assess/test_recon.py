import asyncio
import json

import pytest

from veritas.assess.checks import CHECKS, PlanContext
from veritas.assess.checks.object_authz import ObjectAuthorization
from veritas.assess.checks.sql_string_built import StringBuiltQuery
from veritas.assess.recon import ReconResult, Route, parse_openapi, run_recon, template_for
from veritas.imports.har import parse_har

OPENAPI = {
    "openapi": "3.0.3",
    "paths": {
        "/api/login": {
            "post": {
                "security": [],
                "requestBody": {
                    "content": {
                        "application/x-www-form-urlencoded": {"schema": {"properties": {"email": {}, "password": {}}}}
                    }
                },
            }
        },
        "/api/notes": {
            "get": {
                "security": [{"cookieAuth": []}],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"properties": {"id": {}, "title": {}, "body": {}}},
                                }
                            }
                        }
                    }
                },
            },
            "post": {
                "security": [{"cookieAuth": []}],
                "requestBody": {
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/NoteInput"}},
                        "application/x-www-form-urlencoded": {"schema": {"$ref": "#/components/schemas/NoteInput"}},
                    }
                },
            },
        },
        "/api/notes/{id}": {"get": {"security": [{"cookieAuth": []}], "parameters": [{"name": "id", "in": "path"}]}},
        "/api/v2/notes/{id}": {  # no v2 listing: the ids come from /api/notes, which lists the same resource
            "get": {
                "security": [{"cookieAuth": []}],
                "parameters": [{"name": "id", "in": "path"}],
                "responses": {
                    "200": {
                        "content": {"application/json": {"schema": {"properties": {"id": {}, "title": {}, "body": {}}}}}
                    }
                },
            }
        },
        "/api/profile": {
            "get": {
                "security": [{"cookieAuth": []}],
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"schema": {"properties": {"id": {}, "display_name": {}, "role": {}}}}
                        }
                    }
                },
            },
            "put": {
                "security": [{"cookieAuth": []}],
                "requestBody": {"content": {"application/json": {"schema": {"properties": {"display_name": {}}}}}},
            },
        },
        "/search": {"get": {"security": [], "parameters": [{"name": "q", "in": "query"}]}},
    },
    "components": {"schemas": {"NoteInput": {"properties": {"title": {}, "body": {}}}}},
}

INDEX = (
    '<a href="/search?q=notes">s</a><a href="/logout">out</a><a href="https://docs.example.invalid/x">docs</a>'
    '<a href="/admin">admin</a><form action="/api/notes" method="post"><input name="title"><input name="body"></form>'
)


class FakeRunner:
    """Serves a tiny fake site and records what recon asked for."""

    def __init__(self, exchange):
        self.exchange, self.requests = exchange, []

    async def run(self, steps, impact, purpose):
        out = []
        for s in steps:
            self.requests.append((impact, s.method, s.path, s.identity))
            if s.path == "/openapi.json":
                out.append(self.exchange(body=json.dumps(OPENAPI), headers=[("Content-Type", "application/json")]))
            elif s.path == "/":
                out.append(self.exchange(body=INDEX, headers=[("Content-Type", "text/html")]))
            elif s.path == "/api/notes":
                ids = {"alice": [1, 2], "bob": [4]}[s.identity]
                out.append(
                    self.exchange(
                        body=json.dumps([{"id": i} for i in ids]), headers=[("Content-Type", "application/json")]
                    )
                )
            else:
                out.append(self.exchange(body="<p>ok</p>", headers=[("Content-Type", "text/html")]))
        return out

    def logins(self):
        return {"alice": "E-login-alice", "bob": "E-login-bob"}


@pytest.fixture
def recon(exchange, target, identities):
    runner = FakeRunner(exchange)
    result = asyncio.run(run_recon(runner, target, identities))
    result.runner_requests = runner.requests
    return result


def test_openapi_import_resolves_refs_and_security():
    routes = {r.label: r for r in parse_openapi(OPENAPI)}
    assert routes["POST /api/notes"].request_fields == ("body", "title")
    assert routes["POST /api/notes"].auth is True
    assert routes["POST /api/login"].auth is False
    assert routes["GET /api/notes"].returns_list is True
    assert routes["GET /api/notes/{id}"].path_params == ("id",)
    assert routes["GET /search"].query_params == ("q",)


def test_recon_stays_in_scope_and_maps_objects(recon):
    assert all(impact == "probe" and method == "GET" for impact, method, _, _ in recon.runner_requests)
    fetched = {path for _, _, path, _ in recon.runner_requests}
    assert "/logout" not in fetched
    assert "/admin" not in fetched
    assert recon.external_links == ["https://docs.example.invalid/x"]
    assert recon.skipped == ["/admin (outside scope)", "/logout (state-changing GET)"]
    assert recon.objects == {"alice": {"/api/notes": ["1", "2"]}, "bob": {"/api/notes": ["4"]}}
    assert recon.logins == {"alice": "E-login-alice", "bob": "E-login-bob"}


def test_template_for_numeric_segments():
    assert template_for("/api/notes/42") == "/api/notes/{id}"
    assert template_for("/") == "/"


def test_checks_plan_the_expected_probes(recon, target, identities):
    ctx = PlanContext(target=target, identities=identities, tag="test")
    planned = {(c.id.rsplit(".", 1)[1], p.route) for c in CHECKS for p in c.plan(recon, ctx)}
    assert planned == {
        ("object-authz", "GET /api/notes/{id}"),
        ("object-authz", "GET /api/v2/notes/{id}"),
        ("reflected-html", "GET /search"),
        ("cookie-attributes", "POST /api/login"),
        ("error-disclosure", "POST /api/notes"),
        ("error-disclosure", "PUT /api/profile"),
        ("mass-assignment", "PUT /api/profile"),
        ("csrf", "POST /api/notes"),
        ("cors", "GET /api/notes"),
        ("cors", "GET /api/profile"),
        ("csp", "GET /"),
        ("csp", "GET /search"),
        ("framing", "GET /"),
        ("framing", "GET /search"),
        ("content-type-options", "GET /"),
        ("server-banner", "GET /"),
    }


def test_object_authz_probe_reads_the_owners_object_as_someone_else(recon, target, identities):
    ctx = PlanContext(target=target, identities=identities, tag="test")
    probes = {p.route: p for p in ObjectAuthorization().plan(recon, ctx)}
    own = probes["GET /api/notes/{id}"]
    assert [(s.identity, s.path) for s in own.steps] == [("bob", "/api/notes/4"), ("alice", "/api/notes/4")]
    assert "id_source" not in own.params
    borrowed = probes["GET /api/v2/notes/{id}"]
    assert [(s.identity, s.path) for s in borrowed.steps] == [("bob", "/api/v2/notes/4"), ("alice", "/api/v2/notes/4")]
    assert borrowed.params["id_source"] == "/api/notes"
    assert "listed by GET /api/notes" in borrowed.description


def test_sql_check_plans_only_with_a_query_log_sensor(recon, target, identities):
    check = StringBuiltQuery()
    assert check.plan(recon, PlanContext(target=target, identities=identities, tag="test")) == []
    ctx = PlanContext(target=target, identities=identities, tag="test", sensors=frozenset({"query-log"}))
    (probe,) = check.plan(recon, ctx)
    canary = ctx.marker("sql", "/search", "q")
    assert (probe.route, probe.steps[0].path, probe.steps[0].identity) == ("GET /search", f"/search?q={canary}-1", None)
    assert check.steps_for(probe, 2)[0].path == f"/search?q={canary}-2"
    assert check.markers(probe, 2) == (f"{canary}-2",)


def recording(*urls: tuple[str, str]):
    """A HAR catalog of (method, url) entries that answered 200 with a JSON object."""
    entries = [{"request": {"method": m, "url": u, "headers": [{"name": "Cookie", "value": "sid=vrt-fake"}]},
                "response": {"status": 200, "headers": [{"name": "Content-Type", "value": "application/json"}],
                             "content": {"mimeType": "application/json", "text": '{"id": 1, "secret": 2}'}}}
               for m, u in urls]  # fmt: skip
    return parse_har(json.dumps({"log": {"entries": entries}}).encode())


def test_recordings_add_only_undocumented_in_scope_routes_and_fetch_nothing(exchange, target, identities):
    catalog = recording(
        ("GET", "http://vuln-notes:8080/api/notes/7"),  # documented as /api/notes/{id}: OpenAPI wins
        ("GET", "http://vuln-notes:8080/api/export?format=csv"),  # undocumented: added
        ("POST", "http://vuln-notes:8080/internal/reset"),  # outside scope
        ("DELETE", "http://vuln-notes:8080/api/notes/7"),  # a method the scope doesn't allow
        ("GET", "http://vuln-notes:8080/logout"),  # state-changing GET
        ("GET", "https://cdn.example.net/x.js"),  # another origin: recorded, never fetched
    )
    runner = FakeRunner(exchange)
    result = asyncio.run(run_recon(runner, target, identities, [catalog]))
    recorded = {r.label: r for r in result.routes if r.source == "recording"}
    assert list(recorded) == ["GET /api/export"]
    export = recorded["GET /api/export"]
    assert (export.query_params, export.response_fields, export.auth) == (("format",), ("id", "secret"), True)
    assert result.route("GET", "/api/notes/{id}").source == "openapi"
    assert "/api/export" not in {path.split("?")[0] for _, _, path, _ in runner.requests}
    assert {"POST /internal/reset (recording, outside scope)", "DELETE /api/notes/{id} (recording, outside scope)",
            "GET /logout (recording, state-changing GET)"} <= set(result.skipped)  # fmt: skip
    assert "https://cdn.example.net:443/x.js" in result.external_links


def test_a_recording_that_changed_after_the_scope_check_is_refused(tmp_path, target):
    from veritas.assess.runner import RunError, load_recordings
    from veritas.scope.check import ScopeReport

    (tmp_path / "rec.har").write_text('{"log": {"entries": []}}', encoding="utf-8")
    scope_target = target.model_copy(update={"recordings": ["rec.har"]})
    report = ScopeReport(path=tmp_path / "veritas.scope.yaml", files={"targets.web.recordings.0": "sha256:" + "0" * 64})
    with pytest.raises(RunError, match="changed after the scope was checked"):
        load_recordings(report, scope_target)


def test_object_authz_borrows_ids_only_from_a_listing_of_the_same_resource(target, identities):
    note, user = ("body", "id", "title"), ("id", "name")
    recon = ReconResult(
        routes=[
            Route("GET", "/api/notes", response_fields=note, returns_list=True, auth=True),
            Route("GET", "/api/users", response_fields=user, returns_list=True, auth=True),
            Route("GET", "/api/v2/notes/{id}", path_params=("id",), response_fields=note, auth=True),
            Route("GET", "/api/v2/users/{id}", path_params=("id",), response_fields=("email", "id"), auth=True),
            Route("GET", "/api/teams/{id}", path_params=("id",), response_fields=user, auth=True),
            Route("GET", "/api/v3/notes/{id}", path_params=("id",), auth=True),
        ],
        objects={"bob": {"/api/notes": ["4"], "/api/users": ["7"]}},
    )
    ctx = PlanContext(target=target, identities=identities, tag="test")
    planned = [(p.route, p.params["path"]) for p in ObjectAuthorization().plan(recon, ctx)]
    # v2 users return other fields, teams are another resource, and v3 declares no response schema
    assert planned == [("GET /api/v2/notes/{id}", "/api/v2/notes/4")]
