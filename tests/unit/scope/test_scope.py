import copy
from datetime import UTC, datetime

import pytest
import yaml

from veritas.scope import check_scope

NOW = datetime(2026, 11, 20, tzinfo=UTC)

BASE = {
    "apiVersion": "veritas/v1alpha1",
    "kind": "AssessmentScope",
    "metadata": {"name": "vuln-notes-lab"},
    "authorization": {
        "basis": "owned",
        "reference": {"file": "README.md"},
        "window": {"start": "2026-11-18T00:00:00Z", "end": "2026-12-31T23:59:59Z"},
    },
    "environment": {"kind": "disposable", "provider": "compose", "compose_file": "compose.yaml", "reset": "snapshot"},
    "targets": [
        {
            "id": "web",
            "base_url": "http://vuln-notes:8080",
            "addresses": ["172.30.0.4"],
            "allow": {"paths": ["/", "/api/**"], "methods": ["GET", "HEAD", "POST", "PUT"]},
            "deny": {"paths": ["/api/admin/**"]},
            "unsafe_get": ["/logout"],
            "limits": {"rps": 10, "concurrency": 4, "max_requests": 5000},
        }
    ],
    "identities": [
        {
            "id": "alice",
            "kind": "synthetic",
            "target": "web",
            "login": {
                "type": "form",
                "path": "/api/login",
                "username": "alice@lab.test",
                "username_field": "email",
                "password_field": "password",
            },
            "secret": "env:VRT_ALICE",
            "canary": "vrt-seed-alice",
        }
    ],
    "policy": {"auto_approve": ["observe", "probe", "mutate"], "models": True},
    "budgets": {"wall_clock": "20m"},
}

COMPOSE = {
    "services": {
        "vuln-notes": {"image": "x", "networks": {"lab": {"ipv4_address": "172.30.0.4"}}},
    },
    "networks": {"lab": {"internal": True}},
}


def write(tmp_path, doc=None, compose=None, readme="authorized: owned lab\n", text=None):
    (tmp_path / "README.md").write_text(readme, encoding="utf-8")
    (tmp_path / "compose.yaml").write_text(yaml.safe_dump(compose or COMPOSE), encoding="utf-8")
    path = tmp_path / "veritas.scope.yaml"
    path.write_text(text if text is not None else yaml.safe_dump(doc or BASE, sort_keys=False), encoding="utf-8")
    return path


def mutated(**changes):
    doc = copy.deepcopy(BASE)
    for dotted, value in changes.items():
        node = doc
        keys = dotted.split("__")
        for k in keys[:-1]:
            node = node[int(k)] if isinstance(node, list) else node[k]
        last = keys[-1]
        if value is DELETE:
            del node[last]
        else:
            node[last] = value
    return doc


DELETE = object()


def check(tmp_path, doc=None, **kw):
    return check_scope(write(tmp_path, doc, **kw), now=NOW, resolver=kw.pop("resolver", None) or no_dns)


def no_dns(host, port):
    raise OSError("no DNS in tests")


def test_valid_lab_scope(tmp_path):
    report = check(tmp_path)
    assert report.ok, report.errors
    assert report.digest.startswith("sha256:")
    assert report.pinned[0].addresses == ["172.30.0.4"]
    assert set(report.files) == {"authorization.reference", "environment.compose_file"}


def test_digest_ignores_key_order_and_comments(tmp_path):
    first = check(tmp_path).digest
    reordered = dict(reversed(list(BASE.items())))
    text = "# a comment\n" + yaml.safe_dump(reordered, sort_keys=False)
    assert check_scope(write(tmp_path, text=text), now=NOW, resolver=no_dns).digest == first


def test_digest_changes_with_scope_and_reference_contents(tmp_path):
    first = check(tmp_path).digest
    wider = mutated(targets__0__allow__paths=["/", "/api/**", "/static/**"])
    assert check(tmp_path, wider).digest != first
    assert check(tmp_path, readme="different letter\n").digest != first


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        ({"environment__kind": "production"}, "production environments are not supported"),
        ({"policy__auto_approve": ["observe", "sensitive"]}, "sensitive actions always need approval"),
        ({"environment__reset": "none"}, "mutate can be auto-approved only"),
        (
            {
                "targets__0__allow__methods": ["GET", "DELETE"],
                "environment__kind": "staging",
                "policy__auto_approve": ["observe"],
            },
            "DELETE is allowed only in disposable",
        ),
        ({"targets__0__addresses": DELETE}, "lab targets must declare pinned addresses"),
        ({"targets__0__allow__paths": ["/api/../admin"]}, "'.' or '..' segments"),
        ({"targets__0__base_url": "http://vuln-notes:8080/app"}, "must be an origin"),
        ({"targets__0__base_url": "http://u:p@vuln-notes:8080"}, "must not contain credentials"),
        ({"targets__0__limits__rps": 500}, "less than or equal to 50"),
        ({"identities__0__secret": "hunter2"}, "identities.0.secret"),
        ({"targets__0__surprise": True}, "Extra inputs are not permitted"),
        ({"authorization__window__end": "2026-11-19T00:00:00Z"}, "window ended"),
        ({"authorization__window__start": "2026-11-25T00:00:00Z"}, "window opens"),
        ({"authorization__reference": {"file": "missing.md"}}, "reference.file not found"),
        ({"targets__0__addresses": ["172.30.0.9"]}, "differ from the compose file"),
        ({"targets__0__addresses": ["169.254.169.254"]}, "link-local"),
        ({"identities__0__target": "other"}, "unknown target 'other'"),
        ({"identities__0__login__path": "/login"}, "login path /login must be allowed for POST"),
        ({"identities__0__login__path": "/api/*"}, "must be a literal absolute path"),
        ({"targets__0__openapi": "/openapi.json"}, "openapi path /openapi.json must be allowed for GET"),
    ],
)
def test_rejections(tmp_path, changes, fragment):
    report = check(tmp_path, mutated(**changes))
    assert not report.ok
    assert any(fragment in e for e in report.errors), report.errors


SENSOR = {"id": "queries", "kind": "query-log", "target": "web", "volume": "query-log"}
COMPOSE_WITH_LOG = {**COMPOSE, "volumes": {"query-log": {"name": "vrt-lab-query-log"}}}


def test_sensor_must_name_a_compose_volume(tmp_path):
    report = check(tmp_path, mutated(sensors=[SENSOR]), compose=COMPOSE_WITH_LOG)
    assert report.ok, report.errors
    assert report.scope.sensors[0].volume == "query-log"
    assert report.digest != check(tmp_path, compose=COMPOSE_WITH_LOG).digest  # a sensor is part of what is acknowledged
    missing = check(tmp_path, mutated(sensors=[SENSOR]))
    assert any("declares no volume 'query-log'" in e for e in missing.errors), missing.errors


@pytest.mark.parametrize(
    ("changes", "fragment"),
    [
        (
            {
                "sensors": [SENSOR],
                "environment": {"kind": "staging", "provider": "compose", "compose_file": "compose.yaml"},
                "policy__auto_approve": ["observe", "probe"],
            },
            "sensors run only in disposable or local-dev compose environments",
        ),
        ({"sensors": [{**SENSOR, "target": "other"}]}, "sensor queries: unknown target 'other'"),
        ({"sensors": [{**SENSOR, "kind": "app-log"}]}, "sensors.0.kind"),
        ({"sensors": [SENSOR, SENSOR]}, "duplicate sensor ids: queries"),
    ],
)
def test_sensor_rejections(tmp_path, changes, fragment):
    report = check(tmp_path, mutated(**changes), compose=COMPOSE_WITH_LOG)
    assert not report.ok
    assert any(fragment in e for e in report.errors), report.errors


HAR = '{"log": {"entries": [{"request": {"method": "GET", "url": "http://vuln-notes:8080/api/x"}, "response": {}}]}}'


def test_a_recording_is_hashed_into_the_digest(tmp_path):
    (tmp_path / "rec.har").write_text(HAR, encoding="utf-8")
    report = check(tmp_path, mutated(targets__0__recordings=["rec.har"]))
    assert report.ok, report.errors
    assert "targets.web.recordings.0" in report.files
    assert any("rec.har shows 1 endpoint(s) on this origin" in n for n in report.notices)
    first = report.digest
    (tmp_path / "rec.har").write_text(HAR.replace("/api/x", "/api/y"), encoding="utf-8")
    assert check(tmp_path, mutated(targets__0__recordings=["rec.har"])).digest != first


@pytest.mark.parametrize(
    ("recordings", "contents", "fragment"),
    [
        (["missing.har"], None, "recording not found"),
        (["rec.har"], "{}", "isn't a HAR recording Veritas can read"),
        (["../rec.har"], HAR, "must be a relative path inside the scope's directory"),
        (["/etc/rec.har"], HAR, "must be a relative path inside the scope's directory"),
    ],
)
def test_recording_rejections(tmp_path, recordings, contents, fragment):
    if contents is not None:
        (tmp_path / "rec.har").write_text(contents, encoding="utf-8")
    report = check(tmp_path, mutated(targets__0__recordings=recordings))
    assert not report.ok
    assert any(fragment in e for e in report.errors), report.errors


def test_resolved_public_address_is_rejected(tmp_path):
    doc = mutated(**{"environment": {"kind": "local-dev"}, "policy__auto_approve": ["observe", "probe"]})
    doc["targets"][0]["addresses"] = None
    del doc["targets"][0]["addresses"]
    report = check_scope(write(tmp_path, doc), now=NOW, resolver=lambda h, p: ["93.184.215.14"])
    assert any("public or reserved" in e for e in report.errors), report.errors


def test_resolution_failure_is_an_error(tmp_path):
    doc = mutated(**{"environment": {"kind": "local-dev"}, "policy__auto_approve": ["observe", "probe"]})
    del doc["targets"][0]["addresses"]
    report = check(tmp_path, doc)
    assert any("cannot resolve" in e for e in report.errors), report.errors


def test_resolved_loopback_is_pinned(tmp_path):
    doc = mutated(**{"environment": {"kind": "local-dev"}, "policy__auto_approve": ["observe", "probe"]})
    del doc["targets"][0]["addresses"]
    report = check_scope(write(tmp_path, doc), now=NOW, resolver=lambda h, p: ["127.0.0.1", "::1"])
    assert report.ok, report.errors
    assert report.pinned[0].addresses == ["127.0.0.1", "::1"]


def test_duplicate_yaml_keys_are_rejected(tmp_path):
    text = yaml.safe_dump(BASE, sort_keys=False) + "kind: AssessmentScope\n"
    report = check_scope(write(tmp_path, text=text), now=NOW, resolver=no_dns)
    assert any("duplicate key" in e for e in report.errors), report.errors


def test_reference_identifier_is_recorded_as_notice(tmp_path):
    report = check(tmp_path, mutated(authorization__reference={"id": "SEC-1234"}))
    assert report.ok, report.errors
    assert any("SEC-1234" in n for n in report.notices)
