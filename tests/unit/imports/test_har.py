"""HAR recordings: the catalog keeps shapes and drops values, and the traffic rules judge only the app's origin."""

import json

import pytest

from veritas.analyze.program import FileModel
from veritas.analyze.security import code_findings
from veritas.imports.har import HarError, parse_har, read_har, template

SECRETS = ("vrt-fake", "alice@lab.test", "groceries", "Buy milk", "2 litres", "Lab report")


def har(*entries: dict) -> bytes:
    return json.dumps({"log": {"version": "1.2", "creator": {"name": "test"}, "entries": list(entries)}}).encode()


def entry(method="GET", url="http://app.test/", status=200, type_="application/json", body="", sent=(), got=(),
          post=None, encoding=None):  # fmt: skip
    content = {"mimeType": type_, "text": body, **({"encoding": encoding} if encoding else {})}
    request = {"method": method, "url": url, "headers": [{"name": k, "value": v} for k, v in sent]}
    if post is not None:
        request["postData"] = post
    response = {"status": status, "headers": [{"name": "Content-Type", "value": type_}]
                + [{"name": k, "value": v} for k, v in got], "content": content}  # fmt: skip
    return {"request": request, "response": response}


def by_label(catalog) -> dict:
    return {f"{e['method']} {e['template']}": e for e in catalog.to_json()["endpoints"]}


def test_the_lab_recording_keeps_shapes_and_no_values(repo_root):
    path = repo_root / "labs" / "vuln-notes" / "recordings" / "browse.har"
    facts = read_har(path).to_json()
    text = json.dumps(facts)
    assert [s for s in SECRETS if s in text] == []
    endpoints = by_label(read_har(path))
    assert endpoints["GET /api/notes/{id}"]["response"]["fields"] == {"body": ["string"], "id": ["number"],
                                                                      "title": ["string"]}  # fmt: skip
    assert endpoints["POST /api/login"]["request"]["fields"] == {"email": ["string"], "password": ["string"]}
    assert endpoints["GET /api/notes"]["auth"] == ["cookie:sid"]
    assert endpoints["GET /api/notes"]["response"]["list"] is True
    assert (facts["ignored"], facts["skipped"]) == ({"data": 1}, {})
    assert [o["origin"] for o in facts["origins"] if o["first_party"]] == ["http://vuln-notes:8080"]


def test_credentials_keep_only_their_kind():
    catalog = parse_har(har(entry(sent=[("Authorization", "Bearer vrt-fake-token-1"), ("X-API-Key", "vrt-fake-key-2"),
                                        ("Cookie", "theme=dark; session_id=vrt-fake-3")])))  # fmt: skip
    (e,) = catalog.to_json()["endpoints"]
    assert e["auth"] == ["bearer", "cookie:session_id", "header:x-api-key"]
    assert "vrt-fake" not in json.dumps(catalog.to_json())


def test_path_segments_and_keys_that_carry_data_become_placeholders():
    assert template("/users/alice@example.com/files/550e8400-e29b-41d4-a716-446655440000") == (
        "/users/{email}/files/{id}"
    )
    assert template("/share/AbC123dEf456GhI789jKl0/view") == "/share/{token}/view"
    assert template("/a b/%7Ex") == "/a%20b/~x"
    body = json.dumps({"alice@example.com": 1, "12345": 2, "name": "x"})
    (e,) = parse_har(har(entry(body=body))).to_json()["endpoints"]
    assert e["response"]["fields"] == {"name": ["string"]}


def test_base64_bodies_are_read_for_their_shape_only():
    import base64

    body = base64.b64encode(json.dumps([{"id": 1, "secret": "vrt-fake-x"}]).encode()).decode()
    (e,) = parse_har(har(entry(body=body, encoding="base64"))).to_json()["endpoints"]
    assert e["response"] == {"types": ["application/json"], "fields": {"id": ["number"], "secret": ["string"]},
                             "list": True}  # fmt: skip


@pytest.mark.parametrize(
    ("data", "message"),
    [(b"{not json", "not valid JSON"), (b'{"log": {}}', "no log.entries"), (b"[" * 100_000 + b"]" * 100_000, "JSON")],
)
def test_a_file_that_is_not_a_recording_is_refused(data, message):
    with pytest.raises(HarError, match=message):
        parse_har(data)


def test_malformed_entries_are_counted_not_guessed():
    catalog = parse_har(har(entry(), {"request": "x"}, entry(method="get"), entry(url="http://[::1")))
    assert catalog.to_json()["skipped"] == {"malformed entry": 3}


def rules(*entries) -> list[tuple[str, str]]:
    model = FileModel("t.har", "0" * 64, "E-0123456789ab", parse_har(har(*entries)).to_json())
    return sorted((f["rule"], f["function"]) for f in code_findings([model]))


def test_the_traffic_rules_and_their_look_alikes():
    page = "<!doctype html><title>x</title>"
    found = rules(
        entry(url="https://app.test/", type_="text/html", body=page,
              got=[("Server", "nginx/1.25.3"), ("X-Powered-By", "Express"), ("X-Content-Type-Options", "nosniff"),
                   ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
                   ("Set-Cookie", "session=vrt-fake; HttpOnly; SameSite=Lax"), ("Set-Cookie", "XSRF-TOKEN=x")]),
        entry(url="https://app.test/api/me?access_token=vrt-fake&page=2", got=[("X-Content-Type-Options", "nosniff"),
              ("Strict-Transport-Security", "max-age=31536000"), ("Access-Control-Allow-Origin", "null"),
              ("Access-Control-Allow-Credentials", "true")]),
        entry(url="https://cdn.other.test/x.js", type_="text/javascript", got=[("Server", "cdn/9.9")]),
    )  # fmt: skip
    assert found == [
        ("cookie-secure", "GET /"),
        ("cors-null-origin", "GET /api/me"),
        ("credential-in-url", "GET /api/me"),
        ("hsts-missing", "https://app.test:443"),
        ("version-disclosure", "https://app.test:443"),
    ]


def test_a_well_configured_site_yields_nothing():
    good = [("Content-Security-Policy", "default-src 'self'; frame-ancestors 'self'"), ("Server", "nginx"),
            ("X-Content-Type-Options", "nosniff"), ("Strict-Transport-Security", "max-age=31536000"),
            ("Set-Cookie", "sid=vrt-fake; Secure; HttpOnly; SameSite=Strict")]  # fmt: skip
    assert rules(entry(url="https://app.test/", type_="text/html", body="<p>x</p>", got=good)) == []
