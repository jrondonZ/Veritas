import base64

import pytest

from veritas.core.tokens import NetGrant, TokenClaims, mint, new_run_key
from veritas.gateway.admission import (
    AdmissionState,
    Denied,
    GatewayConfig,
    GatewayTarget,
    ProxyRequest,
    TokenBucket,
    admit,
)

NOW = 1_800_000_000
KEY = new_run_key()
CONFIG = GatewayConfig(
    run="r-0001",
    targets=[
        GatewayTarget(
            id="web",
            scheme="http",
            host="vuln-notes",
            port=8080,
            addresses=["172.30.0.4"],
            allow_paths=["/", "/logout", "/api/**"],
            allow_methods=["GET", "HEAD", "POST", "PUT"],
            deny_paths=["/api/admin/**"],
            unsafe_get=["/logout"],
            rps=10,
            concurrency=4,
            max_requests=100,
        )
    ],
)


def token(tid="t-0001", run="r-0001", impact="probe", exp=NOW + 60, grants=None, key=KEY):
    grants = grants or [
        NetGrant(
            target="web",
            methods=["GET", "HEAD"],
            paths=["/", "/logout", "/api/**"],
            identities=["alice"],
            max_requests=3,
        )
    ]
    claims = TokenClaims(tid=tid, run=run, exp=exp, plugin="selftest@0", impact_max=impact, net=grants)
    return mint(claims, key)


def basic(user, secret):
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


def req(
    method="GET",
    uri="http://vuln-notes:8080/api/notes?x=1",
    host="vuln-notes:8080",
    auth=None,
    identity=None,
    tid="t-0001",
    **token_kw,
):
    if auth is None:
        auth = basic(tid, token(tid=tid, **token_kw))
    return ProxyRequest(method=method, uri=uri, host_header=host, proxy_authorization=auth, identity=identity)


def run(request, state=None):
    return admit(request, CONFIG, KEY, state or AdmissionState(), NOW)


def test_allowed_request():
    a = run(req())
    assert a.target.id == "web"
    assert a.upstream_target == "/api/notes?x=1"
    assert a.authority == "vuln-notes:8080"
    assert a.impact == "probe"


def test_host_case_and_trailing_dot_are_normalized():
    run(req(uri="http://VULN-NOTES.:8080/api/notes", host="Vuln-Notes.:8080"))


@pytest.mark.parametrize(
    ("request_", "code"),
    [
        (req(auth=""), "auth_required"),
        (req(auth="Bearer abc"), "auth_invalid"),
        (req(auth=basic("t-0001", "garbage")), "auth_invalid"),
        (req(auth=basic("t-0001", token(key=new_run_key()))), "auth_invalid"),
        (req(exp=NOW), "auth_invalid"),
        (req(auth=basic("t-0002", token(tid="t-0001"))), "auth_invalid"),
        (req(run="r-0002"), "auth_invalid"),
        (req(method="CONNECT", uri="vuln-notes:8080"), "connect_unsupported"),
        (req(method="TRACE"), "method_unsupported"),
        (req(uri="/api/notes"), "origin_form"),
        (req(uri="http://u:p@vuln-notes:8080/api/notes"), "credentials_in_uri"),
        (req(uri="http://vuln-notes:8080@decoy:8080/api/notes", host="decoy:8080"), "credentials_in_uri"),
        (req(uri="https://vuln-notes:8080/api/notes"), "https_unsupported"),
        (req(host="decoy:8080"), "host_mismatch"),
        (req(host=None), "host_mismatch"),
        (req(uri="http://decoy:8080/api/notes", host="decoy:8080"), "out_of_scope"),
        (req(uri="http://172.30.0.4:8080/api/notes", host="172.30.0.4:8080"), "out_of_scope"),
        (req(uri="http://172.30.0.5:8080/api/notes", host="172.30.0.5:8080"), "out_of_scope"),
        (req(uri="http://[fd00::5]:8080/api/notes", host="[fd00::5]:8080"), "out_of_scope"),
        (req(uri="http://[::ffff:172.30.0.5]:8080/", host="[::ffff:172.30.0.5]:8080"), "out_of_scope"),
        (req(uri="http://vuln-notes:9090/api/notes", host="vuln-notes:9090"), "out_of_scope"),
        (req(uri="http://vuln-notes:8080/api/../admin"), "path_ambiguous"),
        (req(uri="http://vuln-notes:8080/api/%2e%2e/admin"), "path_ambiguous"),
        (req(uri="http://vuln-notes:8080/api%2fadmin"), "path_ambiguous"),
        (req(method="DELETE"), "method_not_in_scope"),
        (req(uri="http://vuln-notes:8080/secret"), "path_not_in_scope"),
        (req(uri="http://vuln-notes:8080/api/admin/users"), "path_denied"),
        (req(uri="http://vuln-notes:8080/api/%61dmin/users"), "path_denied"),
        (req(uri="http://vuln-notes:8080/logout"), "impact_exceeds_token"),
        (req(method="POST"), "impact_exceeds_token"),
        (req(method="POST", impact="mutate"), "outside_envelope"),
        (
            req(grants=[NetGrant(target="web", methods=["GET"], paths=["/api/notes/*"], max_requests=3)]),
            "outside_envelope",
        ),
        (req(identity="bob"), "identity_not_granted"),
    ],
)
def test_denials(request_, code):
    with pytest.raises(Denied) as exc:
        run(request_)
    assert exc.value.code == code


def test_revoked_task_and_run():
    state = AdmissionState(revoked={"t-0001"})
    with pytest.raises(Denied, match="revoked"):
        run(req(), state)
    with pytest.raises(Denied, match="revoked"):
        run(req(tid="t-0009"), AdmissionState(run_revoked=True))


def test_task_budget_is_enforced():
    state = AdmissionState()
    request = req()
    for _ in range(3):
        run(request, state)
    with pytest.raises(Denied) as exc:
        run(request, state)
    assert exc.value.code == "task_budget_exhausted"
    assert exc.value.status == 429


def test_target_budget_is_enforced():
    state = AdmissionState()
    state.target_counts["web"] = 100
    with pytest.raises(Denied) as exc:
        run(req(), state)
    assert exc.value.code == "target_budget_exhausted"


def test_token_bucket_spaces_requests():
    bucket = TokenBucket(rate=10)
    assert bucket.reserve(0.0) == 0.0
    assert bucket.reserve(0.0) == pytest.approx(0.1)
    assert bucket.reserve(0.0) == pytest.approx(0.2)
    assert bucket.reserve(5.0) == 0.0
