import itertools

import pytest

from veritas.assess.evidence import Exchange
from veritas.scope.model import FormLogin, Identity, Target

_ids = itertools.count(1)


def make_exchange(status=200, body="", headers=(), method="GET", path="/", identity=None, kind="exchange"):
    return Exchange(
        id=f"E-{next(_ids):012x}",
        kind=kind,
        tid="t-0001",
        target="web",
        identity=identity,
        method=method,
        path=path,
        request_headers=(),
        request_body=b"",
        status=status,
        response_headers=tuple((n.lower(), v) for n, v in headers),
        response_body=body.encode() if isinstance(body, str) else body,
    )


@pytest.fixture
def exchange():
    return make_exchange


@pytest.fixture
def target():
    return Target.model_validate(
        {
            "id": "web",
            "base_url": "http://vuln-notes:8080",
            "addresses": ["172.30.0.4"],
            "openapi": "/openapi.json",
            "allow": {
                "paths": ["/", "/openapi.json", "/logout", "/search", "/search2", "/api/**"],
                "methods": ["GET", "HEAD", "POST", "PUT"],
            },
            "unsafe_get": ["/logout"],
            "limits": {"rps": 10, "concurrency": 4, "max_requests": 5000},
        }
    )


@pytest.fixture
def identities():
    def identity(name):
        login = FormLogin(
            type="form",
            path="/api/login",
            username=f"{name}@lab.test",
            username_field="email",
            password_field="password",
        )
        return Identity(
            id=name,
            kind="synthetic",
            target="web",
            login=login,
            secret=f"env:VRT_{name.upper()}",
            canary=f"vrt-seed-{name}",
        )

    return (identity("alice"), identity("bob"))
