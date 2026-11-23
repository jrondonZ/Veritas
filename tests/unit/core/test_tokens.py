import pytest

from veritas.core.tokens import NetGrant, TokenClaims, TokenError, mint, new_run_key, verify_token

NOW = 1_800_000_000


def claims(**over):
    base = {
        "tid": "t-0001",
        "run": "r-0001",
        "exp": NOW + 60,
        "plugin": "veritas.selftest@0.0.1",
        "impact_max": "probe",
        "net": [NetGrant(target="web", methods=["GET"], paths=["/api/**"], max_requests=3)],
    }
    base.update(over)
    return TokenClaims(**base)


def test_round_trip():
    key = new_run_key()
    assert verify_token(mint(claims(), key), key, NOW) == claims()


def test_wrong_key_is_rejected():
    with pytest.raises(TokenError, match="bad signature"):
        verify_token(mint(claims(), new_run_key()), new_run_key(), NOW)


def test_tampered_claims_are_rejected():
    key = new_run_key()
    _body, mac = mint(claims(), key).split(".")
    other_body = mint(claims(impact_max="sensitive"), key).split(".")[0]
    with pytest.raises(TokenError, match="bad signature"):
        verify_token(other_body + "." + mac, key, NOW)


def test_expired_token_is_rejected():
    key = new_run_key()
    with pytest.raises(TokenError, match="expired"):
        verify_token(mint(claims(exp=NOW), key), key, NOW)


@pytest.mark.parametrize("token", ["", "abc", "abc.", ".abc", "!!!.###"])
def test_malformed_tokens_are_rejected(token):
    with pytest.raises(TokenError):
        verify_token(token, new_run_key(), NOW)


def test_unknown_methods_are_rejected():
    with pytest.raises(ValueError, match="unknown methods"):
        NetGrant(target="web", methods=["CONNECT"], paths=["/"], max_requests=1)
