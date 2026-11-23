"""Capability tokens (docs/architecture.md §6.5).

A token is `base64url(canonical claims) "." base64url(HMAC-SHA256)`, signed with a
per-run key that only the kernel and the gateway hold. Sandboxes receive it as
proxy credentials; the gateway verifies it on every request.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import json
import secrets

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from .canonical import canonical_bytes
from .impact import HTTP_METHODS, Impact

_DOMAIN = b"veritas-token-v1\x00"


class TokenError(Exception):
    pass


class NetGrant(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    target: str
    methods: list[str] = Field(min_length=1)
    paths: list[str] = Field(min_length=1)
    identities: list[str] = []
    max_requests: int = Field(ge=1)

    @field_validator("methods")
    @classmethod
    def _known_methods(cls, methods: list[str]) -> list[str]:
        bad = [m for m in methods if m not in HTTP_METHODS]
        if bad:
            raise ValueError(f"unknown methods: {bad}")
        return methods


class TokenClaims(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    tid: str
    run: str
    exp: int  # unix seconds
    plugin: str
    impact_max: Impact
    approval: str | None = None
    net: list[NetGrant] = []


def new_run_key() -> bytes:
    return secrets.token_bytes(32)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(key: bytes, body: bytes) -> bytes:
    return hmac.new(key, _DOMAIN + body, hashlib.sha256).digest()


def mint(claims: TokenClaims, key: bytes) -> str:
    body = canonical_bytes(claims.model_dump(mode="json"))
    return _b64(body) + "." + _b64(_mac(key, body))


def verify_token(token: str, key: bytes, now: float) -> TokenClaims:
    body_text, sep, mac_text = token.partition(".")
    if not sep or not body_text or not mac_text:
        raise TokenError("malformed token")
    try:
        body, mac = _unb64(body_text), _unb64(mac_text)
    except (binascii.Error, ValueError):
        raise TokenError("malformed token") from None
    if not hmac.compare_digest(mac, _mac(key, body)):
        raise TokenError("bad signature")
    try:
        claims = TokenClaims.model_validate(json.loads(body))
    except (json.JSONDecodeError, ValidationError, ValueError):
        raise TokenError("invalid claims") from None
    if claims.exp <= now:
        raise TokenError("expired")
    return claims
