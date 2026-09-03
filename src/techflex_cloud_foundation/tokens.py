"""HMAC-signed token codec for service-issued access tokens.

A minimal, business-neutral HS256 token format:
``base64url(header).base64url(payload).base64url(signature)`` where the
header pins ``alg``/``kid``/``typ`` and the payload pins ``aud``.
Signatures are compared before any content is parsed, with constant-time
comparison.  Claims are supplied by the caller; the codec owns only the
envelope.  This complements ``transport.TokenProvider`` (client-side
acquisition) with the server-side issue/verify boundary.
"""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from datetime import UTC, datetime
import hashlib
import hmac
import json
from typing import Any, Protocol

_RESERVED_CLAIMS = frozenset({"aud", "iat", "exp"})
_MIN_SECRET_BYTES = 32


class TokenError(ValueError):
    """Base class for token issue/verification failures."""


class TokenMalformed(TokenError):
    """The token does not have three base64url segments."""


class TokenSignatureInvalid(TokenError):
    """The signature does not match the signing input."""


class TokenHeaderMismatch(TokenError):
    """The header does not pin the expected alg/kid/typ."""


class TokenAudienceMismatch(TokenError):
    """The payload audience differs from the expected audience."""


class TokenExpired(TokenError):
    """The token's exp claim is in the past."""


class TokenIssuer(Protocol):
    """Server-side token boundary; claims belong to the application."""

    def issue(
        self, claims: Mapping[str, Any], *, expires_at: datetime | None = None
    ) -> str: ...

    def verify(self, token: str, *, now: datetime | None = None) -> dict[str, Any]: ...


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _decode_base64url(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise TokenMalformed("token segment is not valid base64url") from exc


def _encoded_json(value: Mapping[str, Any]) -> str:
    return _base64url(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    )


class HmacTokenCodec:
    """Issues and verifies HS256 tokens for one key id, type, and audience."""

    def __init__(
        self, *, secret: bytes, key_id: str, token_type: str, audience: str
    ) -> None:
        if len(secret) < _MIN_SECRET_BYTES:
            raise ValueError("secret must be at least 32 bytes")
        for label, value in (
            ("key_id", key_id), ("token_type", token_type), ("audience", audience)
        ):
            if not value or "." in value:
                raise ValueError(f"{label} must be non-empty and contain no '.'")
        self._secret = secret
        self._key_id = key_id
        self._token_type = token_type
        self._audience = audience

    def issue(
        self, claims: Mapping[str, Any], *, expires_at: datetime | None = None
    ) -> str:
        reserved = _RESERVED_CLAIMS & set(claims)
        if reserved:
            raise ValueError(f"claims must not set reserved keys: {sorted(reserved)}")
        header = {"alg": "HS256", "kid": self._key_id, "typ": self._token_type}
        now = datetime.now(UTC)
        payload: dict[str, Any] = {
            **claims,
            "aud": self._audience,
            "iat": int(now.timestamp()),
        }
        if expires_at is not None:
            if expires_at.tzinfo is None:
                raise ValueError("expires_at must be timezone-aware")
            if expires_at <= now:
                raise ValueError("expires_at must be in the future")
            payload["exp"] = int(expires_at.timestamp())
        encoded_header = _encoded_json(header)
        encoded_payload = _encoded_json(payload)
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"

    def verify(self, token: str, *, now: datetime | None = None) -> dict[str, Any]:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as exc:
            raise TokenMalformed("token must have three segments") from exc
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        supplied = _decode_base64url(encoded_signature)
        if not hmac.compare_digest(expected, supplied):
            raise TokenSignatureInvalid("token signature does not match")
        try:
            header = json.loads(_decode_base64url(encoded_header))
            payload = json.loads(_decode_base64url(encoded_payload))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise TokenMalformed("token segments are not valid JSON") from exc
        if header != {"alg": "HS256", "kid": self._key_id, "typ": self._token_type}:
            raise TokenHeaderMismatch("token header does not match the expected alg/kid/typ")
        if not isinstance(payload, dict) or payload.get("aud") != self._audience:
            raise TokenAudienceMismatch("token audience does not match")
        expires = payload.get("exp")
        if expires is not None:
            checked_at = now or datetime.now(UTC)
            if checked_at.tzinfo is None:
                raise ValueError("now must be timezone-aware")
            if int(expires) <= int(checked_at.timestamp()):
                raise TokenExpired("token has expired")
        return payload
