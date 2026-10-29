from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from uuid import UUID, uuid4

from techflex_cloud_foundation.platform_errors import AuthenticationError


@dataclass(frozen=True, slots=True)
class TerminalContext:
    tenant_id: UUID
    terminal_id: UUID
    expires_at: datetime

    def ensure_active(self, now: datetime | None = None) -> None:
        current = now or datetime.now(UTC)
        if self.expires_at.tzinfo is None or self.expires_at <= current:
            raise AuthenticationError("终端凭据已过期", terminal_id=str(self.terminal_id))


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    try:
        return base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AuthenticationError("终端凭据格式无效") from exc


class TerminalTokenIssuer:
    """Issues short-lived terminal-bound bearer tokens using a server-only HMAC key."""

    def __init__(self, *, secret: bytes, key_id: str, token_ttl: timedelta) -> None:
        if len(secret) < 32:
            raise ValueError("terminal token secret must contain at least 32 bytes")
        if token_ttl <= timedelta(0):
            raise ValueError("token_ttl must be positive")
        self._secret = secret
        self._key_id = key_id
        self._token_ttl = token_ttl

    def issue(
        self,
        tenant_id: UUID,
        terminal_id: UUID,
        *,
        now: datetime | None = None,
    ) -> str:
        issued_at = now or datetime.now(UTC)
        expires_at = issued_at + self._token_ttl
        header = {"alg": "HS256", "kid": self._key_id, "typ": "FFP-Terminal"}
        payload = {
            "tenant_id": str(tenant_id),
            "terminal_id": str(terminal_id),
            "iat": int(issued_at.timestamp()),
            "exp": int(expires_at.timestamp()),
            "jti": str(uuid4()),
        }
        encoded_header = _base64url(
            json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        encoded_payload = _base64url(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        signature = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"

    def verify(self, token: str, *, now: datetime | None = None) -> TerminalContext:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as exc:
            raise AuthenticationError("终端凭据格式无效") from exc
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        supplied = _decode_base64url(encoded_signature)
        if not hmac.compare_digest(expected, supplied):
            raise AuthenticationError("终端凭据签名无效")
        try:
            header = json.loads(_decode_base64url(encoded_header))
            payload = json.loads(_decode_base64url(encoded_payload))
            if header != {"alg": "HS256", "kid": self._key_id, "typ": "FFP-Terminal"}:
                raise AuthenticationError("终端凭据头无效")
            context = TerminalContext(
                tenant_id=UUID(payload["tenant_id"]),
                terminal_id=UUID(payload["terminal_id"]),
                expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, AuthenticationError):
                raise
            raise AuthenticationError("终端凭据载荷无效") from exc
        context.ensure_active(now)
        return context
