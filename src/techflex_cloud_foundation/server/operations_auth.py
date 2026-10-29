from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.operations import OperationsPermission
from techflex_cloud_foundation.platform_errors import AuthenticationError
from techflex_cloud_foundation.server.device_management.operations import OperationsContext


def _base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str) -> bytes:
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (UnicodeEncodeError, binascii.Error) as exc:
        raise AuthenticationError("运营凭据格式无效") from exc


class OperationsTokenIssuer:
    """Testable internal control-plane token boundary; production maps IAM claims here."""

    def __init__(self, *, secret: bytes, key_id: str, token_ttl: timedelta) -> None:
        if len(secret) < 32:
            raise ValueError("operations token secret must contain at least 32 bytes")
        if token_ttl <= timedelta(0):
            raise ValueError("operations token TTL must be positive")
        self._secret = secret
        self._key_id = key_id
        self._token_ttl = token_ttl

    def issue(
        self,
        context: OperationsContext,
        *,
        now: datetime | None = None,
    ) -> str:
        issued_at = now or datetime.now(UTC)
        header = {"alg": "HS256", "kid": self._key_id, "typ": "FFP-Operations"}
        payload = {
            "actor_id": str(context.actor_id),
            "tenant_id": str(context.tenant_id),
            "site_ids": sorted(str(site_id) for site_id in context.site_ids),
            "all_sites": context.all_sites,
            "permissions": sorted(permission.value for permission in context.permissions),
            "iat": int(issued_at.timestamp()),
            "exp": int((issued_at + self._token_ttl).timestamp()),
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

    def verify(
        self,
        token: str,
        *,
        now: datetime | None = None,
    ) -> OperationsContext:
        try:
            encoded_header, encoded_payload, encoded_signature = token.split(".")
        except ValueError as exc:
            raise AuthenticationError("运营凭据格式无效") from exc
        signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
        expected = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        supplied = _decode_base64url(encoded_signature)
        if not hmac.compare_digest(expected, supplied):
            raise AuthenticationError("运营凭据签名无效")
        try:
            header = json.loads(_decode_base64url(encoded_header))
            payload = json.loads(_decode_base64url(encoded_payload))
            if header != {
                "alg": "HS256",
                "kid": self._key_id,
                "typ": "FFP-Operations",
            }:
                raise AuthenticationError("运营凭据头无效")
            expires_at = datetime.fromtimestamp(payload["exp"], UTC)
            if expires_at <= (now or datetime.now(UTC)):
                raise AuthenticationError("运营凭据已过期")
            return OperationsContext(
                actor_id=UUID(payload["actor_id"]),
                tenant_id=UUID(payload["tenant_id"]),
                site_ids=frozenset(UUID(site_id) for site_id in payload["site_ids"]),
                all_sites=bool(payload["all_sites"]),
                permissions=frozenset(
                    OperationsPermission(permission)
                    for permission in payload["permissions"]
                ),
            )
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            if isinstance(exc, AuthenticationError):
                raise
            raise AuthenticationError("运营凭据载荷无效") from exc
