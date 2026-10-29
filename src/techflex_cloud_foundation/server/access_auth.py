"""Strictly separated tenant, Platform, refresh, and signed-License credentials."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import secrets
from typing import Any
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from techflex_cloud_foundation.contracts.access_control import (
    AccessCapabilities,
    LicenseDocumentV2,
    PlatformRole,
    SignedLicenseV2,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.terminal_access import (
    SignedTerminalLicense,
    TerminalLicenseDocument,
)
from techflex_cloud_foundation.platform_errors import AuthenticationError

_ACCESS_TTL = timedelta(minutes=15)
_LOCAL_UI_TEST_LICENSE = "FFP-2026-TEST-0001"


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
        raise AuthenticationError("访问凭据格式无效") from exc


def _encoded_json(value: dict[str, Any]) -> str:
    return _base64url(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"))


def _issue_hmac_token(
    *,
    secret: bytes,
    key_id: str,
    token_type: str,
    audience: str,
    payload: dict[str, Any],
) -> str:
    header = {"alg": "HS256", "kid": key_id, "typ": token_type}
    payload = {**payload, "aud": audience}
    encoded_header = _encoded_json(header)
    encoded_payload = _encoded_json(payload)
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_payload}.{_base64url(signature)}"


def _verify_hmac_token(
    token: str,
    *,
    secret: bytes,
    key_id: str,
    token_type: str,
    audience: str,
) -> dict[str, Any]:
    try:
        encoded_header, encoded_payload, encoded_signature = token.split(".")
    except ValueError as exc:
        raise AuthenticationError("访问凭据格式无效") from exc
    signing_input = f"{encoded_header}.{encoded_payload}".encode("ascii")
    expected = hmac.new(secret, signing_input, hashlib.sha256).digest()
    supplied = _decode_base64url(encoded_signature)
    if not hmac.compare_digest(expected, supplied):
        raise AuthenticationError("访问凭据签名无效")
    try:
        header = json.loads(_decode_base64url(encoded_header))
        payload = json.loads(_decode_base64url(encoded_payload))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthenticationError("访问凭据载荷无效") from exc
    if header != {"alg": "HS256", "kid": key_id, "typ": token_type}:
        raise AuthenticationError("访问凭据类型无效")
    if not isinstance(payload, dict) or payload.get("aud") != audience:
        raise AuthenticationError("访问凭据受众无效")
    return payload


@dataclass(frozen=True, slots=True)
class TenantAccessContext:
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    hardware_id: str
    client_installation_id: UUID
    token_version: int
    capabilities: AccessCapabilities
    expires_at: datetime


class TenantAccessTokenIssuer:
    token_type = "tenant_access"
    audience = "feetforceplate-api"

    def __init__(self, *, secret: bytes, key_id: str) -> None:
        if len(secret) < 32:
            raise ValueError("tenant token secret must contain at least 32 bytes")
        if not key_id:
            raise ValueError("tenant token key_id is required")
        self._secret = secret
        self._key_id = key_id

    def issue(
        self,
        *,
        tenant_id: UUID,
        account_id: UUID,
        license_id: UUID,
        hardware_id: str,
        client_installation_id: UUID,
        token_version: int,
        capabilities: AccessCapabilities,
        now: datetime | None = None,
    ) -> str:
        issued_at = now or datetime.now(UTC)
        return _issue_hmac_token(
            secret=self._secret,
            key_id=self._key_id,
            token_type=self.token_type,
            audience=self.audience,
            payload={
                "tenant_id": str(tenant_id),
                "account_id": str(account_id),
                # CP-03 realm contract: the tenant principal's operator id is
                # carried under the canonical "sub" claim so the foundation
                # RealmTokenAuthority can re-verify captured tokens.
                "sub": str(account_id),
                "license_id": str(license_id),
                "hardware_id": hardware_id,
                "client_installation_id": str(client_installation_id),
                "token_version": token_version,
                "capabilities": capabilities.model_dump(mode="json"),
                "iat": int(issued_at.timestamp()),
                "exp": int((issued_at + _ACCESS_TTL).timestamp()),
                "jti": str(uuid4()),
            },
        )

    def verify(self, token: str, *, now: datetime | None = None) -> TenantAccessContext:
        payload = _verify_hmac_token(
            token,
            secret=self._secret,
            key_id=self._key_id,
            token_type=self.token_type,
            audience=self.audience,
        )
        try:
            context = TenantAccessContext(
                tenant_id=UUID(payload["tenant_id"]),
                account_id=UUID(payload["account_id"]),
                license_id=UUID(payload["license_id"]),
                hardware_id=str(payload["hardware_id"]),
                client_installation_id=UUID(payload["client_installation_id"]),
                token_version=int(payload["token_version"]),
                capabilities=AccessCapabilities.model_validate(payload["capabilities"]),
                expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("租户访问凭据载荷无效") from exc
        if context.expires_at <= (now or datetime.now(UTC)):
            raise AuthenticationError("租户访问凭据已过期")
        return context


@dataclass(frozen=True, slots=True)
class PlatformAccessContext:
    platform_identity_id: UUID
    roles: frozenset[PlatformRole]
    token_version: int
    expires_at: datetime


class PlatformAccessTokenIssuer:
    token_type = "platform_access"
    audience = "feetforceplate-platform"

    def __init__(self, *, secret: bytes, key_id: str) -> None:
        if len(secret) < 32:
            raise ValueError("platform token secret must contain at least 32 bytes")
        if not key_id:
            raise ValueError("platform token key_id is required")
        self._secret = secret
        self._key_id = key_id

    def issue(
        self,
        *,
        platform_identity_id: UUID,
        roles: tuple[PlatformRole, ...],
        token_version: int,
        now: datetime | None = None,
    ) -> str:
        if not roles or len(set(roles)) != len(roles):
            raise ValueError("platform roles must be non-empty and unique")
        issued_at = now or datetime.now(UTC)
        return _issue_hmac_token(
            secret=self._secret,
            key_id=self._key_id,
            token_type=self.token_type,
            audience=self.audience,
            payload={
                "platform_identity_id": str(platform_identity_id),
                "roles": sorted(role.value for role in roles),
                "token_version": token_version,
                "iat": int(issued_at.timestamp()),
                "exp": int((issued_at + _ACCESS_TTL).timestamp()),
                "jti": str(uuid4()),
            },
        )

    def verify(self, token: str, *, now: datetime | None = None) -> PlatformAccessContext:
        payload = _verify_hmac_token(
            token,
            secret=self._secret,
            key_id=self._key_id,
            token_type=self.token_type,
            audience=self.audience,
        )
        try:
            roles = tuple(PlatformRole(role) for role in payload["roles"])
            if not roles or len(set(roles)) != len(roles):
                raise ValueError("invalid roles")
            context = PlatformAccessContext(
                platform_identity_id=UUID(payload["platform_identity_id"]),
                roles=frozenset(roles),
                token_version=int(payload["token_version"]),
                expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("平台访问凭据载荷无效") from exc
        if context.expires_at <= (now or datetime.now(UTC)):
            raise AuthenticationError("平台访问凭据已过期")
        return context


@dataclass(frozen=True, slots=True)
class TerminalAccessContext:
    tenant_id: UUID
    account_id: UUID
    license_id: UUID
    client_installation_id: UUID
    expires_at: datetime


class TerminalAccessTokenIssuer:
    """Terminal bearer tokens; a distinct type and audience from tenant tokens.

    Terminal credentials are not hardware-bound. The hardware-scoped routes
    (capture grants, migration permits, identity recovery, report copies) do
    not accept them; since RAY-728 the subject, consent and session routes do.
    """

    token_type = "terminal_access"
    audience = "feetforceplate-terminal"

    def __init__(self, *, secret: bytes, key_id: str) -> None:
        if len(secret) < 32:
            raise ValueError("terminal token secret must contain at least 32 bytes")
        if not key_id:
            raise ValueError("terminal token key_id is required")
        self._secret = secret
        self._key_id = key_id

    def issue(
        self,
        *,
        tenant_id: UUID,
        account_id: UUID,
        license_id: UUID,
        client_installation_id: UUID,
        now: datetime | None = None,
    ) -> str:
        issued_at = now or datetime.now(UTC)
        return _issue_hmac_token(
            secret=self._secret,
            key_id=self._key_id,
            token_type=self.token_type,
            audience=self.audience,
            payload={
                "tenant_id": str(tenant_id),
                "account_id": str(account_id),
                "sub": str(client_installation_id),
                "license_id": str(license_id),
                "client_installation_id": str(client_installation_id),
                "iat": int(issued_at.timestamp()),
                "exp": int((issued_at + _ACCESS_TTL).timestamp()),
                "jti": str(uuid4()),
            },
        )

    def verify(self, token: str, *, now: datetime | None = None) -> TerminalAccessContext:
        payload = _verify_hmac_token(
            token,
            secret=self._secret,
            key_id=self._key_id,
            token_type=self.token_type,
            audience=self.audience,
        )
        try:
            context = TerminalAccessContext(
                tenant_id=UUID(payload["tenant_id"]),
                account_id=UUID(payload["account_id"]),
                license_id=UUID(payload["license_id"]),
                client_installation_id=UUID(payload["client_installation_id"]),
                expires_at=datetime.fromtimestamp(payload["exp"], UTC),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise AuthenticationError("终端访问凭据载荷无效") from exc
        if context.expires_at <= (now or datetime.now(UTC)):
            raise AuthenticationError("终端访问凭据已过期")
        return context


@dataclass(frozen=True, slots=True)
class IssuedRefreshToken:
    raw_token: str
    token_hash: bytes


class RefreshTokenFactory:
    def __init__(self, *, digest_key: bytes) -> None:
        if len(digest_key) < 32:
            raise ValueError("refresh digest key must contain at least 32 bytes")
        self._digest_key = digest_key

    def issue(self) -> IssuedRefreshToken:
        raw_token = secrets.token_urlsafe(32)
        return IssuedRefreshToken(raw_token, self.digest(raw_token))

    def digest(self, raw_token: str) -> bytes:
        return hmac.new(
            self._digest_key,
            raw_token.encode("utf-8"),
            hashlib.sha256,
        ).digest()


class TerminalRefreshTokenFactory:
    """Refresh tokens derived from their random session id with a server key.

    Derivation lets a rotation replayed inside the grace window return the
    identical successor token without the plaintext ever being stored.
    """

    _DERIVATION_LABEL = b"ffp-terminal-refresh/1|"

    def __init__(self, *, digest_key: bytes) -> None:
        if len(digest_key) < 32:
            raise ValueError("terminal refresh key must contain at least 32 bytes")
        self._digest_key = digest_key

    def derive(self, refresh_session_id: UUID) -> IssuedRefreshToken:
        raw = _base64url(
            hmac.new(
                self._digest_key,
                self._DERIVATION_LABEL + refresh_session_id.bytes,
                hashlib.sha256,
            ).digest()
        )
        return IssuedRefreshToken(raw, self.digest(raw))

    def digest(self, raw_token: str) -> bytes:
        return hmac.new(
            self._digest_key,
            b"ffp-terminal-refresh-digest/1|" + raw_token.encode("utf-8"),
            hashlib.sha256,
        ).digest()


class LicenseDocumentSigner:
    def __init__(
        self,
        *,
        key_id: str,
        public_keys: Mapping[str, bytes],
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        if not key_id:
            raise ValueError("license key_id is required")
        if not public_keys:
            raise ValueError("at least one License public key is required")
        self._key_id = key_id
        self._private_key = private_key
        self._public_keys = {
            identifier: Ed25519PublicKey.from_public_bytes(value)
            for identifier, value in public_keys.items()
        }

    def sign(self, document: LicenseDocumentV2) -> SignedLicenseV2:
        if self._private_key is None:
            raise RuntimeError("License private key is unavailable")
        signature = self._private_key.sign(canonical_json_bytes(document))
        return SignedLicenseV2(
            document=document,
            key_id=self._key_id,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    def sign_terminal(self, document: TerminalLicenseDocument) -> SignedTerminalLicense:
        if self._private_key is None:
            raise RuntimeError("License private key is unavailable")
        signature = self._private_key.sign(canonical_json_bytes(document))
        return SignedTerminalLicense(
            document=document,
            key_id=self._key_id,
            signature=base64.b64encode(signature).decode("ascii"),
        )

    def verify(self, bundle: SignedLicenseV2) -> LicenseDocumentV2:
        public_key = self._public_keys.get(bundle.key_id)
        if public_key is None:
            raise ValueError("License signature key is unknown")
        try:
            signature = base64.b64decode(bundle.signature, validate=True)
            public_key.verify(signature, canonical_json_bytes(bundle.document))
        except (binascii.Error, InvalidSignature) as exc:
            raise ValueError("License signature is invalid") from exc
        return bundle.document


def reject_local_test_license(value: str) -> None:
    if hmac.compare_digest(value.strip(), _LOCAL_UI_TEST_LICENSE):
        raise AuthenticationError("激活凭据无效")


__all__ = [
    "IssuedRefreshToken",
    "LicenseDocumentSigner",
    "PlatformAccessContext",
    "PlatformAccessTokenIssuer",
    "RefreshTokenFactory",
    "TenantAccessContext",
    "TenantAccessTokenIssuer",
    "TerminalAccessContext",
    "TerminalAccessTokenIssuer",
    "TerminalRefreshTokenFactory",
    "reject_local_test_license",
]
