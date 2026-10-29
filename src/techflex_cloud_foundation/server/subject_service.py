from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from typing import Any, cast
import unicodedata

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes, canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ConsentResponse,
    ConsentRevokeRequest,
    IdentityProfileInput,
    SubjectCreateRequest,
    SubjectResolveRequest,
    SubjectSummary,
)
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.principal import (
    IngestionPrincipal,
    coerce_ingestion_principal,
)


@dataclass(frozen=True, slots=True)
class ProtectedIdentifier:
    normalized_hmac: bytes
    encrypted_value: bytes
    encryption_nonce: bytes
    masked_value: str
    key_version: str


@dataclass(frozen=True, slots=True)
class ProtectedIdentityProfile:
    ciphertext: bytes
    nonce: bytes
    key_version: str


class IdentityProtector:
    def __init__(self, *, encryption_key: bytes, lookup_hmac_key: bytes, key_version: str) -> None:
        if len(encryption_key) != 32:
            raise ValueError("identity encryption key must contain 32 bytes")
        if len(lookup_hmac_key) < 32:
            raise ValueError("identity HMAC key must contain at least 32 bytes")
        self._cipher = AESGCM(encryption_key)
        self._lookup_hmac_key = lookup_hmac_key
        self.key_version = key_version

    @staticmethod
    def normalize(value: str) -> str:
        return unicodedata.normalize("NFKC", value).strip().casefold()

    def lookup_digest(self, value: str, *, tenant_id: str, issuer: str, id_type: str) -> bytes:
        normalized = self.normalize(value)
        scoped_value = f"{tenant_id}\x1f{issuer}\x1f{id_type}\x1f{normalized}".encode()
        return hmac.new(self._lookup_hmac_key, scoped_value, hashlib.sha256).digest()

    def protect(
        self, value: str, *, tenant_id: str, issuer: str, id_type: str
    ) -> ProtectedIdentifier:
        normalized = self.normalize(value)
        nonce = os.urandom(12)
        associated_data = f"{tenant_id}\x1f{issuer}\x1f{id_type}".encode()
        encrypted = self._cipher.encrypt(nonce, normalized.encode("utf-8"), associated_data)
        visible = normalized[-4:]
        masked = "*" * max(0, len(normalized) - len(visible)) + visible
        return ProtectedIdentifier(
            normalized_hmac=self.lookup_digest(
                value, tenant_id=tenant_id, issuer=issuer, id_type=id_type
            ),
            encrypted_value=encrypted,
            encryption_nonce=nonce,
            masked_value=masked,
            key_version=self.key_version,
        )

    def protect_identity_profile(
        self, value: Any, *, tenant_id: str, subject_uuid: str
    ) -> ProtectedIdentityProfile:
        nonce = os.urandom(12)
        associated_data = f"{tenant_id}\x1f{subject_uuid}\x1fidentity-profile".encode()
        ciphertext = self._cipher.encrypt(nonce, canonical_json_bytes(value), associated_data)
        return ProtectedIdentityProfile(ciphertext, nonce, self.key_version)

    def unprotect_identity_profile(
        self,
        ciphertext: bytes,
        nonce: bytes,
        key_version: str,
        *,
        tenant_id: str,
        subject_uuid: str,
    ) -> IdentityProfileInput:
        if key_version != self.key_version:
            raise ValueError("unsupported identity key version")
        associated_data = f"{tenant_id}\x1f{subject_uuid}\x1fidentity-profile".encode()
        plaintext = self._cipher.decrypt(nonce, ciphertext, associated_data)
        return IdentityProfileInput.model_validate(json.loads(plaintext))


class SubjectConsentService:
    def __init__(self, repository: Any, identity_protector: IdentityProtector) -> None:
        self._repository = repository
        self._identity = identity_protector

    async def resolve(
        self, context: IngestionPrincipal | TerminalContext, request: SubjectResolveRequest
    ) -> SubjectSummary | None:
        context = coerce_ingestion_principal(context)
        context.ensure_active()
        return cast(
            "SubjectSummary | None",
            await self._repository.resolve_subject(
                context,
                request.issuer,
                request.id_type,
                self._identity.lookup_digest(
                    request.external_id,
                    tenant_id=str(context.tenant_id),
                    issuer=request.issuer,
                    id_type=request.id_type,
                ),
            ),
        )

    async def create_subject(
        self,
        context: IngestionPrincipal | TerminalContext,
        request: SubjectCreateRequest,
        idempotency_key: str,
    ) -> SubjectSummary:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        protected = None
        protected_identity = None
        if request.external_identifier is not None:
            external = request.external_identifier
            protected = self._identity.protect(
                external.external_id,
                tenant_id=str(context.tenant_id),
                issuer=external.issuer,
                id_type=external.id_type,
            )
        if request.identity_profile is not None:
            protected_identity = self._identity.protect_identity_profile(
                request.identity_profile,
                tenant_id=str(context.tenant_id),
                subject_uuid=str(request.subject_uuid),
            )
        return cast(
            "SubjectSummary",
            await self._repository.create_subject(
                context,
                request,
                normalized_hmac=None if protected is None else protected.normalized_hmac,
                encrypted_value=None if protected is None else protected.encrypted_value,
                encryption_nonce=None if protected is None else protected.encryption_nonce,
                masked_value=None if protected is None else protected.masked_value,
                key_version=None if protected is None else protected.key_version,
                identity_ciphertext=(
                    None if protected_identity is None else protected_identity.ciphertext
                ),
                identity_nonce=None if protected_identity is None else protected_identity.nonce,
                identity_key_version=(
                    None if protected_identity is None else protected_identity.key_version
                ),
                idempotency_key=idempotency_key,
            ),
        )

    async def create_consent(
        self,
        context: IngestionPrincipal | TerminalContext,
        request: ConsentCreateRequest,
        idempotency_key: str,
    ) -> ConsentResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        return cast(
            "ConsentResponse",
            await self._repository.create_consent(
                context, request, canonical_sha256(request), idempotency_key
            ),
        )

    async def revoke_consent(
        self,
        context: IngestionPrincipal | TerminalContext,
        consent_record_id: Any,
        request: ConsentRevokeRequest,
        idempotency_key: str,
    ) -> ConsentResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_active()
        digest = canonical_sha256(
            {"consent_record_id": str(consent_record_id), "revocation": request}
        )
        return cast(
            "ConsentResponse",
            await self._repository.revoke_consent(
                context, consent_record_id, request, digest, idempotency_key
            ),
        )
