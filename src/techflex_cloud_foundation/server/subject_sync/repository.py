"""Subject sync persistence ports and the in-memory implementation (RAY-907).

Subject revisions are assigned by the store itself (migration 0017 triggers in
PostgreSQL; ``InMemoryPlatformRepository.touch_subject`` here), so the
existing subject and consent writes bump them too. A subject writer locks its
idempotency key and then the subject row, the same order the existing writes
take (row, then the revision counter), so writers never deadlock.

Identity profiles are returned still encrypted; the service decrypts them.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from uuid import UUID

from techflex_cloud_foundation.contracts.cloud import ProfileValue
from techflex_cloud_foundation.contracts.subject_sync import (
    SubjectConsentRecord,
    SubjectEditableStatus,
    SubjectExternalIdentifier,
    SubjectStatus,
    SubjectTag,
)
from techflex_cloud_foundation.server.repository import (
    ExternalIdentifierRecord,
    InMemoryPlatformRepository,
)
from techflex_cloud_foundation.server.subject_service import ProtectedIdentifier


@dataclass(frozen=True, slots=True)
class StoredIdentity:
    ciphertext: bytes
    nonce: bytes
    key_version: str


@dataclass(frozen=True, slots=True)
class StoredSubject:
    subject_uuid: UUID
    revision: int
    status: SubjectStatus
    merged_into_subject_uuid: UUID | None
    external_identifier: SubjectExternalIdentifier | None
    identity: StoredIdentity | None
    analysis_profile: dict[str, ProfileValue]
    profile_schema_version: str
    tag_ids: tuple[UUID, ...]
    consents: tuple[SubjectConsentRecord, ...]
    created_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class NumberChange:
    issuer: str
    id_type: str
    protected: ProtectedIdentifier


@dataclass(frozen=True, slots=True)
class IdentityChange:
    protected: StoredIdentity
    # None when the new profile has no display name: not name-searchable.
    name_lookup_hmac: bytes | None


@dataclass(frozen=True, slots=True)
class SubjectChanges:
    number: NumberChange | None = None
    identity: IdentityChange | None = None
    # The complete merged profile; set together with its schema version.
    analysis_profile: dict[str, ProfileValue] | None = None
    profile_schema_version: str | None = None
    tag_ids: tuple[UUID, ...] | None = None
    status: SubjectEditableStatus | None = None


@dataclass(frozen=True, slots=True)
class IdempotencyEntry:
    """A stored key; the response holds identifiers only, never identity."""

    request_sha256: str
    response_status: int
    response: dict[str, Any]


@dataclass(frozen=True, slots=True)
class NumberOwner:
    subject_uuid: UUID
    external_id_masked: str


@dataclass(frozen=True, slots=True)
class NameSearchAudit:
    actor_id: UUID
    correlation_id: UUID | None


class SubjectWriteTransaction(Protocol):
    async def lock_key(self, scope: str, idempotency_key: str) -> None: ...

    async def idempotency(self, scope: str, idempotency_key: str) -> IdempotencyEntry | None: ...

    async def save_idempotency(
        self, scope: str, idempotency_key: str, entry: IdempotencyEntry, resource_id: UUID
    ) -> None: ...

    async def lock_subject(self, subject_uuid: UUID) -> StoredSubject | None: ...

    async def unknown_tags(self, tag_ids: tuple[UUID, ...]) -> tuple[UUID, ...]: ...

    async def number_owner(
        self, issuer: str, id_type: str, normalized_hmac: bytes
    ) -> NumberOwner | None: ...

    async def apply(self, subject_uuid: UUID, changes: SubjectChanges) -> StoredSubject: ...


class TagWriteTransaction(Protocol):
    async def idempotency(self, scope: str, idempotency_key: str) -> IdempotencyEntry | None: ...

    async def save_idempotency(
        self, scope: str, idempotency_key: str, entry: IdempotencyEntry, resource_id: UUID
    ) -> None: ...

    async def tag(self, tag_id: UUID) -> tuple[SubjectTag, str] | None: ...

    async def tag_by_key(self, name_key: str) -> SubjectTag | None: ...

    async def insert_tag(
        self, *, tag_id: UUID, name: str, name_key: str, created_by: UUID, created_at: datetime
    ) -> SubjectTag: ...


class SubjectSyncRepository(Protocol):
    def subject_writer(
        self, tenant_id: UUID
    ) -> AbstractAsyncContextManager[SubjectWriteTransaction]: ...

    def tag_writer(
        self, tenant_id: UUID
    ) -> AbstractAsyncContextManager[TagWriteTransaction]: ...

    async def changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[StoredSubject, ...]: ...

    async def search_by_name(
        self,
        tenant_id: UUID,
        name_lookup_hmac: bytes | None,
        *,
        limit: int,
        audit: NameSearchAudit,
    ) -> tuple[StoredSubject, ...]: ...

    async def tag_changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[SubjectTag, ...]: ...


_SEARCHABLE = (SubjectStatus.ACTIVE, SubjectStatus.ARCHIVED)


class _InMemoryTenant:
    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.keys: dict[tuple[str, str], IdempotencyEntry] = {}
        self.tags: dict[UUID, tuple[SubjectTag, str]] = {}
        self.last_tag_revision = 0


class _InMemoryWriter:
    """Shared by both writers. Every check runs before ``apply`` or
    ``insert_tag`` writes, so a raised error leaves nothing behind."""

    def __init__(self, store: InMemorySubjectSyncRepository, tenant_id: UUID) -> None:
        self._store = store
        self._tenant_id = tenant_id
        self._tenant = store._tenant(tenant_id)

    async def lock_key(self, scope: str, idempotency_key: str) -> None:
        return None

    async def idempotency(self, scope: str, idempotency_key: str) -> IdempotencyEntry | None:
        return self._tenant.keys.get((scope, idempotency_key))

    async def save_idempotency(
        self, scope: str, idempotency_key: str, entry: IdempotencyEntry, resource_id: UUID
    ) -> None:
        self._tenant.keys[(scope, idempotency_key)] = entry

    async def lock_subject(self, subject_uuid: UUID) -> StoredSubject | None:
        return self._store._stored(self._tenant_id, subject_uuid)

    async def unknown_tags(self, tag_ids: tuple[UUID, ...]) -> tuple[UUID, ...]:
        return tuple(tag_id for tag_id in tag_ids if tag_id not in self._tenant.tags)

    async def number_owner(
        self, issuer: str, id_type: str, normalized_hmac: bytes
    ) -> NumberOwner | None:
        record = self._store._platform._external_identifiers.get(
            (self._tenant_id, issuer, id_type, normalized_hmac)
        )
        if record is None:
            return None
        return NumberOwner(record.subject_uuid, record.masked_value)

    async def apply(self, subject_uuid: UUID, changes: SubjectChanges) -> Any:
        platform = self._store._platform
        key = (self._tenant_id, subject_uuid)
        if changes.number is not None:
            for index, record in list(platform._external_identifiers.items()):
                if record.tenant_id == self._tenant_id and record.subject_uuid == subject_uuid:
                    platform._superseded_identifiers.append(record)
                    del platform._external_identifiers[index]
            protected = changes.number.protected
            platform._external_identifiers[(
                self._tenant_id, changes.number.issuer, changes.number.id_type,
                protected.normalized_hmac,
            )] = ExternalIdentifierRecord(
                self._tenant_id, subject_uuid, changes.number.issuer, changes.number.id_type,
                protected.normalized_hmac, protected.encrypted_value,
                protected.encryption_nonce, protected.masked_value, protected.key_version,
            )
        if changes.identity is not None:
            identity = changes.identity.protected
            platform._identity_profiles[key] = (
                identity.ciphertext, identity.nonce, identity.key_version
            )
            if changes.identity.name_lookup_hmac is None:
                platform._name_lookup_hmacs.pop(key, None)
            else:
                platform._name_lookup_hmacs[key] = changes.identity.name_lookup_hmac
        if changes.analysis_profile is not None:
            platform._subject_profiles[key] = dict(changes.analysis_profile)
        if changes.tag_ids is not None:
            platform._subject_tags[key] = changes.tag_ids
        state: dict[str, Any] = {}
        if changes.profile_schema_version is not None:
            state["profile_schema_version"] = changes.profile_schema_version
        if changes.status is not None:
            state["status"] = changes.status.value
        platform.touch_subject(self._tenant_id, subject_uuid, **state)
        return self._store._stored(self._tenant_id, subject_uuid)

    async def tag(self, tag_id: UUID) -> tuple[SubjectTag, str] | None:
        return self._tenant.tags.get(tag_id)

    async def tag_by_key(self, name_key: str) -> SubjectTag | None:
        for tag, key in self._tenant.tags.values():
            if key == name_key:
                return tag
        return None

    async def insert_tag(
        self, *, tag_id: UUID, name: str, name_key: str, created_by: UUID, created_at: datetime
    ) -> SubjectTag:
        self._tenant.last_tag_revision += 1
        tag = SubjectTag(
            tag_id=tag_id, name=name, created_at=created_at,
            revision=self._tenant.last_tag_revision,
        )
        self._tenant.tags[tag_id] = (tag, name_key)
        return tag


class InMemorySubjectSyncRepository:
    """Reads and writes the subjects of an ``InMemoryPlatformRepository``."""

    def __init__(self, platform: InMemoryPlatformRepository) -> None:
        self._platform = platform
        self._tenants: dict[UUID, _InMemoryTenant] = {}

    def _tenant(self, tenant_id: UUID) -> _InMemoryTenant:
        return self._tenants.setdefault(tenant_id, _InMemoryTenant())

    def _stored(self, tenant_id: UUID, subject_uuid: UUID) -> StoredSubject | None:
        platform = self._platform
        key = (tenant_id, subject_uuid)
        state = platform._subject_states.get(key)
        if key not in platform._subjects or state is None:
            return None
        number = next(
            (
                record for record in platform._external_identifiers.values()
                if record.tenant_id == tenant_id and record.subject_uuid == subject_uuid
            ),
            None,
        )
        identity = platform._identity_profiles.get(key)
        consents = sorted(
            (
                record for record in platform._consents.values()
                if record.tenant_id == tenant_id and record.subject_uuid == subject_uuid
            ),
            key=lambda record: (record.granted_at, record.consent_record_id),
        )
        return StoredSubject(
            subject_uuid=subject_uuid,
            revision=state.revision,
            status=SubjectStatus(state.status),
            merged_into_subject_uuid=state.merged_into_subject_uuid,
            external_identifier=None if number is None else SubjectExternalIdentifier(
                external_identifier_id=number.external_identifier_id,
                issuer=number.issuer,
                id_type=number.id_type,
                external_id_masked=number.masked_value,
            ),
            identity=None if identity is None else StoredIdentity(*identity),
            analysis_profile=dict(platform._subject_profiles.get(key, {})),
            profile_schema_version=state.profile_schema_version,
            tag_ids=tuple(sorted(platform._subject_tags.get(key, ()))),
            consents=tuple(
                SubjectConsentRecord(
                    consent_record_id=record.consent_record_id,
                    policy_version=record.policy_version,
                    purpose_codes=record.purpose_codes,
                    data_categories=record.data_categories,
                    evidence_type=record.evidence_type,
                    granted_at=record.granted_at,
                    revoked_at=record.revoked_at,
                    revocation_reason_code=record.revocation_reason_code,
                )
                for record in consents
            ),
            created_at=state.created_at,
            updated_at=state.updated_at,
        )

    def _all(self, tenant_id: UUID) -> list[StoredSubject]:
        rows = (
            self._stored(tenant, subject_uuid)
            for tenant, subject_uuid in self._platform._subjects
            if tenant == tenant_id
        )
        return sorted((row for row in rows if row is not None), key=lambda row: row.revision)

    @asynccontextmanager
    async def subject_writer(self, tenant_id: UUID) -> AsyncIterator[_InMemoryWriter]:
        async with self._tenant(tenant_id).lock:
            yield _InMemoryWriter(self, tenant_id)

    tag_writer = subject_writer

    async def changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[StoredSubject, ...]:
        return tuple(
            row for row in self._all(tenant_id) if row.revision > after_revision
        )[:limit]

    async def search_by_name(
        self,
        tenant_id: UUID,
        name_lookup_hmac: bytes | None,
        *,
        limit: int,
        audit: NameSearchAudit,
    ) -> tuple[StoredSubject, ...]:
        matches = tuple(
            row for row in self._all(tenant_id)
            if name_lookup_hmac is not None
            and row.status in _SEARCHABLE
            and self._platform._name_lookup_hmacs.get((tenant_id, row.subject_uuid))
            == name_lookup_hmac
        )[:limit]
        self._platform.subject_audits.append({
            "tenant_id": tenant_id,
            "actor_id": audit.actor_id,
            "action": "subject.search-by-name",
            "safe_context": {"result_count": len(matches)},
        })
        return matches

    async def tag_changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[SubjectTag, ...]:
        tags = sorted(
            (tag for tag, _ in self._tenant(tenant_id).tags.values()
             if tag.revision > after_revision),
            key=lambda tag: tag.revision,
        )
        return tuple(tags[:limit])


__all__ = [
    "IdempotencyEntry",
    "IdentityChange",
    "InMemorySubjectSyncRepository",
    "NameSearchAudit",
    "NumberChange",
    "NumberOwner",
    "StoredIdentity",
    "StoredSubject",
    "SubjectChanges",
    "SubjectSyncRepository",
    "SubjectWriteTransaction",
    "TagWriteTransaction",
]
