"""PostgreSQL persistence for institutional subject sync (RAY-907).

Uses the tenant role pool, as the existing subject and consent routes do,
inside an RLS-scoped tenant transaction. Revisions come from the migration
0017 triggers: every write below touches the subject row, which takes the
tenant's next revision and holds the counter row lock until commit.

Lock order: the idempotency key (advisory), then the subject row, then (via
trigger) the counter. The existing subject and consent writes take the row
before the counter as well, so no two writers wait on each other in reverse.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
import json
from typing import Any
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.cloud import ProfileValue
from techflex_cloud_foundation.contracts.subject_sync import (
    SubjectConsentRecord,
    SubjectExternalIdentifier,
    SubjectStatus,
    SubjectTag,
)
from techflex_cloud_foundation.server.postgres import tenant_transaction

from .repository import (
    IdempotencyEntry,
    NameSearchAudit,
    NumberOwner,
    StoredIdentity,
    StoredSubject,
    SubjectChanges,
)

_IDEMPOTENCY_TTL = timedelta(days=7)

# {where} filters subject.subjects s; results are ordered by revision.
_SELECT_SUBJECTS = """
SELECT s.subject_uuid, s.revision, s.status, s.merged_into_subject_uuid,
       s.created_at, s.updated_at,
       e.external_identifier_id, e.issuer, e.id_type, e.masked_value,
       i.identity_ciphertext, i.encryption_nonce, i.key_version AS identity_key_version,
       p.profile_json, p.schema_version,
       ARRAY(
           SELECT t.tag_id FROM subject.subject_tags t
           WHERE t.tenant_id = s.tenant_id AND t.subject_uuid = s.subject_uuid
           ORDER BY t.tag_id
       ) AS tag_ids,
       COALESCE((
           SELECT jsonb_agg(jsonb_build_object(
               'consent_record_id', c.consent_record_id,
               'policy_version', c.policy_version,
               'purpose_codes', to_jsonb(c.purpose_codes),
               'data_categories', to_jsonb(c.data_categories),
               'evidence_type', c.evidence_type,
               'granted_at', c.granted_at,
               'revoked_at', c.revoked_at,
               'revocation_reason_code', c.revocation_reason_code
           ) ORDER BY c.granted_at, c.consent_record_id)
           FROM subject.consents c
           WHERE c.tenant_id = s.tenant_id AND c.subject_uuid = s.subject_uuid
       ), '[]'::jsonb) AS consents
FROM subject.subjects s
LEFT JOIN LATERAL (
    SELECT x.external_identifier_id, x.issuer, x.id_type, x.masked_value
    FROM subject.external_identifiers x
    WHERE x.tenant_id = s.tenant_id AND x.subject_uuid = s.subject_uuid
      AND x.status = 'ACTIVE'
    ORDER BY x.created_at DESC, x.external_identifier_id
    LIMIT 1
) e ON true
LEFT JOIN subject.identity_profiles i
  ON i.tenant_id = s.tenant_id AND i.subject_uuid = s.subject_uuid
LEFT JOIN subject.analysis_profiles p
  ON p.tenant_id = s.tenant_id AND p.subject_uuid = s.subject_uuid
WHERE {where}
ORDER BY s.revision
"""


def _json(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _stored(row: Any) -> StoredSubject:
    profile = _json(row["profile_json"]) or {}
    return StoredSubject(
        subject_uuid=row["subject_uuid"],
        revision=row["revision"],
        status=SubjectStatus(row["status"]),
        merged_into_subject_uuid=row["merged_into_subject_uuid"],
        external_identifier=(
            None if row["external_identifier_id"] is None else SubjectExternalIdentifier(
                external_identifier_id=row["external_identifier_id"],
                issuer=row["issuer"],
                id_type=row["id_type"],
                external_id_masked=row["masked_value"],
            )
        ),
        identity=(
            None if row["identity_ciphertext"] is None else StoredIdentity(
                bytes(row["identity_ciphertext"]),
                bytes(row["encryption_nonce"]),
                row["identity_key_version"],
            )
        ),
        analysis_profile={
            key: ProfileValue.model_validate(value) for key, value in profile.items()
        },
        profile_schema_version=row["schema_version"] or "analysis-profile/1",
        tag_ids=tuple(row["tag_ids"]),
        consents=tuple(
            SubjectConsentRecord.model_validate(item) for item in _json(row["consents"])
        ),
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


def _tag(row: Any) -> SubjectTag:
    return SubjectTag(
        tag_id=row["tag_id"], name=row["name"], created_at=row["created_at"],
        revision=row["revision"],
    )


class _PostgresWriter:
    def __init__(self, connection: Any, tenant_id: UUID) -> None:
        self._connection = connection
        self._tenant_id = tenant_id

    async def lock_key(self, scope: str, idempotency_key: str) -> None:
        await self._connection.execute(
            "SELECT pg_advisory_xact_lock(hashtextextended("
            "'idempotency:' || $1::uuid::text || ':' || $2 || ':' || $3, 0))",
            self._tenant_id, scope, idempotency_key,
        )

    async def idempotency(self, scope: str, idempotency_key: str) -> IdempotencyEntry | None:
        row = await self._connection.fetchrow(
            "SELECT request_sha256,response_status,response_json FROM ops.idempotency_keys "
            "WHERE tenant_id=$1 AND scope=$2 AND idempotency_key=$3",
            self._tenant_id, scope, idempotency_key,
        )
        if row is None:
            return None
        return IdempotencyEntry(
            request_sha256=row["request_sha256"],
            response_status=row["response_status"],
            response=_json(row["response_json"]),
        )

    async def save_idempotency(
        self, scope: str, idempotency_key: str, entry: IdempotencyEntry, resource_id: UUID
    ) -> None:
        await self._connection.execute(
            """INSERT INTO ops.idempotency_keys (
                   idempotency_record_id, tenant_id, scope, idempotency_key,
                   request_sha256, response_status, response_json,
                   resource_type, resource_id, expires_at
               ) VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,now()+$10::interval)""",
            uuid4(), self._tenant_id, scope, idempotency_key, entry.request_sha256,
            entry.response_status, json.dumps(entry.response, separators=(",", ":"), ensure_ascii=False),
            "subject_tag" if "tag_id" in entry.response else "subject",
            resource_id, _IDEMPOTENCY_TTL,
        )

    async def _subject(self, subject_uuid: UUID) -> StoredSubject | None:
        row = await self._connection.fetchrow(
            _SELECT_SUBJECTS.format(where="s.subject_uuid = $1"), subject_uuid
        )
        return None if row is None else _stored(row)

    async def lock_subject(self, subject_uuid: UUID) -> StoredSubject | None:
        locked = await self._connection.fetchval(
            "SELECT subject_uuid FROM subject.subjects WHERE subject_uuid=$1 FOR UPDATE",
            subject_uuid,
        )
        if locked is None:
            return None
        # Take the revision counter now (row, then counter, as everywhere), not
        # at the first write: subject creation holds it before inserting its
        # number, so the number and tag checks below see every committed
        # writer and two writers of one number cannot both pass them.
        await self._connection.execute(
            "INSERT INTO subject.subject_revision_counters (tenant_id) VALUES ($1) "
            "ON CONFLICT (tenant_id) DO NOTHING",
            self._tenant_id,
        )
        await self._connection.execute(
            "SELECT last_revision FROM subject.subject_revision_counters "
            "WHERE tenant_id=$1 FOR UPDATE",
            self._tenant_id,
        )
        return await self._subject(subject_uuid)

    async def unknown_tags(self, tag_ids: tuple[UUID, ...]) -> tuple[UUID, ...]:
        known = {
            row["tag_id"] for row in await self._connection.fetch(
                "SELECT tag_id FROM subject.tags WHERE tag_id = ANY($1::uuid[])",
                list(tag_ids),
            )
        }
        return tuple(tag_id for tag_id in tag_ids if tag_id not in known)

    async def number_owner(
        self, issuer: str, id_type: str, normalized_hmac: bytes
    ) -> NumberOwner | None:
        row = await self._connection.fetchrow(
            "SELECT subject_uuid, masked_value FROM subject.external_identifiers "
            "WHERE issuer=$1 AND id_type=$2 AND normalized_hmac=$3 AND status='ACTIVE'",
            issuer, id_type, normalized_hmac,
        )
        return None if row is None else NumberOwner(row["subject_uuid"], row["masked_value"])

    async def apply(self, subject_uuid: UUID, changes: SubjectChanges) -> Any:
        connection, tenant_id = self._connection, self._tenant_id
        if changes.number is not None:
            protected = changes.number.protected
            await connection.execute(
                "UPDATE subject.external_identifiers SET status='SUPERSEDED', revoked_at=now() "
                "WHERE tenant_id=$1 AND subject_uuid=$2 AND status='ACTIVE'",
                tenant_id, subject_uuid,
            )
            await connection.execute(
                """INSERT INTO subject.external_identifiers (
                       external_identifier_id, tenant_id, subject_uuid, issuer, id_type,
                       encrypted_value, encryption_nonce, normalized_hmac, masked_value,
                       key_version, status
                   ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'ACTIVE')""",
                uuid4(), tenant_id, subject_uuid, changes.number.issuer,
                changes.number.id_type, protected.encrypted_value,
                protected.encryption_nonce, protected.normalized_hmac,
                protected.masked_value, protected.key_version,
            )
        if changes.identity is not None:
            identity = changes.identity.protected
            await connection.execute(
                """INSERT INTO subject.identity_profiles (
                       subject_uuid, tenant_id, identity_ciphertext, encryption_nonce,
                       key_version, name_lookup_hmac
                   ) VALUES ($1,$2,$3,$4,$5,$6)
                   ON CONFLICT (subject_uuid) DO UPDATE SET
                       identity_ciphertext=EXCLUDED.identity_ciphertext,
                       encryption_nonce=EXCLUDED.encryption_nonce,
                       key_version=EXCLUDED.key_version,
                       name_lookup_hmac=EXCLUDED.name_lookup_hmac,
                       updated_at=now()""",
                subject_uuid, tenant_id, identity.ciphertext, identity.nonce,
                identity.key_version, changes.identity.name_lookup_hmac,
            )
        if changes.analysis_profile is not None:
            await connection.execute(
                """INSERT INTO subject.analysis_profiles (
                       subject_uuid, tenant_id, profile_json, schema_version, source
                   ) VALUES ($1,$2,$3::jsonb,$4,'TERMINAL')
                   ON CONFLICT (subject_uuid) DO UPDATE SET
                       profile_json=EXCLUDED.profile_json,
                       schema_version=EXCLUDED.schema_version,
                       source=EXCLUDED.source,
                       updated_at=now()""",
                subject_uuid, tenant_id,
                json.dumps(
                    {key: value.model_dump(mode="json")
                     for key, value in changes.analysis_profile.items()},
                    separators=(",", ":"), ensure_ascii=False,
                ),
                changes.profile_schema_version,
            )
        if changes.tag_ids is not None:
            await connection.execute(
                "DELETE FROM subject.subject_tags WHERE tenant_id=$1 AND subject_uuid=$2 "
                "AND tag_id <> ALL($3::uuid[])",
                tenant_id, subject_uuid, list(changes.tag_ids),
            )
            await connection.execute(
                "INSERT INTO subject.subject_tags (tenant_id, subject_uuid, tag_id) "
                "SELECT $1, $2, tag_id FROM unnest($3::uuid[]) AS tag_id "
                "ON CONFLICT DO NOTHING",
                tenant_id, subject_uuid, list(changes.tag_ids),
            )
        # Every PATCH takes a new revision, also one that changes nothing.
        await connection.execute(
            "UPDATE subject.subjects SET status=COALESCE($3, status) "
            "WHERE tenant_id=$1 AND subject_uuid=$2",
            tenant_id, subject_uuid,
            None if changes.status is None else changes.status.value,
        )
        return await self._subject(subject_uuid)

    async def tag(self, tag_id: UUID) -> tuple[SubjectTag, str] | None:
        row = await self._connection.fetchrow(
            "SELECT * FROM subject.tags WHERE tag_id=$1", tag_id
        )
        return None if row is None else (_tag(row), row["name_key"])

    async def tag_by_key(self, name_key: str) -> SubjectTag | None:
        row = await self._connection.fetchrow(
            "SELECT * FROM subject.tags WHERE name_key=$1", name_key
        )
        return None if row is None else _tag(row)

    async def insert_tag(
        self, *, tag_id: UUID, name: str, name_key: str, created_by: UUID, created_at: datetime
    ) -> SubjectTag:
        revision = await self._connection.fetchval(
            "UPDATE subject.tag_revision_counters SET last_revision=last_revision+1 "
            "WHERE tenant_id=$1 RETURNING last_revision",
            self._tenant_id,
        )
        row = await self._connection.fetchrow(
            "INSERT INTO subject.tags "
            "(tenant_id, tag_id, name, name_key, created_by, created_at, revision) "
            "VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *",
            self._tenant_id, tag_id, name, name_key, created_by, created_at, revision,
        )
        return _tag(row)


class PostgresSubjectSyncRepository:
    def __init__(self, tenant_pool: Any) -> None:
        if tenant_pool is None:
            raise ValueError("tenant_pool is required")
        self._pool = tenant_pool

    @asynccontextmanager
    async def subject_writer(self, tenant_id: UUID) -> AsyncIterator[_PostgresWriter]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            yield _PostgresWriter(connection, tenant_id)

    @asynccontextmanager
    async def tag_writer(self, tenant_id: UUID) -> AsyncIterator[_PostgresWriter]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            # The counter row lock serializes the tenant's tag writers, so the
            # name check and the insert cannot race and revisions commit in order.
            await connection.execute(
                "INSERT INTO subject.tag_revision_counters (tenant_id) VALUES ($1) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                tenant_id,
            )
            await connection.execute(
                "SELECT last_revision FROM subject.tag_revision_counters "
                "WHERE tenant_id=$1 FOR UPDATE",
                tenant_id,
            )
            yield _PostgresWriter(connection, tenant_id)

    async def changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[StoredSubject, ...]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            rows = await connection.fetch(
                # "revision > 0" matches the predicate of the partial unique index.
                _SELECT_SUBJECTS.format(where="s.revision > 0 AND s.revision > $1")
                + " LIMIT $2",
                after_revision, limit,
            )
        return tuple(_stored(row) for row in rows)

    async def search_by_name(
        self,
        tenant_id: UUID,
        name_lookup_hmac: bytes | None,
        *,
        limit: int,
        audit: NameSearchAudit,
    ) -> tuple[StoredSubject, ...]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            rows = await connection.fetch(
                _SELECT_SUBJECTS.format(
                    where="i.name_lookup_hmac = $1 AND s.status IN ('ACTIVE', 'ARCHIVED')"
                ) + " LIMIT $2",
                name_lookup_hmac, limit,
            )
            # D5: every lookup is audited; the name never is.
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action,
                    resource_type, resource_id, correlation_id, outcome, safe_context)
                   VALUES ($1,$2,'TERMINAL',$3,'subject.search-by-name','SUBJECT',NULL,$4,
                           'ALLOWED',jsonb_build_object('result_count',$5::integer))""",
                uuid4(), tenant_id, audit.actor_id, audit.correlation_id, len(rows),
            )
        return tuple(_stored(row) for row in rows)

    async def tag_changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[SubjectTag, ...]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            rows = await connection.fetch(
                "SELECT * FROM subject.tags WHERE revision>$1 ORDER BY revision LIMIT $2",
                after_revision, limit,
            )
        return tuple(_tag(row) for row in rows)


__all__ = ["PostgresSubjectSyncRepository"]
