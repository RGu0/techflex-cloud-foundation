"""Tenant-bound immutable local report copies in PostgreSQL."""

from __future__ import annotations

import hashlib
import json
from typing import Any, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    ResourceNotFound,
    SessionHeldForReportCopy,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.postgres import tenant_transaction
from techflex_cloud_foundation.server.principal import IngestionPrincipal

from .models import (
    LocalBasicCopyReceipt,
    LocalBasicCopyRecord,
    LocalBasicCopyRequest,
    validate_local_basic_copy,
)


def _receipt(row: Any) -> LocalBasicCopyReceipt:
    return LocalBasicCopyReceipt(
        row["report_id"],
        row["version"],
        row["document_sha256"],
        row["pdf_sha256"],
    )


def _record(row: Any) -> LocalBasicCopyRecord:
    document = row["document_json"]
    if not isinstance(document, str):
        document = json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return LocalBasicCopyRecord(
        tenant_id=row["tenant_id"],
        session_id=row["session_id"],
        report_id=row["report_id"],
        version=row["version"],
        source=row["source"],
        document_json=document,
        document_sha256=row["document_sha256"],
        pdf_sha256=row["pdf_sha256"],
        pdf_object_key=row["pdf_object_key"],
        pdf_size_bytes=row["pdf_size_bytes"],
    )


class PostgresLocalBasicCopyRepository:
    def __init__(self, pool: Any, pdf_store: Any) -> None:
        self._pool = pool
        self._pdf_store = pdf_store

    async def accept(
        self,
        context: IngestionPrincipal,
        request: LocalBasicCopyRequest,
        idempotency_key: str,
    ) -> LocalBasicCopyReceipt:
        context.ensure_can_upload()
        validate_local_basic_copy(request)
        if not 1 <= len(idempotency_key) <= 128 or not idempotency_key.isascii():
            raise RequestContractError("invalid idempotency key")
        key_sha = hashlib.sha256(idempotency_key.encode("ascii")).hexdigest()
        object_key = None
        try:
            async with tenant_transaction(self._pool, context.tenant_id) as connection:
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended('copy-key:' || $1::uuid::text || ':' || $2::text, 0))",
                    context.tenant_id,
                    key_sha,
                )
                # Match hold's advisory lock so an upload cannot pass a concurrent hold.
                await connection.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended($1::uuid::text || ':' || $2::uuid::text, 0))",
                    context.tenant_id,
                    request.session_id,
                )
                session = await connection.fetchrow(
                    """SELECT session_id, tenant_id, terminal_id, subject_uuid,
                              consent_record_id, ingest_status, validity_status,
                              test_protocol_id, test_protocol_version
                       FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2""",
                    context.tenant_id,
                    request.session_id,
                )
                if session is None:
                    raise ResourceNotFound("session not found")
                if session["terminal_id"] != context.terminal_id:
                    raise TenantAccessDenied("session terminal mismatch")
                if session["consent_record_id"] != request.consent_record_id:
                    raise TenantAccessDenied("session consent binding mismatch")
                if session["ingest_status"] != "INGESTED" or session["validity_status"] != "VALID":
                    raise RequestContractError("session is not ingested and valid")
                document = json.loads(request.document_json)
                if (
                    document["protocol_id"] != session["test_protocol_id"]
                    or document["protocol_version"] != session["test_protocol_version"]
                ):
                    raise RequestContractError("report protocol binding mismatch")
                consent = await connection.fetchrow(
                    """SELECT consent_record_id FROM subject.consents
                       WHERE tenant_id=$1 AND consent_record_id=$2 AND subject_uuid=$3
                         AND revoked_at IS NULL
                         AND purpose_codes && ARRAY['SCREENING','SCREENING_SERVICE']::text[]""",
                    context.tenant_id,
                    request.consent_record_id,
                    session["subject_uuid"],
                )
                if consent is None:
                    raise TenantAccessDenied("active necessary consent not found")
                held = await connection.fetchval(
                    """SELECT EXISTS(SELECT 1 FROM ops.session_holds
                       WHERE tenant_id=$1 AND session_id=$2 AND state='HELD')""",
                    context.tenant_id,
                    request.session_id,
                )
                if held:
                    raise SessionHeldForReportCopy("session is held")
                prior_key = await connection.fetchrow(
                    """SELECT tenant_id, session_id, report_id, version, source, document_json,
                              document_sha256, pdf_sha256, pdf_object_key, pdf_size_bytes,
                              consent_record_id, idempotency_key_sha256
                       FROM reporting.local_basic_report_copies
                       WHERE tenant_id=$1 AND idempotency_key_sha256=$2""",
                    context.tenant_id,
                    key_sha,
                )
                prior_identity = await connection.fetchrow(
                    """SELECT tenant_id, session_id, report_id, version, source, document_json,
                              document_sha256, pdf_sha256, pdf_object_key, pdf_size_bytes,
                              consent_record_id, idempotency_key_sha256
                       FROM reporting.local_basic_report_copies
                       WHERE tenant_id=$1 AND (session_id=$2 OR (report_id=$3 AND version=$4))
                       """,
                    context.tenant_id,
                    request.session_id,
                    request.report_id,
                    request.version,
                )
                prior = prior_key or prior_identity
                if prior is not None:
                    if (
                        (
                            prior_key is not None
                            and prior_identity is not None
                            and prior_key["session_id"] != prior_identity["session_id"]
                        )
                        or prior["session_id"] != request.session_id
                        or prior["report_id"] != request.report_id
                        or prior["version"] != request.version
                        or prior["document_sha256"] != request.document_sha256
                        or prior["pdf_sha256"] != request.pdf_sha256
                        or prior["consent_record_id"] != request.consent_record_id
                        or prior["idempotency_key_sha256"] != key_sha
                    ):
                        raise IdempotencyConflict("report copy immutable binding conflict")
                    return _receipt(prior)
                stored = await self._pdf_store.put(
                    context.tenant_id,
                    request.session_id,
                    request.pdf_bytes,
                )
                object_key = stored.object_key
                await connection.execute(
                    """INSERT INTO reporting.local_basic_report_copies
                       (tenant_id, session_id, report_id, version, source, subject_uuid,
                        consent_record_id, terminal_id, document_json, document_sha256,
                        pdf_sha256, pdf_object_key, pdf_size_bytes, idempotency_key_sha256)
                       VALUES ($1,$2,$3,$4,'LOCAL_BASIC_COPY',$5,$6,$7,$8,$9,$10,$11,$12,$13)""",
                    context.tenant_id,
                    request.session_id,
                    request.report_id,
                    request.version,
                    session["subject_uuid"],
                    request.consent_record_id,
                    context.terminal_id,
                    request.document_json,
                    request.document_sha256,
                    request.pdf_sha256,
                    object_key,
                    len(request.pdf_bytes),
                    key_sha,
                )
            return LocalBasicCopyReceipt(
                request.report_id,
                request.version,
                request.document_sha256,
                request.pdf_sha256,
            )
        except Exception as exc:
            if object_key is not None:
                # Keep the object if the database commit result was ambiguous.
                try:
                    async with tenant_transaction(self._pool, context.tenant_id) as connection:
                        referenced = await connection.fetchval(
                            """SELECT EXISTS(SELECT 1 FROM reporting.local_basic_report_copies
                               WHERE tenant_id=$1 AND pdf_object_key=$2)""",
                            context.tenant_id,
                            object_key,
                        )
                    if referenced is False:
                        await self._pdf_store.delete(object_key)
                except Exception:
                    pass
            if getattr(exc, "sqlstate", None) == "23505":
                raise IdempotencyConflict("report copy immutable binding conflict") from exc
            raise

    async def get(self, tenant_id: UUID, report_id: str) -> LocalBasicCopyRecord:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            row = await connection.fetchrow(
                """SELECT tenant_id, session_id, report_id, version, source, document_json,
                          document_sha256, pdf_sha256, pdf_object_key, pdf_size_bytes
                   FROM reporting.local_basic_report_copies
                   WHERE tenant_id=$1 AND report_id=$2 AND version=1""",
                tenant_id,
                report_id,
            )
        if row is None:
            raise ResourceNotFound("basic report copy not found")
        return _record(row)

    async def list_for_tenant(self, tenant_id: UUID) -> tuple[LocalBasicCopyRecord, ...]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            rows = await connection.fetch(
                """SELECT tenant_id, session_id, report_id, version, source, document_json,
                          document_sha256, pdf_sha256, pdf_object_key, pdf_size_bytes
                   FROM reporting.local_basic_report_copies
                   WHERE tenant_id=$1 AND NOT EXISTS (
                       SELECT 1 FROM ops.session_holds hold
                       WHERE hold.tenant_id=local_basic_report_copies.tenant_id
                         AND hold.session_id=local_basic_report_copies.session_id
                         AND hold.state='HELD'
                   ) ORDER BY created_at DESC LIMIT 100""",
                tenant_id,
            )
        return tuple(_record(row) for row in rows)

    async def read_pdf(self, record: LocalBasicCopyRecord) -> bytes:
        expected_prefix = (
            f"tenants/{record.tenant_id}/sessions/{record.session_id}/basic-report-copies/"
        )
        if not record.pdf_object_key.startswith(expected_prefix):
            raise TenantAccessDenied("report object binding mismatch")
        payload = await self._pdf_store.read(record.pdf_object_key)
        if hashlib.sha256(payload).hexdigest() != record.pdf_sha256:
            raise RequestContractError("stored basic report PDF digest mismatch")
        return cast(bytes, payload)

    async def audit_access(
        self,
        tenant_id: UUID,
        session_id: UUID | None,
        actor_id: UUID,
        action: str,
        outcome: str,
    ) -> None:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action,
                    resource_type, resource_id, outcome, safe_context)
                   VALUES ($1,$2,'TENANT_ACCOUNT',$3,$4,'LOCAL_BASIC_REPORT_COPY',$5,$6,
                           '{"source":"LOCAL_BASIC_COPY"}'::jsonb)""",
                uuid4(),
                tenant_id,
                actor_id,
                action,
                session_id,
                outcome,
            )
