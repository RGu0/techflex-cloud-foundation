"""Tenant-RLS PostgreSQL persistence for immutable recovery cases."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
from typing import Any, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.identity_recovery import (
    RecoveryCaseCreateRequest,
    RecoveryComparisonResult,
    RecoveryRegistrationRequest,
    RecoveryRegistrationResult,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RepositoryUnavailable,
    ResourceNotFound,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.postgres import tenant_transaction
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.subject_service import IdentityProtector

from .models import RecoveryCaseRecord


def _record(row: Any) -> RecoveryCaseRecord:
    request = RecoveryCaseCreateRequest(
        session_id=row["session_id"],
        original_subject_uuid=row["original_subject_uuid"],
        cloud_subject_uuid=row["cloud_subject_uuid"],
        envelope_sha256=row["envelope_sha256"],
        identifier_issuer=row["identifier_issuer"],
        identifier_type=row["identifier_type"],
        external_identifier_id=row["external_identifier_id"],
        terminal_id=row["terminal_id"],
    )
    return RecoveryCaseRecord(
        case_id=row["case_id"],
        tenant_id=row["tenant_id"],
        terminal_id=row["terminal_id"],
        request=request,
        request_sha256=row["request_sha256"],
        key_sha256=row["key_sha256"],
        masked_clue=row["masked_clue"],
        status=row["status"],
        created_at=row["created_at"],
        attempts=row["attempts"],
        receipt_id=row["receipt_id"],
        receipt_expires_at=row["receipt_expires_at"],
        receipt_consumed_at=row["receipt_consumed_at"],
        ticket_sha256=row["ticket_sha256"],
    )


_CASE_SELECT = """SELECT c.*, r.receipt_id, r.expires_at AS receipt_expires_at,
                         r.consumed_at AS receipt_consumed_at, r.ticket_sha256
                  FROM ops.identity_recovery_cases c
                  LEFT JOIN ops.identity_recovery_receipts r
                    ON r.tenant_id=c.tenant_id AND r.case_id=c.case_id"""


class PostgresRecoveryIdentityReader:
    """Decrypt inside the tenant service only after the sensitive grant is used."""

    def __init__(self, tenant_pool: Any, protector: IdentityProtector) -> None:
        self._pool = tenant_pool
        self._protector = protector

    async def read_identity(
        self, tenant_id: UUID, subject_id: UUID
    ) -> tuple[str | None, str | None]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            row = await connection.fetchrow(
                """SELECT p.identity_ciphertext, p.encryption_nonce, p.key_version
                   FROM subject.identity_profiles p JOIN subject.subjects s
                     ON s.tenant_id=p.tenant_id AND s.subject_uuid=p.subject_uuid
                   WHERE p.tenant_id=$1 AND p.subject_uuid=$2 AND s.status='ACTIVE'""",
                tenant_id,
                subject_id,
            )
        if row is None:
            return None, None
        try:
            profile = self._protector.unprotect_identity_profile(
                row["identity_ciphertext"],
                row["encryption_nonce"],
                row["key_version"],
                tenant_id=str(tenant_id),
                subject_uuid=str(subject_id),
            )
        except Exception:
            raise RepositoryUnavailable("cloud identity profile unavailable") from None
        return profile.display_name, profile.contact


class PostgresRecoveryCaseRepository:
    def __init__(self, tenant_pool: Any, platform_pool: Any) -> None:
        self._tenant_pool = tenant_pool
        self._platform_pool = platform_pool

    async def create_case(
        self,
        tenant_id: UUID,
        terminal_id: UUID,
        request: RecoveryCaseCreateRequest,
        key_sha256: str,
        request_sha256: str,
    ) -> RecoveryCaseRecord:
        async with tenant_transaction(self._tenant_pool, tenant_id) as connection:
            # Session lock is shared with generic session creation. Acquire it
            # before the key lock so a racing generic create cannot pass its
            # case check while this case is being inserted.
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('recovery-session:' || $1::uuid::text || ':' || $2::uuid::text, 0))",
                tenant_id,
                request.session_id,
            )
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('recovery-key:' || $1::uuid::text || ':' || $2::text, 0))",
                tenant_id,
                key_sha256,
            )
            terminal_active = await connection.fetchval(
                """SELECT EXISTS(
                     SELECT 1 FROM device.terminals WHERE tenant_id=$1 AND terminal_id=$2 AND status='ACTIVE'
                     UNION ALL
                     SELECT 1 FROM device.client_installations
                     WHERE tenant_id=$1 AND client_installation_id=$2 AND status='ACTIVE')""",
                tenant_id,
                terminal_id,
            )
            if not terminal_active:
                raise TenantAccessDenied("terminal is not active for tenant")
            keyed = await connection.fetchrow(
                _CASE_SELECT + " WHERE c.tenant_id=$1 AND c.key_sha256=$2",
                tenant_id,
                key_sha256,
            )
            if keyed is not None:
                if keyed["request_sha256"] != request_sha256:
                    raise IdempotencyConflict("recovery case idempotency key conflict")
                return _record(keyed)
            subject = await connection.fetchrow(
                """SELECT s.subject_uuid, e.masked_value AS masked_clue,
                          e.normalized_hmac AS identifier_hmac
                   FROM subject.subjects s
                   JOIN subject.external_identifiers e
                     ON e.tenant_id=s.tenant_id AND e.subject_uuid=s.subject_uuid
                   WHERE s.tenant_id=$1 AND s.subject_uuid=$2 AND s.status='ACTIVE'
                     AND e.issuer=$3 AND e.id_type=$4 AND e.status='ACTIVE'
                     AND e.external_identifier_id=$5""",
                tenant_id,
                request.cloud_subject_uuid,
                request.identifier_issuer,
                request.identifier_type,
                request.external_identifier_id,
            )
            if subject is None:
                raise ResourceNotFound("cloud subject not found")
            session_exists = await connection.fetchval(
                "SELECT EXISTS(SELECT 1 FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2)",
                tenant_id,
                request.session_id,
            )
            if session_exists:
                raise IdempotencyConflict("session already registered before recovery case")
            existing = await connection.fetchrow(
                _CASE_SELECT + " WHERE c.tenant_id=$1 AND c.session_id=$2",
                tenant_id,
                request.session_id,
            )
            if existing is not None:
                if existing["request_sha256"] != request_sha256:
                    raise IdempotencyConflict("recovery case binding conflict")
                return _record(existing)
            case_id = uuid4()
            row = await connection.fetchrow(
                """INSERT INTO ops.identity_recovery_cases
                   (case_id, tenant_id, terminal_id, session_id, original_subject_uuid,
                    cloud_subject_uuid, envelope_sha256, identifier_issuer, identifier_type,
                    external_identifier_id, identifier_hmac,
                    key_sha256, request_sha256, masked_clue, status)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'PENDING')
                   RETURNING case_id""",
                case_id,
                tenant_id,
                terminal_id,
                request.session_id,
                request.original_subject_uuid,
                request.cloud_subject_uuid,
                request.envelope_sha256,
                request.identifier_issuer,
                request.identifier_type,
                request.external_identifier_id,
                subject["identifier_hmac"],
                key_sha256,
                request_sha256,
                subject["masked_clue"],
            )
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action,
                    resource_type, resource_id, outcome, safe_context)
                   VALUES ($1,$2,'TERMINAL',$3,'identity-recovery.case-create',
                           'RECOVERY_CASE',$4,'ALLOWED',
                           jsonb_build_object('session_id',$5::uuid::text))""",
                uuid4(),
                tenant_id,
                terminal_id,
                case_id,
                request.session_id,
            )
            created = await connection.fetchrow(
                _CASE_SELECT + " WHERE c.tenant_id=$1 AND c.case_id=$2",
                tenant_id,
                row["case_id"],
            )
            return _record(created)

    async def get_case(
        self, tenant_id: UUID, terminal_id: UUID, case_id: UUID
    ) -> RecoveryCaseRecord:
        async with tenant_transaction(self._tenant_pool, tenant_id) as connection:
            row = await connection.fetchrow(
                _CASE_SELECT + " WHERE c.tenant_id=$1 AND c.terminal_id=$2 AND c.case_id=$3",
                tenant_id,
                terminal_id,
                case_id,
            )
            if row is None:
                raise ResourceNotFound("recovery case not found")
            return _record(row)

    async def get_platform_case(self, tenant_id: UUID, case_id: UUID) -> RecoveryCaseRecord:
        async with tenant_transaction(self._platform_pool, tenant_id) as connection:
            row = await connection.fetchrow(
                _CASE_SELECT + " WHERE c.tenant_id=$1 AND c.case_id=$2",
                tenant_id,
                case_id,
            )
            if row is None:
                raise ResourceNotFound("recovery case not found")
            return _record(row)

    async def record_comparison(
        self,
        tenant_id: UUID,
        case_id: UUID,
        *,
        matched: bool,
        actor_id: UUID,
        grant_id: UUID,
        ticket_sha256: str,
    ) -> RecoveryComparisonResult:
        async with tenant_transaction(self._platform_pool, tenant_id) as connection:
            # Serialize with tenant registration without granting tenant UPDATE on cases.
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('recovery-case:' || $1::uuid::text || ':' || $2::uuid::text, 0))",
                tenant_id,
                case_id,
            )
            case = await connection.fetchrow(
                """SELECT * FROM ops.identity_recovery_cases
                   WHERE tenant_id=$1 AND case_id=$2 FOR UPDATE""",
                tenant_id,
                case_id,
            )
            if case is None:
                raise ResourceNotFound("recovery case not found")
            prior = await connection.fetchrow(
                """SELECT receipt_id, expires_at, consumed_at FROM ops.identity_recovery_receipts
                   WHERE tenant_id=$1 AND case_id=$2""",
                tenant_id,
                case_id,
            )
            if prior is not None and prior["consumed_at"] is not None:
                raise IdempotencyConflict("recovery receipt already consumed")
            if prior is not None and prior["expires_at"] > datetime.now(UTC):
                raise IdempotencyConflict("comparison already completed")
            if case["attempts"] >= 3 or case["status"] in {"DENIED", "EXPIRED"}:
                return RecoveryComparisonResult(case_id=case_id, decision="NOT_VERIFIED")
            active_subject = await connection.fetchval(
                """SELECT EXISTS(SELECT 1 FROM subject.subjects s
                   JOIN subject.external_identifiers e
                     ON e.tenant_id=s.tenant_id AND e.subject_uuid=s.subject_uuid
                   WHERE s.tenant_id=$1 AND s.subject_uuid=$2 AND s.status='ACTIVE'
                     AND e.issuer=$3 AND e.id_type=$4 AND e.status='ACTIVE'
                     AND e.external_identifier_id=$5
                     AND e.normalized_hmac=$6)""",
                tenant_id,
                case["cloud_subject_uuid"],
                case["identifier_issuer"],
                case["identifier_type"],
                case["external_identifier_id"],
                case["identifier_hmac"],
            )
            if not active_subject:
                raise ResourceNotFound("cloud subject is no longer active")
            attempt = case["attempts"] + 1
            status = "MATCHED" if matched else ("DENIED" if attempt >= 3 else "PENDING")
            await connection.execute(
                """UPDATE ops.identity_recovery_cases SET attempts=$3, status=$4
                   WHERE tenant_id=$1 AND case_id=$2""",
                tenant_id,
                case_id,
                attempt,
                status,
            )
            receipt_id, expires_at = None, None
            if matched:
                receipt_id, expires_at = uuid4(), datetime.now(UTC) + timedelta(minutes=15)
                if prior is None:
                    await connection.execute(
                        """INSERT INTO ops.identity_recovery_receipts
                           (receipt_id, tenant_id, case_id, terminal_id, session_id,
                            original_subject_uuid, cloud_subject_uuid, envelope_sha256,
                            expires_at, ticket_sha256)
                           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
                        receipt_id,
                        tenant_id,
                        case_id,
                        case["terminal_id"],
                        case["session_id"],
                        case["original_subject_uuid"],
                        case["cloud_subject_uuid"],
                        case["envelope_sha256"],
                        expires_at,
                        ticket_sha256,
                    )
                else:
                    await connection.execute(
                        """UPDATE ops.identity_recovery_receipts
                           SET receipt_id=$3, expires_at=$4, ticket_sha256=$5, consumed_at=NULL
                           WHERE tenant_id=$1 AND case_id=$2 AND consumed_at IS NULL""",
                        tenant_id,
                        case_id,
                        receipt_id,
                        expires_at,
                        ticket_sha256,
                    )
            await connection.execute(
                """INSERT INTO ops.identity_recovery_comparisons
                   (comparison_id, tenant_id, case_id, actor_id, grant_id,
                    ticket_sha256, decision, compared_fields)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,ARRAY['name','contact']::text[])""",
                uuid4(),
                tenant_id,
                case_id,
                actor_id,
                grant_id,
                ticket_sha256,
                "MATCHED" if matched else "NOT_VERIFIED",
            )
            return RecoveryComparisonResult(
                case_id=case_id,
                decision="MATCHED" if matched else "NOT_VERIFIED",
                receipt_id=receipt_id,
                receipt_expires_at=expires_at,
            )

    async def register(
        self,
        context: IngestionPrincipal,
        case_id: UUID,
        request: RecoveryRegistrationRequest,
        idempotency_key: str,
        request_sha256: str,
        *,
        replay_only: bool,
        authorization: SessionAuthorization | None = None,
    ) -> RecoveryRegistrationResult:
        tenant_id = context.tenant_id
        key_sha256 = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
        async with tenant_transaction(self._tenant_pool, tenant_id) as connection:
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('recovery-session:' || $1::uuid::text || ':' || $2::uuid::text, 0))",
                tenant_id,
                request.session.session_id,
            )
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('recovery-register:' || $1::uuid::text || ':' || $2::text, 0))",
                tenant_id,
                key_sha256,
            )
            # The tenant role may read cases but cannot SELECT FOR UPDATE on them.
            await connection.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended('recovery-case:' || $1::uuid::text || ':' || $2::uuid::text, 0))",
                tenant_id,
                case_id,
            )
            prior = await connection.fetchrow(
                """SELECT * FROM ops.identity_recovery_registrations
                   WHERE tenant_id=$1 AND key_sha256=$2""",
                tenant_id,
                key_sha256,
            )
            if prior is not None:
                if prior["request_sha256"] != request_sha256 or prior["case_id"] != case_id:
                    raise IdempotencyConflict("recovery registration key conflict")
                return RecoveryRegistrationResult(
                    case_id=case_id,
                    receipt_id=prior["receipt_id"],
                    consent_record_id=prior["consent_record_id"],
                    session_id=prior["session_id"],
                    registered_at=prior["registered_at"],
                )
            if replay_only:
                raise IdempotencyConflict("recovery registration binding conflict")
            case = await connection.fetchrow(
                """SELECT * FROM ops.identity_recovery_cases
                   WHERE tenant_id=$1 AND case_id=$2""",
                tenant_id,
                case_id,
            )
            if case is None or case["terminal_id"] != context.terminal_id:
                raise ResourceNotFound("recovery case not found")
            receipt = await connection.fetchrow(
                """SELECT * FROM ops.identity_recovery_receipts
                   WHERE tenant_id=$1 AND case_id=$2 FOR UPDATE""",
                tenant_id,
                case_id,
            )
            if (
                receipt is None
                or receipt["receipt_id"] != request.receipt_id
                or receipt["expires_at"] <= datetime.now(UTC)
                or receipt["consumed_at"] is not None
                or case["status"] != "MATCHED"
                or receipt["terminal_id"] != context.terminal_id
                or receipt["session_id"] != case["session_id"]
                or receipt["original_subject_uuid"] != case["original_subject_uuid"]
                or receipt["cloud_subject_uuid"] != case["cloud_subject_uuid"]
                or receipt["envelope_sha256"] != case["envelope_sha256"]
                or request.original_subject_uuid != case["original_subject_uuid"]
                or request.original_envelope_sha256 != case["envelope_sha256"]
                or request.session.session_id != case["session_id"]
                or request.session.subject_uuid != case["cloud_subject_uuid"]
                or request.session.terminal_id != context.terminal_id
                or request.session.client_installation_id != context.terminal_id
                or request.consent.subject_uuid != case["cloud_subject_uuid"]
                or request.consent.consent_record_id != request.session.consent_record_id
            ):
                raise IdempotencyConflict("recovery receipt or binding invalid")
            session_digest = canonical_sha256(request.session)
            consent_digest = canonical_sha256(request.consent)
            authorization_row = None
            if authorization is None:
                context.ensure_can_start_new()
            else:
                table = (
                    "capture_grants"
                    if authorization.kind == "grant"
                    else "upload_migration_permits"
                )
                authorization_row = await connection.fetchrow(
                    f"SELECT * FROM screening.{table} WHERE tenant_id=$1 AND session_id=$2 FOR UPDATE",
                    tenant_id,
                    request.session.session_id,
                )
                row = authorization_row
                if (
                    row is None
                    or row["installation_id"] != context.terminal_id
                    or row["installation_id"] != request.session.client_installation_id
                    or row["account_id"] != context.account_id
                    or row["hardware_id"] != request.session.device_id
                    or not hmac.compare_digest(
                        row["token_sha256"],
                        hashlib.sha256(authorization.token.get_secret_value().encode()).digest(),
                    )
                    or row["state"] != "ISSUED"
                    or (
                        authorization.kind == "migration_permit"
                        and (
                            row["consumed_request_sha256"] != session_digest
                            or row["expected_manifest_sha256"] != authorization.manifest_sha256
                        )
                    )
                ):
                    raise TenantAccessDenied(
                        "capture authorization does not match recovery registration"
                    )
                if authorization.kind == "migration_permit" and (
                    row["final_subject_uuid"] != case["cloud_subject_uuid"]
                    or row["consent_record_id"] != request.consent.consent_record_id
                    or row["consent_sha256"] != consent_digest
                    or row["reconciliation_case_id"] != case_id
                    or row["original_envelope_sha256"] != case["envelope_sha256"]
                    or row["original_subject_uuid"] != case["original_subject_uuid"]
                ):
                    raise TenantAccessDenied(
                        "migration permit consent or reconciliation binding mismatch"
                    )
            if (
                request.consent.evidence_type
                not in {"SUBJECT_CONFIRMED", "REPRESENTATIVE_CONFIRMED"}
                or not any(
                    purpose != "ALGORITHM_RESEARCH" for purpose in request.consent.purpose_codes
                )
                or request.consent.granted_at.tzinfo is None
                or request.consent.granted_at < receipt["created_at"]
                or request.consent.granted_at > datetime.now(UTC) + timedelta(minutes=2)
            ):
                raise IdempotencyConflict("fresh necessary consent required")
            validation = await connection.fetchrow(
                """SELECT
                    EXISTS(SELECT 1 FROM device.client_installations i
                           JOIN device.terminals t ON t.tenant_id=i.tenant_id
                             AND t.terminal_id=i.client_installation_id
                           WHERE i.tenant_id=$1 AND i.client_installation_id=$2
                             AND i.status='ACTIVE' AND t.status='ACTIVE'
                             AND t.site_id IS NOT DISTINCT FROM $3) AS installation_ok,
                    EXISTS(SELECT 1 FROM device.hardware_assets h
                           JOIN device.devices d ON d.tenant_id=h.tenant_id
                             AND d.device_id=h.hardware_id
                           WHERE h.tenant_id=$1 AND h.hardware_id=$4) AS hardware_ok,
                    EXISTS(SELECT 1 FROM subject.subjects s
                           WHERE s.tenant_id=$1 AND s.subject_uuid=$5
                             AND s.status='ACTIVE') AS subject_ok,
                    EXISTS(SELECT 1 FROM subject.external_identifiers e
                           WHERE e.tenant_id=$1 AND e.subject_uuid=$5
                             AND e.issuer=$6 AND e.id_type=$7
                             AND e.status='ACTIVE'
                             AND e.external_identifier_id=$8
                             AND e.normalized_hmac=$9) AS identifier_ok""",
                tenant_id,
                context.terminal_id,
                request.session.site_id,
                request.session.device_id,
                case["cloud_subject_uuid"],
                case["identifier_issuer"],
                case["identifier_type"],
                case["external_identifier_id"],
                case["identifier_hmac"],
            )
            if not all(validation.values()):
                raise TenantAccessDenied("recovery session references are invalid")
            existing = await connection.fetchval(
                """SELECT EXISTS(SELECT 1 FROM screening.sessions
                   WHERE tenant_id=$1 AND session_id=$2)""",
                tenant_id,
                case["session_id"],
            )
            if existing:
                raise IdempotencyConflict("session is already registered")
            consent_exists = await connection.fetchval(
                """SELECT EXISTS(SELECT 1 FROM subject.consents
                   WHERE tenant_id=$1 AND consent_record_id=$2)""",
                tenant_id,
                request.consent.consent_record_id,
            )
            if consent_exists:
                raise IdempotencyConflict("consent identifier already exists")
            await connection.execute(
                """INSERT INTO subject.consents
                   (consent_record_id, tenant_id, subject_uuid, policy_version,
                    purpose_codes, data_categories, evidence_type, terminal_id,
                    evidence_hash, granted_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)""",
                request.consent.consent_record_id,
                tenant_id,
                request.consent.subject_uuid,
                request.consent.policy_version,
                list(request.consent.purpose_codes),
                list(request.consent.data_categories),
                request.consent.evidence_type,
                context.terminal_id,
                canonical_sha256(request.consent),
                request.consent.granted_at,
            )
            session = request.session
            await connection.execute(
                """INSERT INTO screening.sessions
                   (session_id, tenant_id, site_id, terminal_id, device_id,
                    subject_uuid, consent_record_id, test_protocol_id,
                    test_protocol_version, validity_status, ingest_status,
                    started_at, app_version, protocol_profile_version,
                    payload_schema_version, calibration_version, config_snapshot,
                    expected_manifest_sha256)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,'UNKNOWN','RECEIVING',
                           $10,$11,$12,$13,$14,$15::jsonb,$16)""",
                session.session_id,
                tenant_id,
                session.site_id,
                context.terminal_id,
                session.device_id,
                session.subject_uuid,
                session.consent_record_id,
                session.test_protocol.id,
                session.test_protocol.version,
                session.started_at,
                session.versions.app,
                session.versions.protocol_profile,
                session.versions.payload_schema,
                session.versions.calibration,
                json.dumps(session.config_snapshot, separators=(",", ":"), ensure_ascii=False),
                authorization.manifest_sha256 if authorization is not None else None,
            )
            if authorization_row is not None:
                authorization = cast(SessionAuthorization, authorization)
                table = (
                    "capture_grants"
                    if authorization.kind == "grant"
                    else "upload_migration_permits"
                )
                await connection.execute(
                    f"UPDATE screening.{table} SET state='CONSUMED'"
                    + (
                        ",consumed_request_sha256=$3,expected_manifest_sha256=$4"
                        if authorization.kind == "grant"
                        else ""
                    )
                    + " WHERE tenant_id=$1 AND session_id=$2 AND state='ISSUED'",
                    *(
                        (
                            tenant_id,
                            session.session_id,
                            session_digest,
                            authorization.manifest_sha256,
                        )
                        if authorization.kind == "grant"
                        else (tenant_id, session.session_id)
                    ),
                )
                await connection.execute(
                    """INSERT INTO ops.capture_authorization_audit
                       (event_id,tenant_id,session_id,authorization_kind,event_kind,actor_id,evidence_reference,decision_code)
                       VALUES ($1,$2,$3,$4,'CONSUMED',$5,$6,'AUTHORIZED_RECOVERY_REGISTRATION')""",
                    uuid4(),
                    tenant_id,
                    session.session_id,
                    "GRANT" if authorization.kind == "grant" else "PERMIT",
                    context.account_id,
                    authorization_row["evidence_reference"]
                    if authorization.kind == "migration_permit"
                    else None,
                )
            registered_at = datetime.now(UTC)
            await connection.execute(
                """UPDATE ops.identity_recovery_receipts SET consumed_at=$3
                   WHERE tenant_id=$1 AND case_id=$2 AND consumed_at IS NULL""",
                tenant_id,
                case_id,
                registered_at,
            )
            await connection.execute(
                """INSERT INTO ops.identity_recovery_registrations
                   (registration_id, tenant_id, case_id, receipt_id, key_sha256,
                    request_sha256, consent_record_id, session_id, registered_at)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)""",
                uuid4(),
                tenant_id,
                case_id,
                request.receipt_id,
                key_sha256,
                request_sha256,
                request.consent.consent_record_id,
                request.session.session_id,
                registered_at,
            )
            await connection.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id, tenant_id, actor_type, actor_id, action,
                    resource_type, resource_id, outcome, safe_context)
                   VALUES ($1,$2,'TERMINAL',$3,'identity-recovery.register',
                           'RECOVERY_CASE',$4,'ALLOWED',
                           jsonb_build_object('session_id',$5::uuid::text))""",
                uuid4(),
                tenant_id,
                context.terminal_id,
                case_id,
                request.session.session_id,
            )
            return RecoveryRegistrationResult(
                case_id=case_id,
                receipt_id=request.receipt_id,
                consent_record_id=request.consent.consent_record_id,
                session_id=request.session.session_id,
                registered_at=registered_at,
            )
