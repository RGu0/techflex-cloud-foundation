"""Opt-in PostgreSQL role/RLS check for the controlled recovery path."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import os
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    SessionCreateRequest,
    SessionVersions,
)
from techflex_cloud_foundation.contracts.cloud import TestProtocol as CloudTestProtocol
from techflex_cloud_foundation.contracts.identity_recovery import (
    RecoveryCaseCreateRequest,
    RecoveryRegistrationRequest,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    ResourceNotFound,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.identity_recovery.postgres import (
    PostgresRecoveryCaseRepository,
)
from techflex_cloud_foundation.server.identity_recovery.service import IdentityRecoveryService
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from tests.pg_platform import live_environment

live_environment()

_DSN_NAMES = (
    "FEETFORCEPLATE_TEST_ADMIN_DSN",
    "FEETFORCEPLATE_TEST_TENANT_DSN",
    "FEETFORCEPLATE_TEST_PLATFORM_DSN",
)


@pytest.mark.skipif(
    not all(os.environ.get(name) for name in _DSN_NAMES),
    reason="isolated PostgreSQL admin, tenant and platform DSNs are not configured",
)
def test_recovery_case_and_comparison_obey_live_roles_and_tenant_rls() -> None:
    async def exercise() -> None:
        import asyncpg

        tenant_id, other_tenant_id = uuid4(), uuid4()
        terminal_id, cloud_subject_id, original_subject_id = uuid4(), uuid4(), uuid4()
        identifier_id, session_id = uuid4(), uuid4()
        admin = await asyncpg.connect(os.environ[_DSN_NAMES[0]])
        tenant_pool = await asyncpg.create_pool(os.environ[_DSN_NAMES[1]], min_size=1, max_size=2)
        platform_pool = await asyncpg.create_pool(os.environ[_DSN_NAMES[2]], min_size=1, max_size=2)
        try:
            for value in (tenant_id, other_tenant_id):
                await admin.execute(
                    "INSERT INTO iam.tenants (tenant_id, name, status) VALUES ($1, 'RAY-99 test', 'ACTIVE')",
                    value,
                )
            await admin.execute(
                """INSERT INTO device.terminals
                   (terminal_id, tenant_id, installation_id, client_public_key, status)
                   VALUES ($1,$2,$3,'test-public-key','ACTIVE')""",
                terminal_id, tenant_id, uuid4(),
            )
            await admin.execute(
                "INSERT INTO subject.subjects (subject_uuid, tenant_id, status) VALUES ($1,$2,'ACTIVE')",
                cloud_subject_id, tenant_id,
            )
            await admin.execute(
                """INSERT INTO subject.external_identifiers
                   (external_identifier_id, tenant_id, subject_uuid, issuer, id_type,
                    encrypted_value, encryption_nonce, normalized_hmac, masked_value,
                    key_version, status)
                   VALUES ($1,$2,$3,'institution','record-number',$4,$5,$6,'***0731',
                           'test-key','ACTIVE')""",
                identifier_id, tenant_id, cloud_subject_id,
                b"synthetic-ciphertext", b"synthetic-nonce", hashlib.sha256(b"synthetic-0731").digest(),
            )
            principal = IngestionPrincipal(
                tenant_id=tenant_id, terminal_id=terminal_id,
                expires_at=datetime.now(UTC) + timedelta(minutes=10),
                allow_new_test=False, allow_upload=True,
            )
            repository = PostgresRecoveryCaseRepository(tenant_pool, platform_pool)
            service = IdentityRecoveryService(repository)
            request = RecoveryCaseCreateRequest(
                session_id=session_id, original_subject_uuid=original_subject_id,
                cloud_subject_uuid=cloud_subject_id, envelope_sha256="a" * 64,
                identifier_issuer="institution", identifier_type="record-number",
                external_identifier_id=identifier_id, terminal_id=terminal_id,
            )
            created = await service.create_case(principal, request, "live-case")
            assert created.status == "PENDING"
            assert (await service.create_case(principal, request, "live-case")).case_id == created.case_id
            other_principal = IngestionPrincipal(
                tenant_id=other_tenant_id, terminal_id=terminal_id,
                expires_at=principal.expires_at, allow_new_test=False, allow_upload=True,
            )
            with pytest.raises(ResourceNotFound):
                await service.get_case(other_principal, created.case_id)
            compared = await repository.record_comparison(
                tenant_id, created.case_id, matched=True,
                actor_id=uuid4(), grant_id=uuid4(),
                ticket_sha256=hashlib.sha256(b"synthetic-ticket").hexdigest(),
            )
            assert compared.decision == "MATCHED"
            assert (await service.get_case(principal, created.case_id)).receipt_id == compared.receipt_id
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.identity_recovery_comparisons WHERE tenant_id=$1 AND case_id=$2",
                tenant_id, created.case_id,
            ) == 1
            concurrent = await asyncio.gather(
                service.create_case(
                    principal, request.model_copy(update={"session_id": uuid4()}),
                    "shared-concurrent-key",
                ),
                service.create_case(
                    principal, request.model_copy(update={"session_id": uuid4()}),
                    "shared-concurrent-key",
                ),
                return_exceptions=True,
            )
            assert sum(isinstance(result, IdempotencyConflict) for result in concurrent) == 1
            assert sum(not isinstance(result, Exception) for result in concurrent) == 1
            second_request = request.model_copy(update={"session_id": uuid4()})
            second = await service.create_case(principal, second_request, "replaced-identifier-case")
            await admin.execute(
                "UPDATE subject.external_identifiers SET normalized_hmac=$1 WHERE external_identifier_id=$2",
                hashlib.sha256(b"changed-identifier").digest(), identifier_id,
            )
            with pytest.raises(ResourceNotFound):
                await repository.record_comparison(
                    tenant_id, second.case_id, matched=True,
                    actor_id=uuid4(), grant_id=uuid4(),
                    ticket_sha256=hashlib.sha256(b"another-ticket").hexdigest(),
                )
            assert (await repository.get_case(tenant_id, terminal_id, second.case_id)).attempts == 0
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.identity_recovery_receipts WHERE tenant_id=$1 AND case_id=$2",
                tenant_id, second.case_id,
            ) == 0
            async with platform_pool.acquire() as connection:
                async with connection.transaction():
                    await connection.execute("SELECT set_config('app.tenant_id',$1,true)", str(tenant_id))
                    with pytest.raises(asyncpg.InsufficientPrivilegeError):
                        await connection.fetchval(
                            "SELECT encrypted_value FROM subject.external_identifiers LIMIT 1"
                        )
        finally:
            await platform_pool.close()
            await tenant_pool.close()
            await admin.close()

    asyncio.run(exercise())


_REGISTRATION_DSN_NAMES = (
    "FEETFORCEPLATE_TEST_ADMIN_DSN",
    "FEETFORCEPLATE_TEST_TENANT_DSN",
    "FEETFORCEPLATE_TEST_ACTIVATION_DSN",
    "FEETFORCEPLATE_TEST_PLATFORM_DSN",
)


@pytest.mark.parametrize("authorization_kind", ["grant", "migration_permit"])
@pytest.mark.skipif(
    not all(os.environ.get(name) for name in _REGISTRATION_DSN_NAMES),
    reason="isolated PostgreSQL admin, tenant, activation and platform DSNs are not configured",
)
def test_live_recovery_registration_consumes_authorization_atomically_and_replays(
    authorization_kind: str, monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exercise() -> None:
        from dataclasses import replace

        import asyncpg

        from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
        from techflex_cloud_foundation.server.access_control.postgres import (
            PostgresAccessRepository,
        )
        from techflex_cloud_foundation.server.access_control.repository import TenantSeed
        from techflex_cloud_foundation.server.identity_recovery import postgres as recovery_postgres
        from techflex_cloud_foundation.server.postgres import tenant_transaction
        from tests.test_ffp_postgres_capture_grants import _group

        admin = await asyncpg.connect(os.environ[_REGISTRATION_DSN_NAMES[0]])
        tenant_pool = await asyncpg.create_pool(os.environ[_REGISTRATION_DSN_NAMES[1]], min_size=1, max_size=2)
        activation_pool = await asyncpg.create_pool(os.environ[_REGISTRATION_DSN_NAMES[2]], min_size=1, max_size=2)
        platform_pool = await asyncpg.create_pool(os.environ[_REGISTRATION_DSN_NAMES[3]], min_size=1, max_size=2)
        now = datetime.now(UTC)
        tenant_id, installation_id = uuid4(), uuid4()
        group = replace(
            _group(), license_valid_from=now - timedelta(days=1),
            license_valid_until=now + timedelta(days=365),
            activation_expires_at=now + timedelta(days=7),
        )
        tenant = TenantSeed(tenant_id, f"Recovery registration {uuid4()}")
        access = PostgresAccessRepository(
            tenant_pool=tenant_pool,
            activation_pool=activation_pool,
            platform_pool=platform_pool,
        )
        try:
            await access.provision_tenant(tenant, group, created_at=now)
            await access.activate_account_atomically(
                login_name_hmac=group.login_name_hmac,
                activation_code_hash=group.activation_code_hash,
                hardware_identity=group.hardware_identity,
                password_hash="$ffp-scrypt$recovery-registration-test",
                installation_id=installation_id, activated_at=now,
                license_key_id="license/2-recovery-test",
                license_document_json='{"schema_version":"license/2"}',
                license_signature="s" * 86,
            )
            principal = IngestionPrincipal(
                tenant_id=tenant_id, terminal_id=installation_id,
                expires_at=now + timedelta(minutes=10),
                allow_new_test=False, allow_upload=True,
                account_id=group.account_id, license_id=group.license_id,
                hardware_id=group.hardware_identity,
            )
            original_subject_id, cloud_subject_id = uuid4(), uuid4()
            identifier_id, session_id, consent_id = uuid4(), uuid4(), uuid4()
            await admin.execute(
                "INSERT INTO subject.subjects (subject_uuid,tenant_id,status) VALUES ($1,$2,'ACTIVE')",
                cloud_subject_id, tenant_id,
            )
            await admin.execute(
                """INSERT INTO subject.external_identifiers
                   (external_identifier_id,tenant_id,subject_uuid,issuer,id_type,
                    encrypted_value,encryption_nonce,normalized_hmac,masked_value,key_version,status)
                   VALUES ($1,$2,$3,'institution','record-number',$4,$5,$6,'***0731','test-key','ACTIVE')""",
                identifier_id, tenant_id, cloud_subject_id,
                b"synthetic-ciphertext", b"synthetic-nonce", hashlib.sha256(b"synthetic-0731").digest(),
            )
            repository = PostgresRecoveryCaseRepository(tenant_pool, platform_pool)
            service = IdentityRecoveryService(repository)
            case_request = RecoveryCaseCreateRequest(
                session_id=session_id, original_subject_uuid=original_subject_id,
                cloud_subject_uuid=cloud_subject_id, envelope_sha256="a" * 64,
                identifier_issuer="institution", identifier_type="record-number",
                external_identifier_id=identifier_id, terminal_id=installation_id,
            )
            case = await service.create_case(principal, case_request, "live-registration-case")
            comparison = await repository.record_comparison(
                tenant_id, case.case_id, matched=True, actor_id=uuid4(), grant_id=uuid4(),
                ticket_sha256=hashlib.sha256(b"synthetic-ticket").hexdigest(),
            )
            assert comparison.receipt_id is not None
            consent = ConsentCreateRequest(
                consent_record_id=consent_id, subject_uuid=cloud_subject_id,
                policy_version="consent/1", purpose_codes=("SCREENING_SERVICE",),
                data_categories=("PRESSURE_RAW",), granted_at=datetime.now(UTC),
                evidence_type="SUBJECT_CONFIRMED", terminal_signature="synthetic-test-signature",
            )
            session = SessionCreateRequest(
                session_id=session_id, subject_uuid=cloud_subject_id,
                consent_record_id=consent_id, site_id=None,
                terminal_id=installation_id, client_installation_id=installation_id,
                device_id=group.hardware_id,
                test_protocol=CloudTestProtocol(id="standard-screening", version="1"),
                versions=SessionVersions(
                    app="0.1", protocol_profile="do-p4864/1",
                    payload_schema="raw-segment/1", calibration="calibration/1",
                ),
                started_at=now,
            )
            request = RecoveryRegistrationRequest(
                receipt_id=comparison.receipt_id,
                original_subject_uuid=original_subject_id,
                original_envelope_sha256=case_request.envelope_sha256,
                consent=consent, session=session,
            )
            token = f"live-recovery-{authorization_kind}-{uuid4()}"
            manifest_sha256 = "b" * 64
            approver_id = uuid4()
            if authorization_kind == "migration_permit":
                await admin.execute(
                    """INSERT INTO iam.platform_identities
                       (platform_identity_id,login_name_hmac,display_name,password_hash,status)
                       VALUES ($1,$2,'synthetic recovery approver','synthetic-hash','ACTIVE')""",
                    approver_id, hashlib.sha256(str(approver_id).encode()).digest(),
                )
                await admin.execute(
                    """INSERT INTO screening.upload_migration_permits
                       (tenant_id,session_id,installation_id,account_id,license_id,hardware_id,
                        token_sha256,consumed_request_sha256,expected_manifest_sha256,approver_id,
                        approval_reason,evidence_reference,original_envelope_sha256,original_subject_uuid,
                        final_subject_uuid,consent_record_id,consent_sha256,reconciliation_case_id)
                       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
                               'LEGACY_VALID_SESSION_REVIEWED','evidence/ray-513/live-registration',
                               $11,$12,$13,$14,$15,$16)""",
                    tenant_id, session_id, installation_id, group.account_id, group.license_id,
                    group.hardware_id, hashlib.sha256(token.encode()).digest(),
                    canonical_sha256(session), manifest_sha256, approver_id,
                    case_request.envelope_sha256, original_subject_id, cloud_subject_id,
                    consent_id, canonical_sha256(consent), case.case_id,
                )
            else:
                await admin.execute(
                    """INSERT INTO screening.capture_grants
                       (tenant_id,session_id,installation_id,account_id,license_id,hardware_id,token_sha256)
                       VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                    tenant_id, session_id, installation_id, group.account_id, group.license_id,
                    group.hardware_id, hashlib.sha256(token.encode()).digest(),
                )
            authorization = SessionAuthorization(
                session_id=session_id, kind=authorization_kind,
                token=token, manifest_sha256=manifest_sha256,
            )
            table = "upload_migration_permits" if authorization_kind == "migration_permit" else "capture_grants"

            if authorization_kind == "migration_permit":
                changed_consent = consent.model_copy(update={"purpose_codes": ("SCREENING_SERVICE", "RESEARCH")})
                mismatched_request = request.model_copy(update={"consent": changed_consent})
                with pytest.raises(TenantAccessDenied):
                    await service.register(
                        principal, case.case_id, mismatched_request,
                        "live-registration-bad-binding", authorization,
                    )
            else:
                wrong_authorization = SessionAuthorization(
                    session_id=session_id, kind="grant", token=f"wrong-{uuid4()}",
                    manifest_sha256=manifest_sha256,
                )
                with pytest.raises(TenantAccessDenied):
                    await service.register(
                        principal, case.case_id, request,
                        "live-registration-bad-binding", wrong_authorization,
                    )
            assert await admin.fetchval(
                f"SELECT state FROM screening.{table} WHERE tenant_id=$1 AND session_id=$2",
                tenant_id, session_id,
            ) == "ISSUED"
            assert await admin.fetchval(
                "SELECT count(*) FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2",
                tenant_id, session_id,
            ) == 0

            collision_id = uuid4()
            await admin.execute(
                """INSERT INTO ops.audit_logs
                   (audit_log_id,tenant_id,actor_type,action,resource_type,outcome)
                   VALUES ($1,$2,'TEST','collision','TEST','FAILED')""",
                collision_id, tenant_id,
            )
            generated_ids = iter((uuid4(), uuid4(), collision_id))
            with monkeypatch.context() as patcher:
                patcher.setattr(recovery_postgres, "uuid4", lambda: next(generated_ids))
                with pytest.raises(asyncpg.UniqueViolationError):
                    await service.register(
                        principal, case.case_id, request,
                        "live-registration-rollback", authorization,
                    )
            assert await admin.fetchval(
                f"SELECT state FROM screening.{table} WHERE tenant_id=$1 AND session_id=$2",
                tenant_id, session_id,
            ) == "ISSUED"
            assert await admin.fetchval(
                "SELECT consumed_at IS NULL FROM ops.identity_recovery_receipts WHERE tenant_id=$1 AND case_id=$2",
                tenant_id, case.case_id,
            )
            assert await admin.fetchval(
                "SELECT count(*) FROM subject.consents WHERE tenant_id=$1 AND consent_record_id=$2",
                tenant_id, consent_id,
            ) == 0
            assert await admin.fetchval(
                "SELECT count(*) FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2",
                tenant_id, session_id,
            ) == 0
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.identity_recovery_registrations WHERE tenant_id=$1 AND case_id=$2",
                tenant_id, case.case_id,
            ) == 0
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.capture_authorization_audit WHERE tenant_id=$1 AND session_id=$2 AND event_kind='CONSUMED'",
                tenant_id, session_id,
            ) == 0
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.audit_logs WHERE tenant_id=$1 AND action='identity-recovery.register' AND resource_id=$2",
                tenant_id, case.case_id,
            ) == 0

            first = await service.register(
                principal, case.case_id, request,
                "live-registration-success", authorization,
            )
            replay = await service.register(
                principal, case.case_id, request,
                "live-registration-success", authorization,
            )
            assert replay.registered_at == first.registered_at
            assert await admin.fetchval(
                f"SELECT state FROM screening.{table} WHERE tenant_id=$1 AND session_id=$2",
                tenant_id, session_id,
            ) == "CONSUMED"
            assert await admin.fetchval(
                "SELECT count(*) FROM subject.consents WHERE tenant_id=$1 AND consent_record_id=$2",
                tenant_id, consent_id,
            ) == 1
            assert await admin.fetchval(
                "SELECT count(*) FROM screening.sessions WHERE tenant_id=$1 AND session_id=$2",
                tenant_id, session_id,
            ) == 1
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.identity_recovery_registrations WHERE tenant_id=$1 AND case_id=$2",
                tenant_id, case.case_id,
            ) == 1
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.capture_authorization_audit WHERE tenant_id=$1 AND session_id=$2 AND event_kind='CONSUMED'",
                tenant_id, session_id,
            ) == 1
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.audit_logs WHERE tenant_id=$1 AND action='identity-recovery.register' AND resource_id=$2",
                tenant_id, case.case_id,
            ) == 1
            if authorization_kind == "migration_permit":
                assert await admin.fetchval(
                    "SELECT evidence_reference FROM ops.capture_authorization_audit WHERE tenant_id=$1 AND session_id=$2 AND event_kind='CONSUMED'",
                    tenant_id, session_id,
                ) == "evidence/ray-513/live-registration"
            else:
                async with tenant_transaction(tenant_pool, tenant_id) as connection:
                    grant = await connection.fetchrow(
                        "SELECT consumed_request_sha256,expected_manifest_sha256 FROM screening.capture_grants WHERE tenant_id=$1 AND session_id=$2",
                        tenant_id, session_id,
                    )
                assert grant["consumed_request_sha256"] == canonical_sha256(session)
                assert grant["expected_manifest_sha256"] == manifest_sha256
        finally:
            await platform_pool.close()
            await activation_pool.close()
            await tenant_pool.close()
            await admin.close()

    asyncio.run(exercise())
