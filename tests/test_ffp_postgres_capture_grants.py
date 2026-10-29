from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import os
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.repository import (
    AccessGroupSeed,
    PlatformIdentityRecord,
    PlatformRoleBindingRecord,
    TenantSeed,
)
from techflex_cloud_foundation.server.postgres import tenant_transaction
from tests.pg_platform import live_environment

live_environment()

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


def _group() -> AccessGroupSeed:
    nonce = os.urandom(32)
    return AccessGroupSeed(
        account_id=uuid4(),
        login_name_hmac=hashlib.sha256(b"login" + nonce).digest(),
        account_display_name=f"capture-grant-test-{nonce.hex()[:8]}",
        license_id=uuid4(),
        hardware_id=uuid4(),
        hardware_identity=f"usb-serial-{hashlib.sha256(nonce).hexdigest()[:20]}",
        hardware_model="DO-P4864",
        activation_code_id=uuid4(),
        activation_code_hash=hashlib.sha256(b"activation" + nonce).digest(),
        activation_expires_at=NOW + timedelta(days=7),
        license_valid_from=NOW,
        license_valid_until=NOW + timedelta(days=365),
        enabled_features=("reports.view", "screening.start", "sync.upload"),
    )


def _role_dsns() -> tuple[str, str, str] | None:
    names = (
        "FEETFORCEPLATE_TEST_TENANT_DSN",
        "FEETFORCEPLATE_TEST_ACTIVATION_DSN",
        "FEETFORCEPLATE_TEST_PLATFORM_DSN",
    )
    values = tuple(os.environ.get(name, "") for name in names)
    return values if all(values) else None


@pytest.mark.skipif(
    _role_dsns() is None or not os.environ.get("FEETFORCEPLATE_TEST_ADMIN_DSN"),
    reason="three PostgreSQL application role DSNs and an admin inspection DSN are required",
)
def test_live_concurrent_51st_grant_locks_installation_and_stores_only_hashes():
    async def exercise():
        import asyncpg

        from techflex_cloud_foundation.platform_errors import TenantAccessDenied
        from techflex_cloud_foundation.server.access_control.capture_grants import (
            CaptureGrantService,
        )
        from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
        from techflex_cloud_foundation.server.principal import IngestionPrincipal

        tenant_dsn, activation_dsn, platform_dsn = _role_dsns()
        tenant_pool = await asyncpg.create_pool(tenant_dsn, min_size=2, max_size=3)
        activation_pool = await asyncpg.create_pool(activation_dsn, min_size=1, max_size=1)
        platform_pool = await asyncpg.create_pool(platform_dsn, min_size=1, max_size=1)
        try:
            repository = PostgresAccessRepository(tenant_pool=tenant_pool, activation_pool=activation_pool, platform_pool=platform_pool)
            now = datetime.now(UTC)
            from dataclasses import replace
            group = replace(_group(), license_valid_from=now - timedelta(days=1), license_valid_until=now + timedelta(days=365), activation_expires_at=now + timedelta(days=7))
            tenant = TenantSeed(uuid4(), "Grant concurrency fixture")
            installation_id = uuid4()
            await repository.provision_tenant(tenant, group, created_at=now)
            await repository.activate_account_atomically(
                login_name_hmac=group.login_name_hmac, activation_code_hash=group.activation_code_hash,
                hardware_identity=group.hardware_identity, password_hash="$ffp-scrypt$capture-test",
                installation_id=installation_id, activated_at=now,
                license_key_id="license/2-test", license_document_json='{"schema_version":"license/2"}', license_signature="s" * 86,
            )
            context = IngestionPrincipal(tenant.tenant_id, installation_id, now + timedelta(minutes=10), True, True, group.account_id, group.license_id, group.hardware_identity)
            service = CaptureGrantService(PostgresPlatformRepository(tenant_pool))
            initial = await service.issue(context, 49)
            results = await asyncio.gather(service.issue(context, 1), service.issue(context, 1), return_exceptions=True)
            assert sum(isinstance(result, TenantAccessDenied) for result in results) == 1
            assert sum(not isinstance(result, BaseException) for result in results) == 1
            async with tenant_transaction(tenant_pool, tenant.tenant_id) as connection:
                assert await connection.fetchval("SELECT count(*) FROM screening.capture_grants WHERE installation_id=$1 AND state='ISSUED'", installation_id) == 50
                digest = await connection.fetchval("SELECT token_sha256 FROM screening.capture_grants WHERE session_id=$1", initial.grants[0].session_id)
                assert digest == hashlib.sha256(initial.grants[0].token.get_secret_value().encode()).digest()
            # Both application roles have INSERT-only audit access. Inspection
            # uses an explicitly configured administrative test connection.
            audit_connection = await asyncpg.connect(os.environ["FEETFORCEPLATE_TEST_ADMIN_DSN"])
            try:
                async with audit_connection.transaction():
                    await audit_connection.execute(
                        "SELECT set_config('app.tenant_id', $1, true)", str(tenant.tenant_id)
                    )
                    assert await audit_connection.fetchval(
                        "SELECT count(*) FROM ops.capture_authorization_audit WHERE tenant_id=$1 AND event_kind='ISSUED'",
                        tenant.tenant_id,
                    ) == 50
            finally:
                await audit_connection.close()
            await service.retire(context, initial.grants[0].session_id, "CANCELED")
            with pytest.raises(TenantAccessDenied):
                await service.retire(context, initial.grants[0].session_id, "CANCELED")
            assert len((await service.issue(context, 50)).grants) == 1

            # Two independent connections race to register the same prebound
            # session with different idempotency keys (lost-response retry).
            from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
            from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
            from techflex_cloud_foundation.contracts.cloud import (
                SessionCreateRequest,
                SessionVersions,
                TestProtocol,
            )
            subject_id, consent_id = uuid4(), uuid4()
            async with tenant_transaction(tenant_pool, tenant.tenant_id) as connection:
                await connection.execute(
                    "INSERT INTO subject.subjects (subject_uuid,tenant_id,status) VALUES ($1,$2,'ACTIVE')",
                    subject_id, tenant.tenant_id,
                )
                await connection.execute(
                    """INSERT INTO subject.consents
                       (consent_record_id,tenant_id,subject_uuid,policy_version,purpose_codes,
                        data_categories,evidence_type,evidence_hash,granted_at)
                       VALUES ($1,$2,$3,'test/1',ARRAY['SCREENING_SERVICE'],ARRAY['PRESSURE_RAW'],
                               'OPERATOR_CONFIRMED',$4,$5)""",
                    consent_id, tenant.tenant_id, subject_id, "a" * 64, now,
                )
            grant = initial.grants[1]
            request = SessionCreateRequest(
                session_id=grant.session_id, subject_uuid=subject_id, consent_record_id=consent_id,
                site_id=None, terminal_id=installation_id, client_installation_id=installation_id,
                device_id=group.hardware_id, test_protocol=TestProtocol(id="test", version="1"),
                versions=SessionVersions(app="1", protocol_profile="test/1", payload_schema="raw-segment/1", calibration="test/1"),
                started_at=now,
            )
            authorization = SessionAuthorization(session_id=grant.session_id, kind="grant", token=grant.token, manifest_sha256="b" * 64)
            suspended = replace(context, allow_new_test=False)
            ingestion_repository = PostgresPlatformRepository(tenant_pool)
            results = await asyncio.gather(
                ingestion_repository.create_session(suspended, request, "first-register", authorization),
                ingestion_repository.create_session(suspended, request, "lost-response", authorization),
            )
            assert sorted(result.idempotent_replay for result in results) == [False, True]
            assert (await ingestion_repository.create_session(suspended, request, "first-register", authorization)).idempotent_replay
            async with tenant_transaction(tenant_pool, tenant.tenant_id) as connection:
                assert await connection.fetchval("SELECT count(*) FROM screening.sessions WHERE session_id=$1", grant.session_id) == 1
                row = await connection.fetchrow("SELECT state,consumed_request_sha256,expected_manifest_sha256 FROM screening.capture_grants WHERE session_id=$1", grant.session_id)
                assert tuple(row.values()) == ("CONSUMED", canonical_sha256(request), authorization.manifest_sha256)
            audit_connection = await asyncpg.connect(os.environ["FEETFORCEPLATE_TEST_ADMIN_DSN"])
            try:
                async with audit_connection.transaction():
                    await audit_connection.execute("SELECT set_config('app.tenant_id', $1, true)", str(tenant.tenant_id))
                    assert await audit_connection.fetchval("SELECT count(*) FROM ops.capture_authorization_audit WHERE tenant_id=$1 AND session_id=$2 AND event_kind='CONSUMED'", tenant.tenant_id, grant.session_id) == 1
            finally:
                await audit_connection.close()
        finally:
            await tenant_pool.close()
            await activation_pool.close()
            await platform_pool.close()
    asyncio.run(exercise())


@pytest.mark.skipif(_role_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_live_capture_authorization_role_and_rls_contract() -> None:
    async def exercise() -> None:
        import asyncpg

        tenant_dsn, activation_dsn, platform_dsn = _role_dsns() or ("", "", "")
        tenant = await asyncpg.connect(tenant_dsn)
        activation = await asyncpg.connect(activation_dsn)
        platform = await asyncpg.connect(platform_dsn)
        try:
            for table in (
                "screening.capture_grants",
                "screening.upload_migration_permits",
                "ops.capture_authorization_audit",
            ):
                row = await tenant.fetchrow(
                    "SELECT oid, relrowsecurity, relforcerowsecurity FROM pg_class WHERE oid=$1::regclass",
                    table,
                )
                assert (row["relrowsecurity"], row["relforcerowsecurity"]) == (True, True)
                # OID lookup avoids requiring schema USAGE just to inspect a
                # denied table. Do not grant activation extra schema access.
                assert not await activation.fetchval(
                    "SELECT has_table_privilege(current_user, $1::oid, 'SELECT')", row["oid"]
                )
                assert not await tenant.fetchval(
                    """SELECT EXISTS (
                           SELECT 1 FROM aclexplode(relacl)
                           WHERE grantee=0 AND privilege_type='SELECT'
                       ) FROM pg_class WHERE oid=$1::regclass""",
                    table,
                )
            assert await tenant.fetchval(
                "SELECT has_table_privilege(current_user, 'screening.capture_grants', 'INSERT')"
            )
            assert not await tenant.fetchval(
                "SELECT has_table_privilege(current_user, 'screening.upload_migration_permits', 'INSERT')"
            )
            assert await platform.fetchval(
                "SELECT has_table_privilege(current_user, 'screening.upload_migration_permits', 'INSERT')"
            )
        finally:
            await tenant.close()
            await activation.close()
            await platform.close()

    asyncio.run(exercise())


@pytest.mark.skipif(_role_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_live_capture_authorization_operations_are_tenant_scoped_and_one_way() -> None:
    async def exercise() -> None:
        import asyncpg

        tenant_dsn, activation_dsn, platform_dsn = _role_dsns() or ("", "", "")
        tenant_pool = await asyncpg.create_pool(tenant_dsn, min_size=1, max_size=2)
        activation_pool = await asyncpg.create_pool(activation_dsn, min_size=1, max_size=2)
        platform_pool = await asyncpg.create_pool(platform_dsn, min_size=1, max_size=2)
        repository = PostgresAccessRepository(
            tenant_pool=tenant_pool,
            activation_pool=activation_pool,
            platform_pool=platform_pool,
        )
        first, second = (TenantSeed(uuid4(), f"Capture grant test {uuid4()}") for _ in range(2))
        first_group, second_group = _group(), _group()
        first_installation_id, second_installation_id = uuid4(), uuid4()
        grant_session_id, permit_session_id = uuid4(), uuid4()
        request_digest, manifest_digest = "a" * 64, "b" * 64
        try:
            for tenant, group, installation_id in (
                (first, first_group, first_installation_id),
                (second, second_group, second_installation_id),
            ):
                await repository.provision_tenant(tenant, group, created_at=NOW)
                activated = await repository.activate_account_atomically(
                    login_name_hmac=group.login_name_hmac,
                    activation_code_hash=group.activation_code_hash,
                    hardware_identity=group.hardware_identity,
                    password_hash="$ffp-scrypt$capture-test",
                    installation_id=installation_id,
                    activated_at=NOW + timedelta(minutes=1),
                    license_key_id="license/2-test",
                    license_document_json='{"schema_version":"license/2"}',
                    license_signature="s" * 86,
                )
                assert activated.installation.client_installation_id == installation_id

            async with tenant_transaction(tenant_pool, first.tenant_id) as connection:
                await connection.execute(
                    """INSERT INTO screening.capture_grants
                       (tenant_id,session_id,installation_id,account_id,license_id,
                        hardware_id,token_sha256)
                       VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                    first.tenant_id, grant_session_id, first_installation_id,
                    first_group.account_id, first_group.license_id,
                    first_group.hardware_id, os.urandom(32),
                )
                assert await connection.fetchval(
                    "SELECT state FROM screening.capture_grants WHERE session_id=$1",
                    grant_session_id,
                ) == "ISSUED"
                await connection.execute(
                    """UPDATE screening.capture_grants
                       SET state='CONSUMED',consumed_request_sha256=$3,
                           expected_manifest_sha256=$4
                       WHERE tenant_id=$1 AND session_id=$2""",
                    first.tenant_id, grant_session_id, request_digest, manifest_digest,
                )
                assert await connection.fetchval(
                    "SELECT state FROM screening.capture_grants WHERE session_id=$1",
                    grant_session_id,
                ) == "CONSUMED"

                with pytest.raises(asyncpg.PostgresError):
                    async with connection.transaction():
                        await connection.execute(
                            """UPDATE screening.capture_grants
                               SET expected_manifest_sha256=$3
                               WHERE tenant_id=$1 AND session_id=$2""",
                            first.tenant_id, grant_session_id, "c" * 64,
                        )
                with pytest.raises(asyncpg.PostgresError):
                    async with connection.transaction():
                        await connection.execute(
                            """UPDATE screening.capture_grants SET state='ISSUED'
                               WHERE tenant_id=$1 AND session_id=$2""",
                            first.tenant_id, grant_session_id,
                        )
                with pytest.raises(asyncpg.InsufficientPrivilegeError):
                    async with connection.transaction():
                        await connection.execute(
                            """UPDATE screening.capture_grants SET account_id=$3
                               WHERE tenant_id=$1 AND session_id=$2""",
                            first.tenant_id, grant_session_id, second_group.account_id,
                        )

            async with tenant_transaction(tenant_pool, second.tenant_id) as connection:
                assert await connection.fetchval(
                    "SELECT count(*) FROM screening.capture_grants WHERE session_id=$1",
                    grant_session_id,
                ) == 0
                with pytest.raises(asyncpg.InsufficientPrivilegeError):
                    async with connection.transaction():
                        await connection.execute(
                            """INSERT INTO screening.capture_grants
                               (tenant_id,session_id,installation_id,account_id,license_id,
                                hardware_id,token_sha256)
                               VALUES ($1,$2,$3,$4,$5,$6,$7)""",
                            first.tenant_id, uuid4(), first_installation_id,
                            first_group.account_id, first_group.license_id,
                            first_group.hardware_id, os.urandom(32),
                        )
                assert await connection.fetchval(
                    """UPDATE screening.capture_grants SET state='RETIRED'
                       WHERE tenant_id=$1 AND session_id=$2 RETURNING session_id""",
                    first.tenant_id, grant_session_id,
                ) is None

            approver = PlatformIdentityRecord(
                platform_identity_id=uuid4(), login_name_hmac=os.urandom(32),
                display_name="Capture Permit Test Owner",
                password_hash="$ffp-scrypt$platform", status="ACTIVE",
                token_version=1, created_at=NOW,
            )
            await repository.create_platform_identity(
                approver,
                (PlatformRoleBindingRecord(
                    uuid4(), approver.platform_identity_id, PlatformRole.OWNER, NOW,
                ),),
            )
            permit_args = (
                first.tenant_id, permit_session_id, first_installation_id,
                first_group.account_id, first_group.license_id,
                first_group.hardware_id, os.urandom(32), request_digest,
                manifest_digest, approver.platform_identity_id,
                "LEGACY_VALID_SESSION_REVIEWED", "evidence/ray-513/test",
            )
            permit_sql = """INSERT INTO screening.upload_migration_permits
                (tenant_id,session_id,installation_id,account_id,license_id,
                 hardware_id,token_sha256,consumed_request_sha256,
                 expected_manifest_sha256,approver_id,approval_reason,evidence_reference)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"""
            async with tenant_transaction(tenant_pool, first.tenant_id) as connection:
                with pytest.raises(asyncpg.InsufficientPrivilegeError):
                    async with connection.transaction():
                        await connection.execute(permit_sql, *permit_args)
            from dataclasses import replace

            from techflex_cloud_foundation.contracts.capture_grants import (
                UploadMigrationPermitRequest,
            )
            from techflex_cloud_foundation.platform_errors import TenantAccessDenied
            from techflex_cloud_foundation.server.access_auth import PlatformAccessContext
            from techflex_cloud_foundation.server.access_control.capture_grants import (
                CaptureGrantService,
            )
            from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository

            context = PlatformAccessContext(approver.platform_identity_id, frozenset({PlatformRole.OWNER}),
                                            1, datetime.now(UTC) + timedelta(minutes=10))
            service = CaptureGrantService(PostgresPlatformRepository(tenant_pool, platform_pool=platform_pool))
            request = UploadMigrationPermitRequest(
                tenant_id=first.tenant_id, session_id=permit_session_id, installation_id=first_installation_id,
                account_id=first_group.account_id, license_id=first_group.license_id,
                hardware_id=first_group.hardware_identity, request_sha256=request_digest,
                manifest_sha256=manifest_digest, evidence_reference="evidence/ray-513/test",
                original_envelope_sha256="d" * 64, original_subject_uuid=uuid4(),
                final_subject_uuid=uuid4(), consent_record_id=uuid4(), consent_sha256="c" * 64,
                reason="LEGACY_VALID_SESSION_REVIEWED", identity_conflict=False, reconciliation_reference=None,
                local_valid_reviewed=True, immutable_manifest_reviewed=True,
                original_consent_reviewed=True, historical_authorization_reviewed=True,
            )
            for denied_context, denied_request in (
                (replace(context, roles=frozenset({PlatformRole.SUPPORT})), request),
                (context, request.model_copy(update={"account_id": second_group.account_id})),
                (context, request.model_copy(update={"tenant_id": uuid4()})),
                (context, request.model_copy(update={"identity_conflict": True, "reconciliation_reference": uuid4()})),
            ):
                with pytest.raises(TenantAccessDenied):
                    await service.approve_migration(denied_context, denied_request)
            async with platform_pool.acquire() as connection:
                assert await connection.fetchval(
                    "SELECT count(*) FROM ops.access_audit_events WHERE actor_id=$1 AND action='UPLOAD_MIGRATION_PERMIT_REJECTED'",
                    approver.platform_identity_id,
                ) == 4
            results = await asyncio.gather(service.approve_migration(context, request),
                                           service.approve_migration(context, request), return_exceptions=True)
            assert sum(isinstance(result, TenantAccessDenied) for result in results) == 1
            permit = next(result for result in results if not isinstance(result, BaseException))
            async with tenant_transaction(platform_pool, first.tenant_id) as connection:
                assert await connection.fetchval(
                    "SELECT state FROM screening.upload_migration_permits WHERE session_id=$1",
                    permit_session_id,
                ) == "ISSUED"
                row = await connection.fetchrow(
                    "SELECT * FROM screening.upload_migration_permits WHERE session_id=$1", permit_session_id)
                assert row["token_sha256"] == hashlib.sha256(permit.token.get_secret_value().encode()).digest()
                assert row["approval_reason"] == request.reason
                assert row["approver_id"] == context.platform_identity_id
                assert permit.token.get_secret_value() not in repr(dict(row))
            async with tenant_transaction(platform_pool, second.tenant_id) as connection:
                with pytest.raises(asyncpg.InsufficientPrivilegeError):
                    async with connection.transaction():
                        await connection.execute(
                            permit_sql,
                            first.tenant_id, uuid4(), *permit_args[2:6],
                            os.urandom(32), *permit_args[7:],
                        )
            async with tenant_transaction(tenant_pool, first.tenant_id) as connection:
                await connection.execute(
                    """UPDATE screening.upload_migration_permits SET state='CONSUMED'
                       WHERE tenant_id=$1 AND session_id=$2""",
                    first.tenant_id, permit_session_id,
                )
                with pytest.raises(asyncpg.PostgresError):
                    async with connection.transaction():
                        await connection.execute(
                            """UPDATE screening.upload_migration_permits SET state='ISSUED'
                               WHERE tenant_id=$1 AND session_id=$2""",
                            first.tenant_id, permit_session_id,
                        )
            async with tenant_transaction(tenant_pool, second.tenant_id) as connection:
                assert await connection.fetchval(
                    "SELECT count(*) FROM screening.upload_migration_permits WHERE session_id=$1",
                    permit_session_id,
                ) == 0
        finally:
            await tenant_pool.close()
            await activation_pool.close()
            await platform_pool.close()

    asyncio.run(exercise())


@pytest.mark.skipif(_role_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_live_suspended_bare_session_replay_preserves_digest_and_tenant_guards() -> None:
    async def exercise() -> None:
        from dataclasses import replace

        import asyncpg

        from techflex_cloud_foundation.contracts.access_control import LicenseState
        from techflex_cloud_foundation.contracts.cloud import (
            SessionCreateRequest,
            SessionVersions,
            TestProtocol,
        )
        from techflex_cloud_foundation.object_store import InMemoryObjectStore
        from techflex_cloud_foundation.platform_errors import (
            IdempotencyConflict,
            TenantAccessDenied,
        )
        from techflex_cloud_foundation.server.ingestion_service import IngestionService
        from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
        from techflex_cloud_foundation.server.principal import IngestionPrincipal

        tenant_dsn, activation_dsn, platform_dsn = _role_dsns() or ("", "", "")
        tenant_pool = await asyncpg.create_pool(tenant_dsn, min_size=1, max_size=2)
        activation_pool = await asyncpg.create_pool(activation_dsn, min_size=1, max_size=2)
        platform_pool = await asyncpg.create_pool(platform_dsn, min_size=1, max_size=2)
        access = PostgresAccessRepository(
            tenant_pool=tenant_pool, activation_pool=activation_pool, platform_pool=platform_pool
        )
        now = datetime.now(UTC)
        try:
            principals = []
            groups = []
            for _ in range(2):
                tenant = TenantSeed(uuid4(), f"Bare replay regression {uuid4()}")
                group = replace(
                    _group(), license_valid_from=now - timedelta(days=1),
                    license_valid_until=now + timedelta(days=365),
                    activation_expires_at=now + timedelta(days=7),
                )
                installation_id = uuid4()
                await access.provision_tenant(tenant, group, created_at=now)
                await access.activate_account_atomically(
                    login_name_hmac=group.login_name_hmac,
                    activation_code_hash=group.activation_code_hash,
                    hardware_identity=group.hardware_identity,
                    password_hash="$ffp-scrypt$bare-replay-test",
                    installation_id=installation_id, activated_at=now,
                    license_key_id="license/2-test", license_document_json='{"schema_version":"license/2"}',
                    license_signature="s" * 86,
                )
                principals.append(IngestionPrincipal(
                    tenant.tenant_id, installation_id, now + timedelta(minutes=10),
                    True, True, group.account_id, group.license_id, group.hardware_identity,
                ))
                groups.append(group)
            active, other_tenant = principals
            subject_id, consent_id = uuid4(), uuid4()
            async with tenant_transaction(tenant_pool, active.tenant_id) as connection:
                await connection.execute(
                    "INSERT INTO subject.subjects (subject_uuid,tenant_id,status) VALUES ($1,$2,'ACTIVE')",
                    subject_id, active.tenant_id,
                )
                await connection.execute(
                    """INSERT INTO subject.consents
                       (consent_record_id,tenant_id,subject_uuid,policy_version,purpose_codes,
                        data_categories,evidence_type,evidence_hash,granted_at)
                       VALUES ($1,$2,$3,'test/1',ARRAY['SCREENING_SERVICE'],ARRAY['PRESSURE_RAW'],
                               'OPERATOR_CONFIRMED',$4,$5)""",
                    consent_id, active.tenant_id, subject_id, "a" * 64, now,
                )
            request = SessionCreateRequest(
                session_id=uuid4(), subject_uuid=subject_id, consent_record_id=consent_id,
                site_id=None, terminal_id=active.terminal_id,
                client_installation_id=active.terminal_id, device_id=groups[0].hardware_id,
                test_protocol=TestProtocol(id="test", version="1"),
                versions=SessionVersions(app="1", protocol_profile="test/1", payload_schema="raw-segment/1", calibration="test/1"),
                started_at=now,
            )
            repository = PostgresPlatformRepository(tenant_pool)
            service = IngestionService(
                repository, InMemoryObjectStore(),
                supported_payload_schemas={"raw-segment/1"},
                supported_manifest_schemas={"session-manifest/1"},
            )
            key = f"bare-{request.session_id}"
            created = await service.create_session(active, request, key)
            assert not created.idempotent_replay
            license_record = await access.license(groups[0].license_id)
            await access.replace_license(
                license_id=license_record.license_id, expected_version=license_record.version,
                status=LicenseState.SUSPENDED, issued_at=now + timedelta(seconds=1),
                valid_until=license_record.valid_until, key_id="license/2-test",
                document_json='{"schema_version":"license/2"}', signature="t" * 86,
            )
            suspended = replace(active, allow_new_test=False)
            replay = await service.create_session(suspended, request, key)
            assert replay.session_id == created.session_id
            assert replay.idempotent_replay

            new_request = request.model_copy(update={"session_id": uuid4()})
            new_key = f"blocked-{new_request.session_id}"
            with pytest.raises(TenantAccessDenied):
                await service.create_session(suspended, new_request, new_key)
            with pytest.raises(IdempotencyConflict):
                await service.create_session(suspended, request.model_copy(update={"config_snapshot": {"changed": True}}), key)
            with pytest.raises(IdempotencyConflict):
                await service.create_session(suspended, request.model_copy(update={"client_installation_id": uuid4()}), key)
            with pytest.raises(TenantAccessDenied):
                await service.create_session(other_tenant, request, key)
            with pytest.raises(TenantAccessDenied):
                await service.create_session(replace(suspended, terminal_id=uuid4()), request, key)

            async with tenant_transaction(tenant_pool, active.tenant_id) as connection:
                assert await connection.fetchval("SELECT count(*) FROM screening.sessions WHERE tenant_id=$1", active.tenant_id) == 1
                assert await connection.fetchval("SELECT count(*) FROM screening.sessions WHERE session_id=$1", new_request.session_id) == 0
                assert await connection.fetchval("SELECT count(*) FROM ops.idempotency_keys WHERE tenant_id=$1 AND scope='session.create' AND idempotency_key=$2", active.tenant_id, new_key) == 0
                assert await connection.fetchval("SELECT count(*) FROM screening.capture_grants WHERE tenant_id=$1", active.tenant_id) == 0
            async with tenant_transaction(tenant_pool, other_tenant.tenant_id) as connection:
                assert await connection.fetchval("SELECT count(*) FROM screening.sessions WHERE session_id=$1", request.session_id) == 0
                assert await connection.fetchval("SELECT count(*) FROM ops.idempotency_keys WHERE tenant_id=$1 AND scope='session.create' AND idempotency_key=$2", other_tenant.tenant_id, key) == 0
        finally:
            await tenant_pool.close()
            await activation_pool.close()
            await platform_pool.close()

    asyncio.run(exercise())
