"""Opt-in isolated PostgreSQL role/RLS acceptance for report copies."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import os
from uuid import uuid4

import pytest

from techflex_cloud_foundation.object_store import FileSystemObjectStore
from techflex_cloud_foundation.platform_errors import ResourceNotFound, TenantAccessDenied
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.report_copy.object_store import LocalBasicPdfStore
from techflex_cloud_foundation.server.report_copy.postgres import PostgresLocalBasicCopyRepository
from tests.pg_platform import live_environment
from tests.test_ffp_local_basic_report_copy import copy_request

live_environment()


@pytest.mark.skipif(
    os.environ.get("FEETFORCEPLATE_TEST_ISOLATED") != "1"
    or not os.environ.get("FEETFORCEPLATE_TEST_ADMIN_DSN")
    or not os.environ.get("FEETFORCEPLATE_TEST_TENANT_DSN"),
    reason="isolated PostgreSQL admin and tenant DSNs are not configured",
)
# ffp inserted the session with protocol 'synthetic' while the report document names
# standard-static-balance, which the protocol-binding check rejects. The session now carries the document's
# protocol.
def test_copy_is_tenant_bound_immutable_and_hidden_after_revocation(tmp_path) -> None:
    async def exercise() -> None:
        import asyncpg

        tenant_id, other_tenant = uuid4(), uuid4()
        terminal_id, device_id, subject_id = uuid4(), uuid4(), uuid4()
        request = copy_request()
        admin = await asyncpg.connect(os.environ["FEETFORCEPLATE_TEST_ADMIN_DSN"])
        pool = await asyncpg.create_pool(
            os.environ["FEETFORCEPLATE_TEST_TENANT_DSN"], min_size=1, max_size=2,
        )
        repo = PostgresLocalBasicCopyRepository(
            pool, LocalBasicPdfStore(FileSystemObjectStore(tmp_path)),
        )
        principal = IngestionPrincipal(
            tenant_id=tenant_id, terminal_id=terminal_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
            allow_new_test=False, allow_upload=True,
        )
        try:
            assert await admin.fetchval(
                "SELECT to_regclass('reporting.local_basic_report_copies') IS NOT NULL"
            ), "apply the 0010 migration to the isolated database before this test"
            assert await admin.fetchval(
                "SELECT has_schema_privilege('ffp_seed_backup', 'reporting', 'USAGE')"
            )
            assert await admin.fetchval(
                """SELECT has_table_privilege('ffp_seed_backup',
                   'reporting.local_basic_report_copies', 'SELECT')"""
            )
            for value in (tenant_id, other_tenant):
                await admin.execute(
                    "INSERT INTO iam.tenants (tenant_id, name, status) VALUES ($1,'synthetic copy','ACTIVE')",
                    value,
                )
            await admin.execute(
                """INSERT INTO device.terminals
                   (terminal_id, tenant_id, installation_id, client_public_key, status)
                   VALUES ($1,$2,$3,'synthetic-key','ACTIVE')""",
                terminal_id, tenant_id, uuid4(),
            )
            await admin.execute(
                "INSERT INTO device.devices (device_id, tenant_id, model, status) VALUES ($1,$2,'synthetic','ACTIVE')",
                device_id, tenant_id,
            )
            await admin.execute(
                "INSERT INTO subject.subjects (subject_uuid, tenant_id, status) VALUES ($1,$2,'ACTIVE')",
                subject_id, tenant_id,
            )
            await admin.execute(
                """INSERT INTO subject.consents
                   (consent_record_id, tenant_id, subject_uuid, policy_version, purpose_codes,
                    data_categories, evidence_type, terminal_id, evidence_hash, granted_at)
                   VALUES ($1,$2,$3,'synthetic',ARRAY['SCREENING_SERVICE'],ARRAY['RAW_DATA'],
                           'SUBJECT_CONFIRMED',$4,$5,$6)""",
                request.consent_record_id, tenant_id, subject_id, terminal_id,
                "a" * 64, datetime.now(UTC),
            )
            await admin.execute(
                """INSERT INTO screening.sessions
                   (session_id, tenant_id, terminal_id, device_id, subject_uuid,
                    consent_record_id, test_protocol_id, test_protocol_version,
                    validity_status, ingest_status, started_at, app_version,
                    protocol_profile_version, payload_schema_version,
                    calibration_version, config_snapshot)
                   VALUES ($1,$2,$3,$4,$5,$6,'standard-static-balance','1','VALID','INGESTED',
                           $7,'synthetic','1','1','1','{}'::jsonb)""",
                request.session_id, tenant_id, terminal_id, device_id, subject_id,
                request.consent_record_id, datetime.now(UTC),
            )
            first = await repo.accept(principal, request, "synthetic-key")
            assert first == await repo.accept(principal, request, "synthetic-key")
            assert (await repo.get(tenant_id, request.report_id)).document_json == request.document_json
            with pytest.raises(ResourceNotFound):
                await repo.get(other_tenant, request.report_id)
            await admin.execute(
                "UPDATE subject.consents SET revoked_at=now(), revocation_reason_code='TEST' WHERE consent_record_id=$1",
                request.consent_record_id,
            )
            with pytest.raises(TenantAccessDenied):
                await repo.accept(principal, request, "synthetic-key")
        finally:
            await admin.execute(
                "DELETE FROM reporting.local_basic_report_copies WHERE tenant_id=$1", tenant_id,
            )
            await admin.execute("DELETE FROM screening.sessions WHERE tenant_id=$1", tenant_id)
            await admin.execute("DELETE FROM subject.consents WHERE tenant_id=$1", tenant_id)
            await admin.execute("DELETE FROM subject.subjects WHERE tenant_id=$1", tenant_id)
            await admin.execute("DELETE FROM device.devices WHERE tenant_id=$1", tenant_id)
            await admin.execute("DELETE FROM device.terminals WHERE tenant_id=$1", tenant_id)
            await admin.execute("DELETE FROM iam.tenants WHERE tenant_id=ANY($1::uuid[])", [tenant_id, other_tenant])
            await pool.close()
            await admin.close()

    asyncio.run(exercise())
