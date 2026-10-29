"""Opt-in PostgreSQL role/RLS check for administrative session holds."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
import os
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.platform_errors import ResourceNotFound
from techflex_cloud_foundation.server.access_auth import PlatformAccessContext
from techflex_cloud_foundation.server.session_hold.models import (
    HoldApplyRequest,
    HoldDispositionRequest,
    HoldReleaseRequest,
)
from techflex_cloud_foundation.server.session_hold.postgres import PostgresSessionHoldRepository
from techflex_cloud_foundation.server.session_hold.service import SessionHoldService
from tests.pg_platform import live_environment

live_environment()


@pytest.mark.skipif(
    not os.environ.get("FEETFORCEPLATE_TEST_ADMIN_DSN")
    or not os.environ.get("FEETFORCEPLATE_TEST_PLATFORM_DSN"),
    reason="isolated PostgreSQL admin and platform DSNs are not configured",
)
def test_hold_disposition_and_release_preserve_ingested_session_under_live_rls() -> None:
    async def exercise() -> None:
        import asyncpg

        tenant_id, other_tenant_id = uuid4(), uuid4()
        terminal_id, device_id, subject_id, consent_id, session_id = (uuid4() for _ in range(5))
        admin = await asyncpg.connect(os.environ["FEETFORCEPLATE_TEST_ADMIN_DSN"])
        platform_pool = await asyncpg.create_pool(
            os.environ["FEETFORCEPLATE_TEST_PLATFORM_DSN"], min_size=1, max_size=2,
        )
        try:
            for value in (tenant_id, other_tenant_id):
                await admin.execute(
                    "INSERT INTO iam.tenants (tenant_id, name, status) VALUES ($1,'RAY-99 hold test','ACTIVE')",
                    value,
                )
            await admin.execute(
                """INSERT INTO device.terminals
                   (terminal_id, tenant_id, installation_id, client_public_key, status)
                   VALUES ($1,$2,$3,'test-public-key','ACTIVE')""",
                terminal_id, tenant_id, uuid4(),
            )
            await admin.execute(
                "INSERT INTO device.devices (device_id, tenant_id, model, status) VALUES ($1,$2,'test','ACTIVE')",
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
                   VALUES ($1,$2,$3,'test',ARRAY['SCREENING'],ARRAY['RAW_DATA'],
                           'SUBJECT_CONFIRMED',$4,$5,$6)""",
                consent_id, tenant_id, subject_id, terminal_id, "a" * 64, datetime.now(UTC),
            )
            await admin.execute(
                """INSERT INTO screening.sessions
                   (session_id, tenant_id, terminal_id, device_id, subject_uuid,
                    consent_record_id, test_protocol_id, test_protocol_version,
                    validity_status, ingest_status, started_at, app_version,
                    protocol_profile_version, payload_schema_version,
                    calibration_version, config_snapshot)
                   VALUES ($1,$2,$3,$4,$5,$6,'test','1','VALID','INGESTED',
                           $7,'test','1','1','1','{}'::jsonb)""",
                session_id, tenant_id, terminal_id, device_id, subject_id,
                consent_id, datetime.now(UTC),
            )
            actor = PlatformAccessContext(
                uuid4(), frozenset({PlatformRole.OWNER}), 1, datetime.now(UTC),
            )
            service = SessionHoldService(PostgresSessionHoldRepository(platform_pool))
            apply = HoldApplyRequest(
                tenant_id=tenant_id, session_id=session_id,
                ticket_reference="SYNTHETIC-INC-99", reason_code="IDENTITY_UNVERIFIED",
            )
            first = await service.apply(actor, apply, "synthetic-hold-key")
            assert first.state == "HELD"
            assert await service.apply(actor, apply, "synthetic-hold-key") == first
            assert (await service.status(actor, tenant_id, session_id)).held
            with pytest.raises(ResourceNotFound):
                await service.status(actor, other_tenant_id, session_id)
            with pytest.raises(ResourceNotFound):
                await service.apply(
                    actor, apply.model_copy(update={"tenant_id": other_tenant_id}),
                    "synthetic-wrong-tenant-key",
                )
            assert await admin.fetchval(
                "SELECT ingest_status FROM screening.sessions WHERE session_id=$1", session_id,
            ) == "INGESTED"
            restricted_session_id, policy_id = uuid4(), uuid4()
            await admin.execute(
                """INSERT INTO screening.sessions
                   (session_id, tenant_id, terminal_id, device_id, subject_uuid,
                    consent_record_id, test_protocol_id, test_protocol_version,
                    validity_status, ingest_status, started_at, app_version,
                    protocol_profile_version, payload_schema_version,
                    calibration_version, config_snapshot)
                   SELECT $1, tenant_id, terminal_id, device_id, subject_uuid,
                          consent_record_id, test_protocol_id, test_protocol_version,
                          validity_status, ingest_status, started_at, app_version,
                          protocol_profile_version, payload_schema_version,
                          calibration_version, config_snapshot
                   FROM screening.sessions WHERE session_id=$2""",
                restricted_session_id, session_id,
            )
            await admin.execute(
                """INSERT INTO ops.retention_policies
                   (retention_policy_id, tenant_id, data_category, policy_version,
                    legal_basis, effective_at, approved_by)
                   VALUES ($1,$2,'RAW_DATA','synthetic-1','synthetic-test-basis',$3,$4)""",
                policy_id, tenant_id, datetime.now(UTC), actor.platform_identity_id,
            )
            await service.apply(actor, apply.model_copy(update={
                "session_id": restricted_session_id,
            }), "synthetic-restrict-hold-key")
            restricted = await service.dispose(actor, HoldDispositionRequest(
                tenant_id=tenant_id, session_id=restricted_session_id,
                ticket_reference="SYNTHETIC-INC-99",
                decision_code="RESTRICT_AND_DISPOSE",
                evidence_reference="SYNTHETIC-RESTRICTION",
                retention_policy_id=policy_id,
            ), "synthetic-restrict-disposition-key")
            assert restricted.planned_job_status == "PLANNED"
            assert (await service.status(actor, tenant_id, restricted_session_id)).held
            assert await admin.fetchval(
                "SELECT status FROM ops.data_disposition_jobs WHERE data_disposition_job_id=$1",
                restricted.planned_job_id,
            ) == "PLANNED"
            assert await admin.fetchval(
                "SELECT count(*) FROM ops.session_hold_events WHERE hold_id=$1 AND action='APPLY'",
                first.hold_id,
            ) == 1
            decided = await service.dispose(actor, HoldDispositionRequest(
                tenant_id=tenant_id, session_id=session_id,
                ticket_reference="SYNTHETIC-INC-99",
                decision_code="RETAIN_WITH_VALID_BASIS",
                evidence_reference="SYNTHETIC-EVIDENCE",
                valid_basis_reference="SYNTHETIC-BASIS",
            ), "synthetic-disposition-key")
            assert decided.state == "HELD"
            released = await service.release(actor, HoldReleaseRequest(
                tenant_id=tenant_id, session_id=session_id,
                ticket_reference="SYNTHETIC-INC-99",
                evidence_reference="SYNTHETIC-RELEASE",
            ), "synthetic-release-key")
            assert released.state == "RELEASED"
            assert not (await service.status(actor, tenant_id, session_id)).held
            assert await admin.fetchval(
                "SELECT ingest_status FROM screening.sessions WHERE session_id=$1", session_id,
            ) == "INGESTED"
        finally:
            await platform_pool.close()
            await admin.close()

    asyncio.run(exercise())
