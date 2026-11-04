"""RAY-953: real PostgreSQL upgrade, tenant boundaries and wire-identity reloads."""
from __future__ import annotations

import copy
from uuid import UUID, uuid4

import pytest

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import IdempotencyConflict, SegmentDigestConflict
from techflex_cloud_foundation.schema import DEFAULT_PLAN, apply_migrations
from techflex_cloud_foundation.server.ingestion_contracts import parse_registered
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository, tenant_transaction
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests.test_ffp_postgres_platform_live import BIN, TENANT_LOGIN, Harness, _run, asyncpg
from tests.test_ffp_postgres_platform_live import cluster as cluster
from tests.test_registry_http_ingestion import vector
from tests.test_schema_migrations import ROLE_STEP

pytestmark = pytest.mark.skipif(BIN is None, reason="no PostgreSQL server installation found")


def service(repository, objects=None):
    return IngestionService(
        repository, objects or SegmentObjectStore(InMemoryObjectStore())
    )


def core_session(terminal):
    document = vector("session-create-vectors.json", "gait-session-archive/1")["session"][
        "document"
    ]
    document.update(session_id=str(uuid4()), client_installation_id=str(terminal), site_id=None)
    return document


async def insert_segment(conn, tenant, session_id, schema, profile, frame, *, index=0):
    return await conn.execute(
        """INSERT INTO screening.session_segments (
            session_segment_id, tenant_id, session_id, segment_index, object_key,
            sha256, size_bytes, start_frame_index, frame_count, start_monotonic_ns,
            end_monotonic_ns, payload_schema_version, compression, cipher, status,
            segment_profile
        ) VALUES ($1,$2,$3,$4,$5,$6,3,$7,$8,$9,$10,$11,$12,$13,'VERIFIED',$14)""",
        uuid4(), tenant, session_id, index, f"test/{uuid4()}", "1" * 64,
        0 if frame else None, 1 if frame else None, 1 if frame else None,
        2 if frame else None, schema, "none" if frame else None,
        "aes-256-gcm" if frame else None, profile,
    )


@pytest.mark.parametrize("schema,profile,frame,accepted", [
    ("raw-segment/1", "byte-segment", False, False),
    ("insole-session-archive/1", "frame-segment", True, False),
    ("test-registered/1", None, True, False),
    ("test-registered/1", "unknown-profile", True, False),
    ("test-registered/1", "byte-segment", True, False),
    ("test-registered/1", "frame-segment", False, False),
    ("test-registered/1", "byte-segment", False, True),
    ("test-registered/1", "frame-segment", True, True),
])
def test_segment_profile_constraints_do_not_depend_on_new_product_names(
    cluster, schema, profile, frame, accepted,
):
    async def body(h):
        tenant = await h.tenant()
        session_id, _ = await h.session(tenant)
        if accepted:
            await insert_segment(h.admin, tenant.tenant_id, session_id, schema, profile, frame)
        else:
            with pytest.raises(asyncpg.CheckViolationError):
                await insert_segment(h.admin, tenant.tenant_id, session_id, schema, profile, frame)
    _run(cluster, body)


@pytest.mark.parametrize("schema,profile,frames,accepted", [
    ("session-manifest/1", "byte-segment", None, False),
    ("insole-session-manifest/1", "frame-segment", 1, False),
    ("test-manifest/1", None, 1, False),
    ("test-manifest/1", "unknown-profile", 1, False),
    ("test-manifest/1", "frame-segment", None, False),
    ("test-manifest/1", "byte-segment", 1, False),
    ("test-manifest/1", "frame-segment", 1, True),
    ("test-manifest/1", "byte-segment", None, True),
])
def test_manifest_profile_constraints_preserve_raw_and_byte_shapes(
    cluster, schema, profile, frames, accepted,
):
    async def body(h):
        tenant = await h.tenant()
        session_id, _ = await h.session(tenant)

        async def insert():
            await h.admin.execute(
                """INSERT INTO screening.session_manifests (
                    manifest_id,tenant_id,session_id,schema_version,manifest_sha256,
                    object_key,segment_count,total_frames,total_bytes,manifest_json,
                    verification_status,segment_profile
                ) VALUES ($1,$2,$3,$4,$5,$6,1,$7,3,'{}','PENDING',$8)""",
                uuid4(), tenant.tenant_id, session_id, schema, "1" * 64,
                f"manifest/{uuid4()}", frames, profile,
            )
        if accepted:
            await insert()
        else:
            with pytest.raises(asyncpg.CheckViolationError):
                await insert()
    _run(cluster, body)


def test_original_session_canonical_identity_survives_fresh_repository(cluster):
    async def body(h):
        tenant = await h.tenant()
        original = core_session(tenant.terminal_id)
        original["started_at"] = "2026-11-04T13:30:00.120000+08:00"
        original["config_snapshot"] = {"large": 1e20, "small": 1e-7, "unicode": "步态"}
        current = service(h.repository)
        request = current.parse_session(original)
        await current.create_session(tenant.principal, request, "first:" + original["session_id"])
        fresh_repository = PostgresPlatformRepository(h.pool)
        reloaded = await fresh_repository.session(tenant.principal, UUID(original["session_id"]))
        assert canonical_sha256(reloaded.request) == canonical_sha256(original)
        assert reloaded.request_sha256 == canonical_sha256(original)
        assert reloaded.request.model_dump(mode="json") == original
        fresh = service(fresh_repository)
        replay = await fresh.create_session(
            tenant.principal, fresh.parse_session(original), "new-key:" + original["session_id"]
        )
        assert replay.idempotent_replay
        changed = copy.deepcopy(original)
        changed["started_at"] = "2026-11-04T05:30:00.120000Z"
        with pytest.raises(IdempotencyConflict):
            await fresh.create_session(
                tenant.principal, fresh.parse_session(changed), "changed:" + original["session_id"]
            )
    _run(cluster, body)


def test_omitted_optional_mapping_is_not_inserted_into_reloaded_identity(cluster):
    async def body(h):
        tenant = await h.tenant()
        original = core_session(tenant.terminal_id)
        original.pop("config_snapshot", None)
        current = service(h.repository)
        await current.create_session(
            tenant.principal, current.parse_session(original), "create:" + original["session_id"]
        )
        fresh = PostgresPlatformRepository(h.pool)
        record = await fresh.session(tenant.principal, UUID(original["session_id"]))
        assert "config_snapshot" not in record.request.model_dump(mode="json")
        assert canonical_sha256(record.request) == canonical_sha256(original)
    _run(cluster, body)


def test_registry_metadata_retry_with_changed_offset_conflicts_after_reload(cluster):
    async def body(h):
        tenant = await h.tenant()
        objects = SegmentObjectStore(InMemoryObjectStore())
        current = service(h.repository, objects)
        original = core_session(tenant.terminal_id)
        session_id = UUID(original["session_id"])
        await current.create_session(
            tenant.principal, current.parse_session(original), "create:" + str(session_id)
        )
        schema = "gait-session-archive/1"
        first = vector("payload-schema-vectors.json", schema)["segments"][0]
        metadata = first["metadata"]
        metadata["offset"] = 0
        parsed = parse_registered(metadata, "segment", schema, current.payload_registry)
        await h.repository.register_segment(
            tenant.principal, session_id, parsed, "part/" + str(uuid4())
        )
        fresh_repository = PostgresPlatformRepository(h.pool)
        record = await fresh_repository.get_segment(tenant.principal, session_id, 0)
        assert record.metadata.model_dump(mode="json")["offset"] == 0
        changed = {**metadata, "offset": 1}
        altered = parse_registered(changed, "segment", schema, current.payload_registry)
        # The repository insert-race path must agree with the service's existing-record path.
        with pytest.raises(SegmentDigestConflict):
            await fresh_repository.register_segment(
                tenant.principal, session_id, altered, "other/" + str(uuid4())
            )

        async def unread_body():
            pytest.fail("a conflicting retry must not consume its body")
            yield b""
        fresh = service(fresh_repository, objects)
        with pytest.raises(SegmentDigestConflict):
            await fresh.put_segment(tenant.principal, session_id, 0, altered, unread_body())
        assert await h.admin.fetchval(
            "SELECT count(*) FROM ops.outbox_events WHERE aggregate_id::text=$1", str(session_id)
        ) == 0
    _run(cluster, body)


def test_nullable_business_columns_do_not_weaken_tenant_rls_or_foreign_keys(cluster):
    async def body(h):
        tenants = [await h.tenant(), await h.tenant()]
        ids = []
        for tenant in tenants:
            current = service(h.repository)
            original = core_session(tenant.terminal_id)
            await current.create_session(
                tenant.principal, current.parse_session(original),
                "create:" + original["session_id"]
            )
            ids.append(UUID(original["session_id"]))
        for index, tenant in enumerate(tenants):
            async with tenant_transaction(h.pool, tenant.tenant_id) as conn:
                rows = await conn.fetch("SELECT session_id FROM screening.sessions")
                assert ids[index] in {row["session_id"] for row in rows}
                assert ids[1 - index] not in {row["session_id"] for row in rows}
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await h.admin.execute(
                    "UPDATE screening.sessions SET terminal_id=$1 WHERE session_id=$2",
                    tenants[1 - index].terminal_id, ids[index],
                )
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await insert_segment(
                    h.admin, tenant.tenant_id, ids[1 - index],
                    "gait-session-archive/1", "byte-segment", False,
                )
    _run(cluster, body)


def test_forward_upgrade_preserves_existing_raw_and_insole_rows(cluster):
    async def body(h):
        database = "registry_upgrade_" + uuid4().hex
        await h.admin.execute(f'CREATE DATABASE "{database}"')
        conn = await asyncpg.connect(
            host=cluster.socket_dir, port=cluster.port, user="postgres", database=database
        )
        try:
            old_plan = tuple(step for step in DEFAULT_PLAN if not step.step_id.startswith("0020"))
            assert len(old_plan) < len(DEFAULT_PLAN), "0020 must be in the shipped migration plan"
            await apply_migrations(conn, plan=old_plan)
            await conn.execute(ROLE_STEP)
            pool = await asyncpg.create_pool(
                host=cluster.socket_dir, port=cluster.port, user=TENANT_LOGIN,
                database=database, min_size=1, max_size=2,
            )
            try:
                old = Harness(conn, pool)
                tenant = await old.tenant()
                subject, consent = await old.subject_and_consent(tenant)
                session_ids = []
                for schema, frame in (("raw-segment/1", True), ("insole-session-archive/1", False)):
                    session_id = uuid4()
                    session_ids.append(session_id)
                    await conn.execute(
                        """INSERT INTO screening.sessions (
                            session_id,tenant_id,terminal_id,device_id,subject_uuid,
                            consent_record_id,test_protocol_id,test_protocol_version,
                            started_at,app_version,protocol_profile_version,payload_schema_version,
                            calibration_version,config_snapshot
                        ) VALUES ($1,$2,$3,$4,$5,$6,'test','1','2026-11-04T00:00:00Z',
                            '1','profile/1',$7,'calibration/1','{}')""",
                        session_id, tenant.tenant_id, tenant.terminal_id, tenant.device_id,
                        subject, consent, schema,
                    )
                    await conn.execute(
                        """INSERT INTO screening.session_segments (
                            session_segment_id,tenant_id,session_id,segment_index,object_key,
                            sha256,size_bytes,start_frame_index,frame_count,start_monotonic_ns,
                            end_monotonic_ns,payload_schema_version,compression,cipher,status
                        ) VALUES ($1,$2,$3,0,$4,$5,3,$6,$7,$8,$9,$10,$11,$12,'VERIFIED')""",
                        uuid4(), tenant.tenant_id, session_id, f"old/{uuid4()}", "1" * 64,
                        0 if frame else None, 1 if frame else None, 1 if frame else None,
                        2 if frame else None, schema, "none" if frame else None,
                        "aes-256-gcm" if frame else None,
                    )
                before = await conn.fetch(
                    "SELECT session_id,tenant_id,terminal_id,started_at,payload_schema_version "
                    "FROM screening.sessions ORDER BY session_id"
                )
                segment_before = await conn.fetch(
                    "SELECT session_id,sha256,size_bytes,frame_count,payload_schema_version "
                    "FROM screening.session_segments ORDER BY session_id"
                )
                await apply_migrations(conn)
                assert await conn.fetch(
                    "SELECT session_id,tenant_id,terminal_id,started_at,payload_schema_version "
                    "FROM screening.sessions ORDER BY session_id"
                ) == before
                assert await conn.fetch(
                    "SELECT session_id,sha256,size_bytes,frame_count,payload_schema_version "
                    "FROM screening.session_segments ORDER BY session_id"
                ) == segment_before
                fresh = PostgresPlatformRepository(pool)
                for session_id in session_ids:
                    record = await fresh.session(tenant.principal, session_id)
                    assert record.request.subject_uuid == subject
                    assert record.request.consent_record_id == consent
                    assert await fresh.get_segment(tenant.principal, session_id, 0) is not None
                again = await apply_migrations(conn)
                assert not again.applied
            finally:
                await pool.close()
        finally:
            await conn.close()
            await h.admin.execute(f'DROP DATABASE "{database}"')
    _run(cluster, body)


def test_registry_format_cannot_bypass_raw_session_business_shape(cluster):
    async def body(h):
        tenant = await h.tenant()
        session_id, _ = await h.session(tenant)
        with pytest.raises(asyncpg.CheckViolationError):
            await h.admin.execute(
                """UPDATE screening.sessions SET input_format='registry',
                    request_document='{}', request_sha256=$1, device_id=NULL,
                    subject_uuid=NULL, consent_record_id=NULL, test_protocol_id=NULL,
                    test_protocol_version=NULL, protocol_profile_version=NULL,
                    calibration_version=NULL WHERE session_id=$2""",
                "1" * 64, session_id,
            )
    _run(cluster, body)


def test_legacy_session_cannot_drop_its_required_started_at(cluster):
    async def body(h):
        tenant = await h.tenant()
        session_id, _ = await h.session(tenant)
        original = await h.admin.fetchval(
            "SELECT started_at FROM screening.sessions WHERE session_id=$1", session_id
        )
        assert original is not None
        with pytest.raises(asyncpg.CheckViolationError):
            await h.admin.execute(
                "UPDATE screening.sessions SET started_at=NULL WHERE session_id=$1", session_id
            )
        assert await h.admin.fetchval(
            "SELECT started_at FROM screening.sessions WHERE session_id=$1", session_id
        ) == original
    _run(cluster, body)
