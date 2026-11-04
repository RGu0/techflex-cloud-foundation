"""Upgrade real 0020 registry rows without inventing lost original wire JSON."""
from __future__ import annotations

import asyncio
import copy
from datetime import UTC, datetime
import json
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    ManifestConflict,
    SegmentDigestConflict,
)
from techflex_cloud_foundation.schema import DEFAULT_PLAN, RoleMissing, apply_migrations
from techflex_cloud_foundation.server.ingestion_contracts import parse_registered
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
from techflex_cloud_foundation.server.segment_store import (
    SegmentObjectStore,
    manifest_object_key,
    segment_object_key,
)
from tests.pg_cluster import find_postgres_bin, running_cluster
from tests.test_ffp_postgres_platform_live import Harness, asyncpg
from tests.test_registry_ingestion_http import documents
from tests.test_schema_migrations import ROLE_STEP

BIN = find_postgres_bin()
pytestmark = pytest.mark.skipif(BIN is None, reason="no PostgreSQL server installation found")


@pytest.fixture(scope="module", params=("UTF8", "SQL_ASCII"))
def predecessor_cluster(request):
    assert BIN is not None
    with running_cluster(BIN) as cluster:
        yield cluster, request.param


def _json(document):
    return json.dumps(document, ensure_ascii=False, separators=(",", ":"))


def _run(predecessor_cluster, body):
    cluster, encoding = predecessor_cluster

    async def execute():
        settings = dict(host=cluster.socket_dir, port=cluster.port, user="postgres")
        bootstrap = await asyncpg.connect(**settings, database="postgres")
        database = "upgrade_" + uuid4().hex
        await bootstrap.execute(
            f'CREATE DATABASE "{database}" TEMPLATE template0 ENCODING \'{encoding}\' '
            "LC_COLLATE 'C' LC_CTYPE 'C'"
        )
        admin = await asyncpg.connect(**settings, database=database)
        pool = None
        try:
            old_plan = tuple(s for s in DEFAULT_PLAN if not s.step_id.startswith("0021"))
            assert any(s.step_id == "0020_registered_ingestion" for s in old_plan)
            assert len(old_plan) < len(DEFAULT_PLAN), "0021 must be in the shipped plan"
            try:
                await apply_migrations(admin, plan=old_plan)
            except RoleMissing:
                await admin.execute(ROLE_STEP)
                await apply_migrations(admin, plan=old_plan)
            await admin.execute(ROLE_STEP)
            pool = await asyncpg.create_pool(
                **settings, database=database, min_size=1, max_size=4,
                server_settings={"role": "ffp_tenant_app"},
            )
            harness = Harness(admin, pool)
            await body(harness)
        finally:
            if pool is not None:
                await pool.close()
            await admin.close()
            await bootstrap.execute(f'DROP DATABASE "{database}"')
            await bootstrap.close()
    asyncio.run(execute())


async def _idempotency(h, tenant, sid, scope, key, digest, response):
    await h.admin.execute(
        """INSERT INTO ops.idempotency_keys (
            idempotency_record_id,tenant_id,scope,idempotency_key,request_sha256,
            response_status,response_json,resource_type,resource_id,expires_at
        ) VALUES ($1,$2,$3,$4,$5,$8,$6::jsonb,'screening_session',$7,now()+interval '1 day')""",
        uuid4(), tenant.tenant_id, scope, key, digest, _json(response), sid,
        201 if scope == "session.create" else 200,
    )


async def _seed_0020(h, *, part=False, completed=False, exponent=False):
    """Persist only predecessor columns; no 0021 parser/repository writes old fixtures."""
    tenant = await h.tenant()
    session, metadata, manifest, payload = documents(tenant.terminal_id)
    session["session_id"] = session["session_id"].replace("-", "").upper()
    session["client_installation_id"] = session["client_installation_id"].upper()
    session["started_at"] = "2026-11-04T08:00:00.120000+08:00"
    session["config_snapshot"] = {"label": "步态升级", **({"scale": 1e20} if exponent else {})}
    sid = UUID(session["session_id"])
    await h.admin.execute(
        """INSERT INTO screening.sessions (
            session_id,tenant_id,site_id,terminal_id,started_at,app_version,
            payload_schema_version,config_snapshot,registered_document
        ) VALUES ($1,$2,NULL,$3,$4,'gait/1','gait-session-archive/1',$5::jsonb,$6::jsonb)""",
        sid, tenant.tenant_id, tenant.terminal_id,
        datetime.fromisoformat(session["started_at"]),
        _json(session["config_snapshot"]), _json(session),
    )
    create_key = "old-create:" + str(sid)
    await _idempotency(h, tenant, sid, "session.create", create_key, canonical_sha256(session), {
        "session_id": str(sid), "ingest_status": "RECEIVING", "idempotent_replay": False,
    })
    if part or completed:
        await h.admin.execute(
            """INSERT INTO screening.session_segments (
                session_segment_id,tenant_id,session_id,segment_index,object_key,
                sha256,size_bytes,payload_schema_version,status,metadata_json
            ) VALUES ($1,$2,$3,0,$4,$5,$6,'gait-session-archive/1','VERIFIED',$7::jsonb)""",
            uuid4(), tenant.tenant_id, sid,
            segment_object_key(tenant.tenant_id, sid, 0, metadata["sha256"]),
            metadata["sha256"], len(payload), _json(metadata),
        )
    complete_key = "old-complete:" + str(sid)
    completed_at = datetime(2026, 11, 4, 1, tzinfo=UTC)
    digest = canonical_sha256(manifest)
    object_key = manifest_object_key(tenant.tenant_id, sid, digest)
    if completed:
        await h.admin.execute(
            """INSERT INTO screening.session_manifests (
                manifest_id,tenant_id,session_id,schema_version,manifest_sha256,object_key,
                segment_count,total_bytes,manifest_json,registered_manifest,verification_status,
                verified_at,eligibility_reason,eligibility_policy_version,completed_at,idempotency_key
            ) VALUES ($1,$2,$3,'gait-session-manifest/1',$4,$5,1,$6,$7::jsonb,true,'VERIFIED',
                $8,'registry validated','seed-completion-eligibility/1',$8,$9)""",
            uuid4(), tenant.tenant_id, sid, digest, object_key, len(payload),
            _json(manifest), completed_at, complete_key,
        )
        await h.admin.execute(
            "UPDATE screening.sessions SET ingest_status='INGESTED',manifest_sha256=$1,"
            "aggregate_version=2 WHERE session_id=$2", digest, sid,
        )
        await h.admin.execute(
            """INSERT INTO ops.outbox_events (
                event_id,event_type,tenant_id,aggregate_type,aggregate_id,aggregate_version,payload
            ) VALUES ($1,'session.ingested.v1',$2,'screening_session',$3,2,$4::jsonb)""",
            uuid4(), tenant.tenant_id, sid,
            _json({"session_id": str(sid), "manifest_sha256": digest}),
        )
        await _idempotency(h, tenant, sid, "session.complete", complete_key, digest, {
            "session_id": str(sid), "ingest_status": "INGESTED", "manifest_sha256": digest,
            "idempotent_replay": False, "manifest_object_key": object_key,
            "eligibility_reason": "registry validated",
            "eligibility_policy_version": "seed-completion-eligibility/1",
            "completed_at": completed_at.isoformat(),
        })
    return SimpleNamespace(
        tenant=tenant, sid=sid, session=session, metadata=metadata, manifest=manifest,
        payload=payload, create_key=create_key, complete_key=complete_key,
        digest=digest, completed_at=completed_at,
    )


async def _upgrade(h, old):
    persisted = await h.admin.fetchval(
        "SELECT registered_document::text FROM screening.sessions WHERE session_id=$1", old.sid
    )
    await apply_migrations(h.admin)
    row = await h.admin.fetchrow(
        "SELECT input_format,registered_document::text,request_document,request_sha256 "
        "FROM screening.sessions WHERE session_id=$1", old.sid,
    )
    assert row["input_format"] == "registry-jsonb"
    assert row["registered_document"] == persisted
    assert row["request_document"] is None and row["request_sha256"] is None
    assert not (await apply_migrations(h.admin)).applied
    repository = PostgresPlatformRepository(h.pool)
    service = IngestionService(repository, SegmentObjectStore(InMemoryObjectStore()))
    return repository, service, json.loads(persisted)


async def _body(payload):
    yield payload


async def _complete(service, old, key):
    manifest = parse_registered(
        old.manifest, "manifest", "gait-session-archive/1", service.payload_registry
    )
    return await service.complete_session(old.tenant.principal, old.sid, manifest, old.digest, key)


@pytest.mark.parametrize("existing_part", [False, True])
def test_0020_receiving_session_resumes_upload_and_completion(predecessor_cluster, existing_part):
    async def body(h):
        old = await _seed_0020(h, part=existing_part)
        repository, service, normalized = await _upgrade(h, old)
        record = await repository.session(old.tenant.principal, old.sid)
        assert record.request.model_dump(mode="json") == normalized == old.session
        assert record.request_sha256 == canonical_sha256(normalized)
        for key in (old.create_key, "different-create-key"):
            result = await service.create_session(
                old.tenant.principal, service.parse_session(old.session), key
            )
            assert result.idempotent_replay
        metadata = parse_registered(
            old.metadata, "segment", "gait-session-archive/1", service.payload_registry
        )
        result = await service.put_segment(
            old.tenant.principal, old.sid, 0, metadata, _body(old.payload)
        )
        assert result.idempotent_replay is existing_part
        done = await _complete(service, old, "new-complete")
        assert done.ingest_status == "INGESTED"
        assert done.manifest_sha256 == old.digest
        assert await h.admin.fetchval(
            "SELECT count(*) FROM ops.outbox_events WHERE aggregate_id=$1", old.sid
        ) == 1
    _run(predecessor_cluster, body)


def test_0020_completed_receipt_replays_without_another_event(predecessor_cluster):
    async def body(h):
        old = await _seed_0020(h, completed=True)
        before = await h.admin.fetch(
            "SELECT * FROM ops.outbox_events WHERE aggregate_id=$1", old.sid
        )
        _, service, _ = await _upgrade(h, old)
        for key in (old.complete_key, "different-complete-key"):
            result = await _complete(service, old, key)
            assert result.idempotent_replay
            assert result.completed_at == old.completed_at
            assert result.eligibility_reason == "registry validated"
            assert result.manifest_sha256 == old.digest
        assert await h.admin.fetch(
            "SELECT * FROM ops.outbox_events WHERE aggregate_id=$1", old.sid
        ) == before
        marker = await h.admin.fetchrow(
            "SELECT registered_manifest,segment_profile FROM screening.session_manifests "
            "WHERE session_id=$1", old.sid,
        )
        assert marker["registered_manifest"] is True
        assert marker["segment_profile"] == "byte-segment"
    _run(predecessor_cluster, body)


def test_0020_jsonb_exponent_loss_is_not_relabelled_original_json(predecessor_cluster):
    async def body(h):
        old = await _seed_0020(h, exponent=True)
        _, service, normalized = await _upgrade(h, old)
        assert isinstance(normalized["config_snapshot"]["scale"], int)
        assert canonical_sha256(normalized) != canonical_sha256(old.session)
        for key in (old.create_key, "other-original-key"):
            with pytest.raises(IdempotencyConflict):
                await service.create_session(
                    old.tenant.principal, service.parse_session(old.session), key
                )
        # The old key still identifies the original request digest, not normalized JSONB.
        with pytest.raises(IdempotencyConflict):
            await service.create_session(
                old.tenant.principal, service.parse_session(normalized), old.create_key
            )
        normalized_replay = await service.create_session(
            old.tenant.principal, service.parse_session(normalized), "normalized-new-key"
        )
        assert normalized_replay.idempotent_replay
        assert await h.admin.fetchval(
            "SELECT request_document FROM screening.sessions WHERE session_id=$1", old.sid
        ) is None
    _run(predecessor_cluster, body)


def test_0020_metadata_offset_conflict_survives_upgrade(predecessor_cluster):
    async def body(h):
        old = await _seed_0020(h, part=True)
        original_metadata = await h.admin.fetchval(
            "SELECT metadata_json::text FROM screening.session_segments WHERE session_id=$1",
            old.sid,
        )
        repository, service, _ = await _upgrade(h, old)
        part = await repository.get_segment(old.tenant.principal, old.sid, 0)
        assert part.metadata.model_dump(mode="json") == old.metadata
        row = await h.admin.fetchrow(
            "SELECT metadata_json::text,metadata_document,segment_profile "
            "FROM screening.session_segments WHERE session_id=$1", old.sid,
        )
        assert row["metadata_json"] == original_metadata
        assert row["metadata_document"] is None
        assert row["segment_profile"] == "byte-segment"
        changed = parse_registered(
            {**old.metadata, "offset": 1}, "segment", "gait-session-archive/1",
            service.payload_registry,
        )
        with pytest.raises(SegmentDigestConflict):
            await service.put_segment(old.tenant.principal, old.sid, 0, changed, _body(old.payload))
        with pytest.raises(ManifestConflict):
            await _complete(service, old, "conflicted-complete")
        assert await h.admin.fetchval(
            "SELECT count(*) FROM ops.outbox_events WHERE aggregate_id=$1", old.sid
        ) == 0
    _run(predecessor_cluster, body)


def test_0020_upgrade_keeps_concurrent_create_idempotent(predecessor_cluster):
    async def body(h):
        old = await _seed_0020(h)
        _, service, _ = await _upgrade(h, old)
        old_replays = await asyncio.gather(*(
            service.create_session(
                old.tenant.principal, service.parse_session(old.session), old.create_key
            ) for _ in range(3)
        ))
        assert all(result.idempotent_replay for result in old_replays)
        fresh_document = copy.deepcopy(old.session)
        fresh_document["session_id"] = uuid4().hex.upper()
        new_results = await asyncio.gather(*(
            service.create_session(
                old.tenant.principal, service.parse_session(fresh_document), "concurrent-new"
            ) for _ in range(3)
        ))
        assert sorted(result.idempotent_replay for result in new_results) == [False, True, True]
        stored = await h.admin.fetchrow(
            "SELECT input_format,request_document,request_sha256,registered_document "
            "FROM screening.sessions WHERE session_id=$1", UUID(fresh_document["session_id"]),
        )
        assert stored["input_format"] == "registry"
        assert json.loads(stored["request_document"]) == fresh_document
        assert json.loads(stored["registered_document"]) == fresh_document
        assert stored["request_sha256"] == canonical_sha256(fresh_document)
        assert await h.admin.fetchval("SELECT count(*) FROM screening.sessions") == 2
    _run(predecessor_cluster, body)
