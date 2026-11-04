"""Run one real installed-wheel phase against a disposable PostgreSQL database."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
import sys
from uuid import UUID

import asyncpg

from techflex_cloud_foundation.contracts.registered import (
    RegisteredManifest,
    RegisteredSegmentMetadata,
    RegisteredSessionRequest,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.schema import DEFAULT_PLAN, RoleMissing, apply_migrations
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests.test_ffp_postgres_platform_live import Harness, Tenant
from tests.test_registry_ingestion_http import canonical, documents
from tests.test_schema_migrations import ROLE_STEP


async def main():
    settings = json.loads(os.environ["WHEEL_UPGRADE_DB"])
    phase = sys.argv[1]
    state_file = Path(sys.argv[2])
    admin = await asyncpg.connect(**settings)
    pool = None
    try:
        try:
            await apply_migrations(admin)
        except RoleMissing:
            await admin.execute(ROLE_STEP)
            await apply_migrations(admin)
        await admin.execute(ROLE_STEP)
        pool = await asyncpg.create_pool(**settings, min_size=1, max_size=2,
                                        server_settings={"role": "ffp_tenant_app"})
        repository = PostgresPlatformRepository(pool)
        service = IngestionService(repository, SegmentObjectStore(InMemoryObjectStore()),
            supported_payload_schemas={"gait-session-archive/1"},
            supported_manifest_schemas={"gait-session-manifest/1"})
        if phase == "old":
            assert not any(s.step_id.startswith("0021") for s in DEFAULT_PLAN)
            tenant = await Harness(admin, pool).tenant()
            session, metadata, manifest, _ = documents(tenant.terminal_id)
            result = await service.create_session(
                tenant.principal, RegisteredSessionRequest.model_validate(session), "wheel-create")
            assert not result.idempotent_replay
            state_file.write_text(json.dumps({"tenant": str(tenant.tenant_id),
                "terminal": str(tenant.terminal_id), "device": str(tenant.device_id),
                "session": session, "metadata": metadata, "manifest": manifest}))
        else:
            assert any(s.step_id.startswith("0021") for s in DEFAULT_PLAN)
            state = json.loads(state_file.read_text())
            tenant = Tenant(UUID(state["tenant"]), UUID(state["terminal"]), UUID(state["device"]))
            sid = UUID(state["session"]["session_id"])
            replay = await service.create_session(tenant.principal,
                RegisteredSessionRequest.model_validate(state["session"]), "wheel-create")
            assert replay.idempotent_replay
            assert await admin.fetchval(
                "SELECT input_format FROM screening.sessions WHERE session_id=$1", sid
            ) == "registry-jsonb"
            if phase == "new":
                async def body():
                    yield b"gait-synthetic-archive"
                await service.put_segment(tenant.principal, sid, 0,
                    RegisteredSegmentMetadata.model_validate(state["metadata"]), body())
            completed = await service.complete_session(tenant.principal, sid,
                RegisteredManifest.model_validate(state["manifest"]),
                hashlib.sha256(canonical(state["manifest"])).hexdigest(), "wheel-complete")
            assert completed.ingest_status == "INGESTED"
            if phase == "restart":
                assert completed.idempotent_replay
        print(json.dumps({"phase": phase, "status": "passed"}))
    finally:
        if pool is not None:
            await pool.close()
        await admin.close()


if __name__ == "__main__":
    asyncio.run(main())
