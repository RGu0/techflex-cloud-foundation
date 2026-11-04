"""RAY-953 R2: neutral published vectors must reach the actual HTTP data plane."""
from __future__ import annotations

import asyncio
import base64
from contextlib import AsyncExitStack
import copy
from dataclasses import replace
from datetime import timedelta
import hashlib
import json
from pathlib import Path
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.payload_contracts import (
    GAIT_ARCHIVE_SCHEMA,
    FieldKind,
    FieldSpec,
    default_payload_schema_registry,
)
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests.test_ffp_postgres_platform_live import Harness, _run
from tests.test_ffp_postgres_platform_live import cluster as cluster  # shared ephemeral PG fixture

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ("insole-session-archive/1", "gait-session-archive/1")
FOURTH = "test-fourth-archive/1"


def vector(filename, schema):
    entries = json.loads((ROOT / "docs/contracts" / filename).read_text())["schemas"]
    return copy.deepcopy(next(entry for entry in entries if entry["schema"] == schema))


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


async def exercise(
    repository, tenant, terminal, schema, *, registry=None, reload_repository=None,
    quality=None, omit_quality=False, conflict_metadata=False, completion_status=200,
    naive_times=False,
):
    source = "gait-session-archive/1" if schema == FOURTH else schema
    session = vector("session-create-vectors.json", source)["session"]["document"]
    session.update(session_id=str(uuid4()), client_installation_id=str(terminal), site_id=None)
    payload = vector("payload-schema-vectors.json", source)
    if naive_times:
        session["started_at"] = "2026-11-04T10:20:30"
        payload["manifest"]["document"]["ended_at"] = "2026-11-04T10:21:30"
    if schema == FOURTH:
        registry = default_payload_schema_registry()
        registry.register(replace(
            GAIT_ARCHIVE_SCHEMA, schema_id=FOURTH,
            manifest_schema="test-fourth-manifest/1", allowed_products=("test-fourth",),
            manifest_schema_implied=True,
            session_extension=(FieldSpec("device_id", FieldKind.TEXT),),
            segment_extension=(
                FieldSpec("frame_count", FieldKind.TEXT), FieldSpec("compression", FieldKind.TEXT),
            ),
            manifest_extension=tuple(
                spec for spec in GAIT_ARCHIVE_SCHEMA.manifest_extension
                if spec.name not in {"ended_at", "local_quality_outcome"}
            ) + (
                FieldSpec("ended_at", FieldKind.TEXT),
                FieldSpec("local_quality_outcome", FieldKind.TEXT),
                FieldSpec("total_frames", FieldKind.TEXT),
            ),
        ))
        session["versions"]["payload_schema"] = FOURTH
        session["device_id"] = "product-extension-not-a-legacy-device"
        for segment in payload["segments"]:
            segment["metadata"]["payload_schema_version"] = FOURTH
            segment["metadata"]["frame_count"] = "not-a-frame-count"
            segment["metadata"]["compression"] = "product-owned-text"
        del payload["manifest"]["document"]["schema_version"]
        payload["manifest"]["document"]["ended_at"] = "product-text-not-a-timestamp"
        payload["manifest"]["document"]["local_quality_outcome"] = "not-a-clinical-status"
        payload["manifest"]["document"]["total_frames"] = "not-a-frame-total"
    options = {
        "supported_payload_schemas": set(SCHEMAS),
        "supported_manifest_schemas": {"insole-session-manifest/1", "gait-session-manifest/1"},
    }
    if registry is not None:
        options = {"payload_registry": registry}
    objects = SegmentObjectStore(InMemoryObjectStore())
    service = IngestionService(repository, objects, **options)
    issuer = TerminalTokenIssuer(
        secret=b"registry-http-test-secret-at-least-32", key_id="test/1",
        token_ttl=timedelta(minutes=10),
    )
    container = ServiceContainer(ingestion=service, token_issuer=issuer)
    app = create_app(container)
    headers = {"Authorization": f"Bearer {issuer.issue(tenant, terminal)}",
               "X-Terminal-ID": str(terminal),
               "Idempotency-Key": f"create:{session['session_id']}"}
    async with AsyncExitStack() as stack:
        client = await stack.enter_async_context(AsyncClient(
            transport=ASGITransport(app=app), base_url="https://cloud.test"
        ))
        created = await client.post("/v1/sessions", headers=headers, json=session)
        assert created.status_code == 201, created.text
        replay = await client.post("/v1/sessions", headers=headers, json=session)
        assert replay.status_code == 200, replay.text
        changed = {**session, "config_snapshot": {"changed": True}}
        conflict = await client.post("/v1/sessions", headers=headers, json=changed)
        assert conflict.status_code == 409, conflict.text
        path = f"/v1/sessions/{session['session_id']}"
        for segment in payload["segments"]:
            metadata = segment["metadata"]
            encoded = base64.urlsafe_b64encode(canonical(metadata)).rstrip(b"=").decode()
            response = await client.put(
                f"{path}/segments/{metadata['segment_index']}",
                headers={**headers, "X-Segment-Metadata": encoded,
                         "X-Content-SHA256": metadata["sha256"],
                         "X-Schema-Version": schema,
                         "Content-Type": "application/octet-stream"},
                content=base64.b64decode(segment["payload_base64"]),
            )
            assert response.status_code == 201, response.text
        if conflict_metadata:
            segment = payload["segments"][0]
            changed_metadata = {**segment["metadata"], "offset": 1}
            encoded = base64.urlsafe_b64encode(canonical(changed_metadata)).rstrip(b"=").decode()
            response = await client.put(
                path + "/segments/0",
                headers={**headers, "X-Segment-Metadata": encoded,
                         "X-Content-SHA256": changed_metadata["sha256"],
                         "X-Schema-Version": schema},
                content=base64.b64decode(segment["payload_base64"]),
            )
            assert response.status_code == 409, response.text
        manifest = payload["manifest"]["document"]
        if quality is not None:
            manifest["local_quality_outcome"] = quality
        if omit_quality:
            manifest.pop("local_quality_outcome", None)
        if reload_repository is not None:
            fresh_app = create_app(ServiceContainer(
                ingestion=IngestionService(reload_repository(), objects, **options),
                token_issuer=issuer,
            ))
            client = await stack.enter_async_context(AsyncClient(
                transport=ASGITransport(app=fresh_app), base_url="https://cloud.test"
            ))
            replay = await client.post("/v1/sessions", headers=headers, json=session)
            assert replay.status_code == 200, replay.text
        digest = hashlib.sha256(canonical(manifest)).hexdigest()
        completed = await client.post(
            path + "/complete", json=manifest,
            headers={**headers, "Idempotency-Key": "complete:" + session["session_id"],
                     "X-Content-SHA256": digest,
                     "X-Schema-Version": (
                         "test-fourth-manifest/1" if schema == FOURTH
                         else manifest["schema_version"]
                     )},
        )
        assert completed.status_code == completion_status, completed.text
        if completion_status != 200:
            return session["session_id"]
        assert completed.json()["data"]["ingest_status"] == "INGESTED"
        assert completed.json()["data"]["manifest_sha256"] == digest
        status = await client.get(path + "/status", headers=headers)
        assert status.json()["data"]["ingest_status"] == "INGESTED"
    return session["session_id"]


@pytest.mark.parametrize("schema", (*SCHEMAS, FOURTH))
def test_core_vectors_complete_through_http_in_memory(schema):
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)
    asyncio.run(exercise(repository, tenant, terminal, schema))


@pytest.mark.parametrize("schema", (*SCHEMAS, FOURTH))
def test_core_vectors_complete_through_http_postgres(cluster, schema):
    async def body(h: Harness):
        tenant = await h.tenant()
        session_id = await exercise(
            h.repository, tenant.tenant_id, tenant.terminal_id, schema,
            reload_repository=lambda: PostgresPlatformRepository(h.pool),
        )
        rows = await h.admin.fetchval(
            "SELECT count(*) FROM ops.outbox_events WHERE aggregate_id::text = $1", session_id
        )
        assert rows == 1
        if schema == FOURTH:
            row = await h.admin.fetchrow(
                "SELECT device_id, request_document FROM screening.sessions "
                "WHERE session_id::text=$1", session_id,
            )
            assert row["device_id"] is None
            assert json.loads(row["request_document"])["device_id"] == (
                "product-extension-not-a-legacy-device"
            )
    _run(cluster, body)


@pytest.mark.parametrize("options", [
    {"quality": "INVALID", "completion_status": 422},
    {"omit_quality": True, "completion_status": 422},
    {"conflict_metadata": True, "completion_status": 409},
])
def test_core_insole_refusal_keeps_no_completion_or_event(cluster, options):
    async def body(h: Harness):
        tenant = await h.tenant()
        session_id = await exercise(
            h.repository, tenant.tenant_id, tenant.terminal_id, "insole-session-archive/1",
            **options,
        )
        assert await h.admin.fetchval(
            "SELECT count(*) FROM ops.outbox_events WHERE aggregate_id::text=$1", session_id
        ) == 0
        assert await h.admin.fetchval(
            "SELECT count(*) FROM screening.session_manifests WHERE session_id::text=$1", session_id
        ) == 0
        if options.get("conflict_metadata"):
            assert await h.admin.fetchval(
                "SELECT ingest_status FROM screening.sessions WHERE session_id::text=$1", session_id
            ) == "CONFLICT"
    _run(cluster, body)


def test_naive_core_timestamps_complete_in_memory_without_inventing_timezone():
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)
    asyncio.run(exercise(repository, tenant, terminal, "gait-session-archive/1", naive_times=True))


def test_naive_core_timestamps_preserve_original_but_have_no_sql_instant(cluster):
    async def body(h):
        tenant = await h.tenant()
        session_id = await exercise(
            h.repository, tenant.tenant_id, tenant.terminal_id, "gait-session-archive/1",
            naive_times=True, reload_repository=lambda: PostgresPlatformRepository(h.pool),
        )
        row = await h.admin.fetchrow(
            "SELECT started_at,ended_at,request_document FROM screening.sessions "
            "WHERE session_id::text=$1", session_id,
        )
        assert row["started_at"] is None and row["ended_at"] is None
        assert json.loads(row["request_document"])["started_at"] == "2026-11-04T10:20:30"
        manifest = await h.admin.fetchval(
            "SELECT manifest_json FROM screening.session_manifests WHERE session_id::text=$1",
            session_id,
        )
        assert json.loads(manifest)["ended_at"] == "2026-11-04T10:21:30"
    _run(cluster, body)
