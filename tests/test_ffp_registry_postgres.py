"""Actual HTTP -> least-privilege role pools -> migrated PostgreSQL round trip."""
from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
import hashlib
import json
import os
from pathlib import Path
from uuid import UUID, uuid4

import asyncpg
from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.schema import apply_migrations
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.seed import SeedSettings, build_seed_app
from tests import test_ffp_terminal_data_plane_postgres_live as live
from tests.pg_cluster import find_postgres_bin, running_cluster
from tests.test_ffp_postgres_access_repository import _group
from tests.test_ffp_seed_composition import _values
from tests.test_registry_ingestion_http import canonical, documents
from tests.test_schema_migrations import _installer_run


def terminal_context(tenant, installation):
    return IngestionPrincipal(tenant, installation, datetime.now(UTC) + timedelta(hours=1),
                              True, True, terminal_access=True)


@pytest.mark.parametrize("encoding", ["UTF8", "SQL_ASCII"])
def test_registered_http_postgres_round_trip(encoding):
    binary = find_postgres_bin()
    if binary is None:
        pytest.skip("PostgreSQL server is unavailable")
    with running_cluster(binary) as cluster:
        asyncio.run(exercise(cluster, encoding))


async def exercise(cluster, encoding):
    settings = dict(host=cluster.socket_dir, port=cluster.port,
                    user="postgres", database="postgres")
    admin = await asyncpg.connect(**settings)
    await admin.execute(f"CREATE DATABASE registry_test TEMPLATE template0 ENCODING '{encoding}' "
                        "LC_COLLATE 'C' LC_CTYPE 'C'")
    await admin.close()
    settings["database"] = "registry_test"
    admin = await asyncpg.connect(**settings)
    try:
        await _installer_run(admin)
        await apply_migrations(admin)
        await apply_migrations(admin)  # convergence is required
    finally:
        await admin.close()
    pools = [await asyncpg.create_pool(**settings, min_size=1, max_size=4,
             server_settings={"role": role})
             for role in ("ffp_tenant_app", "ffp_activation_app", "ffp_platform_app")]
    tenant_pool, activation_pool, platform_pool = pools
    try:
        access = live.PostgresAccessRepository(
            tenant_pool=tenant_pool, activation_pool=activation_pool,
            platform_pool=platform_pool,
        )
        tenant = live.TenantSeed(uuid4(), f"RAY-728 clinic {uuid4()}")
        group = _group(71, run_nonce=os.urandom(32))
        await access.provision_tenant(tenant, group, created_at=group.license_valid_from)
        # Account activation turns the provisioned License ACTIVE.
        await access.activate_account_atomically(
            login_name_hmac=group.login_name_hmac,
            activation_code_hash=group.activation_code_hash,
            hardware_identity=group.hardware_identity,
            password_hash="$ffp-scrypt$good", installation_id=uuid4(),
            activated_at=group.license_valid_from + timedelta(minutes=1),
            license_key_id="license/2-test",
            license_document_json='{"schema_version":"license/2"}',
            license_signature="s" * 86,
        )
        await access.set_terminal_seats(
            license_id=group.license_id, seats=2, changed_at=datetime.now(UTC)
        )
        installation = uuid4()
        await live._activate(access, tenant.tenant_id, group, installation)

        seed_settings = SeedSettings(**_values(Path(cluster.socket_dir) / "objects"))
        pool_map = dict(zip((seed_settings.tenant_dsn, seed_settings.activation_dsn,
                            seed_settings.platform_dsn), pools, strict=True))

        async def pool_factory(*, dsn, **kwargs):
            return pool_map[dsn]

        app = await build_seed_app(seed_settings, pool_factory=pool_factory,
                                  object_store_factory=lambda _: live.InMemoryObjectStore())
        tokens = live.TerminalAccessTokenIssuer(
            secret=seed_settings.tenant_token_secret.encode(), key_id=seed_settings.tenant_token_key_id)
        data = live.PostgresPlatformRepository(tenant_pool, platform_pool=platform_pool)

        def bearer(**extra):
            token = tokens.issue(
                tenant_id=tenant.tenant_id, account_id=group.account_id,
                license_id=group.license_id, client_installation_id=installation,
            )
            return {"Authorization": f"Bearer {token}", **extra}

        async with AsyncClient(
            transport=ASGITransport(app=app), base_url="https://cloud.test"
        ) as client:
            session, metadata, manifest, payload = documents(installation)
            session["session_id"] = session["session_id"].replace("-", "").upper()
            session["client_installation_id"] = session["client_installation_id"].upper()
            session["config_snapshot"] = {"label": "步态测试"}
            sid = UUID(session["session_id"])
            created = await asyncio.gather(*[
                client.post("/v1/sessions", json=session,
                    headers=bearer(**{"Idempotency-Key": "create-gait"})) for _ in range(3)])
            assert sorted(response.status_code for response in created) == [200, 200, 201], [r.text for r in created]
            stored = await data.session(terminal_context(tenant.tenant_id, installation), sid)
            assert stored.request.model_dump(mode="json") == session
            response = await client.post("/v1/sessions", json=session,
                headers=bearer(**{"Idempotency-Key": "create-gait"}))
            assert response.status_code == 200, response.text
            response = await client.put(f"/v1/sessions/{sid}/segments/0", content=payload,
                headers=bearer(**{
                    "X-Content-SHA256": metadata["sha256"],
                    "X-Schema-Version": metadata["payload_schema_version"],
                    "X-Segment-Metadata": base64.urlsafe_b64encode(canonical(metadata)).decode(),
                    "Content-Type": "application/octet-stream"}))
            assert response.status_code == 201, response.text
            part = await data.get_segment(terminal_context(tenant.tenant_id, installation), sid, 0)
            assert part.metadata.model_dump(mode="json") == metadata
            for _ in range(2):
                response = await client.post(f"/v1/sessions/{sid}/complete", json=manifest,
                    headers=bearer(**{"Idempotency-Key": "complete-gait",
                        "X-Content-SHA256": hashlib.sha256(canonical(manifest)).hexdigest(),
                        "X-Schema-Version": manifest["schema_version"]}))
                assert response.status_code == 200, response.text
                assert response.json()["data"]["ingest_status"] == "INGESTED"
            async with live.tenant_transaction(tenant_pool, tenant.tenant_id) as connection:
                row = await connection.fetchrow("SELECT * FROM screening.sessions WHERE session_id=$1", sid)
                assert json.loads(row["registered_document"]) == session
                assert row["device_id"] is None and row["subject_uuid"] is None
                assert row["validity_status"] == "UNKNOWN"
                assert await connection.fetchval("SELECT count(*) FROM screening.session_manifests WHERE session_id=$1", sid) == 1
            # Dropping the neutral marker cannot turn NULL measurement fields into a legacy row.
            async with live.tenant_transaction(tenant_pool, tenant.tenant_id) as connection:
                with pytest.raises(asyncpg.CheckViolationError):
                    async with connection.transaction():
                        await connection.execute("UPDATE screening.sessions SET registered_document=NULL WHERE session_id=$1", sid)
            # PostgreSQL must check persisted profile metadata, not only matching bytes.
            second, bad_meta, bad_manifest, part_bytes = documents(installation)
            bad_meta["offset"] = 2
            second_id = second["session_id"]
            response = await client.post("/v1/sessions", json=second,
                headers=bearer(**{"Idempotency-Key": "offset-create"}))
            assert response.status_code == 201, response.text
            response = await client.put(f"/v1/sessions/{second_id}/segments/0", content=part_bytes,
                headers=bearer(**{"Content-Type": "application/octet-stream",
                    "X-Content-SHA256": bad_meta["sha256"],
                    "X-Schema-Version": bad_meta["payload_schema_version"],
                    "X-Segment-Metadata": base64.urlsafe_b64encode(canonical(bad_meta)).decode()}))
            assert response.status_code == 201, response.text
            response = await client.post(f"/v1/sessions/{second_id}/complete", json=bad_manifest,
                headers=bearer(**{"Idempotency-Key": "offset-complete",
                    "X-Content-SHA256": hashlib.sha256(canonical(bad_manifest)).hexdigest(),
                    "X-Schema-Version": bad_manifest["schema_version"]}))
            assert response.status_code == 422, response.text
            assert response.json()["error"]["action"] == "UPLOAD_MISSING_SEGMENTS"
            # A different tenant sees no session under the same role pool.
            async with live.tenant_transaction(tenant_pool, uuid4()) as connection:
                assert await connection.fetchval("SELECT count(*) FROM screening.sessions WHERE session_id=$1", sid) == 0
    finally:
        for pool in pools:
            await pool.close()
