"""RAY-728 R1 terminal data plane against live PostgreSQL role pools.

Covers the D3 projections (device.terminals, device.devices) written by
terminal activation, revocation, insole registration and retirement, and the
foreign keys of subject.consents and screening.sessions they satisfy.
"""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    SegmentMetadata,
    SessionManifest,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.repository import (
    AccessRepositoryConflict,
    TenantSeed,
    TerminalInstallationOwned,
    TerminalRecord,
    TerminalRefreshSessionRecord,
)
from techflex_cloud_foundation.server.access_control.terminal_service import TerminalAccessService
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.contract_export import build_vectors
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.insole_inventory.postgres import (
    PostgresInsoleInventoryRepository,
    insole_device_serial_hmac,
)
from techflex_cloud_foundation.server.insole_inventory.service import InsoleInventoryService
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository, tenant_transaction
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)
from tests.test_ffp_postgres_access_repository import _group, _live_dsns

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "src/techflex_cloud_foundation/schema/sql/0015_terminal_data_plane_projection.sql"
SECRET = b"tenant-token-secret-must-be-at-least-32-bytes"


def test_projection_migration_converges_without_widening_foreign_keys() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
    for forbidden in ("DROP ", "ALTER TABLE", "GRANT ", "CREATE "):
        assert forbidden not in sql
    assert sql.count("ON CONFLICT") == 2
    # Backfill never takes over hardware/legacy rows or another tenant's rows.
    assert "WHERE device.terminals.client_public_key = 'terminal-access-v1'" in sql
    assert "WHERE device.devices.model = 'insole-pair'" in sql
    assert sql.count("tenant_id = EXCLUDED.tenant_id") == 2
    assert "'terminal-access-v1'" in sql and "'insole-pair'" in sql
    assert "sha256(convert_to('insole-pair:', 'UTF8') || uuid_send(p.insole_id))" in sql


def test_projection_serial_matches_the_migration_backfill() -> None:
    insole_id = UUID("00112233-4455-6677-8899-aabbccddeeff")
    assert insole_device_serial_hmac(insole_id) == hashlib.sha256(
        b"insole-pair:" + insole_id.bytes
    ).digest()


async def _activate(access, tenant_id, group, installation: UUID) -> None:
    now = datetime.now(UTC)
    terminal = TerminalRecord(
        tenant_id=tenant_id, client_installation_id=installation,
        account_id=group.account_id, license_id=group.license_id,
        terminal_name="Gait lab", platform="android", status="ACTIVE",
        refresh_family_id=uuid4(), activated_at=now,
    )
    session = TerminalRefreshSessionRecord(
        refresh_session_id=uuid4(), tenant_id=tenant_id, account_id=group.account_id,
        client_installation_id=installation, refresh_family_id=terminal.refresh_family_id,
        refresh_token_hash=hashlib.sha256(os.urandom(32)).digest(),
        issued_at=now, idle_expires_at=now + timedelta(days=30),
        absolute_expires_at=now + timedelta(days=180),
    )
    await access.activate_terminal_atomically(terminal=terminal, session=session)


@pytest.mark.skipif(_live_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_terminal_uploads_through_projected_terminal_and_insole() -> None:
    import asyncpg

    tenant_dsn, activation_dsn, platform_dsn = _live_dsns() or ("", "", "")

    async def exercise() -> None:
        pools = [
            await asyncpg.create_pool(dsn, min_size=1, max_size=4)
            for dsn in (tenant_dsn, activation_dsn, platform_dsn)
        ]
        tenant_pool, activation_pool, platform_pool = pools
        try:
            access = PostgresAccessRepository(
                tenant_pool=tenant_pool, activation_pool=activation_pool,
                platform_pool=platform_pool,
            )
            tenant = TenantSeed(uuid4(), f"RAY-728 clinic {uuid4()}")
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
            await _activate(access, tenant.tenant_id, group, installation)

            private_key = Ed25519PrivateKey.generate()
            signer = LicenseDocumentSigner(
                private_key=private_key, key_id="license/2-key-1",
                public_keys={"license/2-key-1": private_key.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw)},
            )
            tokens = TerminalAccessTokenIssuer(secret=SECRET, key_id="tenant/1")
            data = PostgresPlatformRepository(tenant_pool, platform_pool=platform_pool)
            app = create_app(ServiceContainer(
                ingestion=IngestionService(
                    data, SegmentObjectStore(InMemoryObjectStore()),
                    supported_payload_schemas={"raw-segment/1", "insole-session-archive/1"},
                    supported_manifest_schemas={"session-manifest/1", "insole-session-manifest/1"},
                ),
                subjects=SubjectConsentService(data, IdentityProtector(
                    encryption_key=b"e" * 32, lookup_hmac_key=b"h" * 32,
                    key_version="identity/1",
                )),
                terminal_access=TerminalAccessService(
                    access, login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
                    terminal_tokens=tokens,
                    refresh_tokens=TerminalRefreshTokenFactory(
                        digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"),
                    license_signer=signer,
                ),
                terminal_tokens=tokens,
                insole_inventory=InsoleInventoryService(
                    PostgresInsoleInventoryRepository(activation_pool), access
                ),
            ))

            def bearer(**extra):
                token = tokens.issue(
                    tenant_id=tenant.tenant_id, account_id=group.account_id,
                    license_id=group.license_id, client_installation_id=installation,
                )
                return {"Authorization": f"Bearer {token}", **extra}

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="https://cloud.test"
            ) as client:
                registered = await client.post(
                    "/v1/inventory/insoles",
                    json=build_vectors()["insole_inventory"]["registration_request"],
                    headers=bearer(**{"Idempotency-Key": "insole"}),
                )
                assert registered.status_code == 201, registered.text
                insole_id = UUID(registered.json()["data"]["insole"]["insole_id"])

                async with tenant_transaction(activation_pool, tenant.tenant_id) as connection:
                    terminal_row = await connection.fetchrow(
                        "SELECT status,site_id,installation_id FROM device.terminals "
                        "WHERE terminal_id=$1", installation)
                    device_row = await connection.fetchrow(
                        "SELECT model,status,serial_hmac FROM device.devices "
                        "WHERE device_id=$1", insole_id)
                assert dict(terminal_row) == {
                    "status": "ACTIVE", "site_id": None, "installation_id": installation}
                assert (device_row["model"], device_row["status"]) == ("insole-pair", "ACTIVE")
                assert device_row["serial_hmac"] == insole_device_serial_hmac(insole_id)

                subject_id, consent_id = uuid4(), uuid4()
                created = await client.post("/v1/subjects", headers=bearer(**{"Idempotency-Key": "s"}), json={
                    "subject_uuid": str(subject_id),
                    "external_identifier": {"issuer": "ray-728", "id_type": "medical_record_number",
                                            "external_id": f"R728-{uuid4().hex[:8]}"},
                    "analysis_profile": {},
                })
                assert created.status_code == 201, created.text
                granted = await client.post("/v1/consents", headers=bearer(**{"Idempotency-Key": "c"}), json={
                    "consent_record_id": str(consent_id), "subject_uuid": str(subject_id),
                    "policy_version": "privacy-policy/1.0",
                    "purpose_codes": ["SCREENING_SERVICE"],
                    "data_categories": ["PRESSURE_RAW", "ANALYSIS_PROFILE"],
                    "granted_at": datetime.now(UTC).isoformat(),
                    "evidence_type": "OPERATOR_CONFIRMED",
                    "terminal_signature": "signed-client-evidence",
                })
                assert granted.status_code == 201, granted.text

                def session_body(device_id=insole_id):
                    return {
                        "session_id": str(uuid4()), "subject_uuid": str(subject_id),
                        "consent_record_id": str(consent_id), "site_id": None,
                        "terminal_id": str(installation),
                        "client_installation_id": str(installation),
                        "device_id": str(device_id),
                        "test_protocol": {"id": "walk-10m", "version": "1.0"},
                        "versions": {"app": "0.1.0", "protocol_profile": "insole/1",
                                     "payload_schema": "raw-segment/1",
                                     "calibration": "calibration/1"},
                        "started_at": datetime.now(UTC).isoformat(),
                    }

                async def create(body):
                    return await client.post(
                        "/v1/sessions", json=body, headers=bearer(**{"Idempotency-Key": str(uuid4())}))

                payload = b"insole segment"
                metadata = SegmentMetadata(
                    segment_index=0, start_frame_index=0, frame_count=10,
                    start_monotonic_ns=100, end_monotonic_ns=200, compression="zstd",
                    cipher="aes-256-gcm", size_bytes=len(payload),
                    sha256=hashlib.sha256(payload).hexdigest(),
                    payload_schema_version="raw-segment/1",
                )
                manifest = SessionManifest(
                    segment_count=1, total_frames=10, total_bytes=len(payload),
                    segments=(ManifestSegment(index=0, sha256=metadata.sha256,
                                              size_bytes=len(payload), frame_count=10),),
                    ended_at=datetime.now(UTC) + timedelta(seconds=1),
                    local_quality_outcome="VALID",
                )

                async def upload_and_complete(session_id):
                    put = await client.put(
                        f"/v1/sessions/{session_id}/segments/0", content=payload,
                        headers=bearer(**{
                            "X-Content-SHA256": metadata.sha256,
                            "X-Schema-Version": metadata.payload_schema_version,
                            "X-Segment-Metadata": encode_segment_metadata(metadata),
                        }),
                    )
                    assert put.status_code == 201, put.text
                    done = await client.post(
                        f"/v1/sessions/{session_id}/complete", json=manifest.model_dump(mode="json"),
                        headers=bearer(**{
                            "Idempotency-Key": f"complete-{session_id}",
                            "X-Content-SHA256": canonical_sha256(manifest),
                            "X-Schema-Version": manifest.schema_version,
                        }),
                    )
                    assert done.status_code == 200, done.text

                first = session_body()
                made = await create(first)
                assert made.status_code == 201, made.text
                await upload_and_complete(first["session_id"])
                status = await client.get(
                    f"/v1/sessions/{first['session_id']}/status", headers=bearer())
                assert status.status_code == 200, status.text

                # RAY-825: the published insole archive vectors reach INGESTED and
                # store NULL frame, clock and cipher columns (0016 shape checks).
                archive = build_vectors()["insole_session_archive"]
                archive_session = session_body()
                archive_session["versions"] = archive["session_versions"]
                # RAY-834: non-ASCII config_snapshot text. Before RAY-834 this
                # failed only when the test database is SQL_ASCII, like the
                # integration host; run it against one to cover that case.
                archive_session["config_snapshot"] = {"测试计划": "步行 60 秒", "备注": "其他"}
                assert (await create(archive_session)).status_code == 201
                archive_id = archive_session["session_id"]
                for part in archive["segments"]:
                    index = part["metadata"]["segment_index"]
                    put = await client.put(
                        f"/v1/sessions/{archive_id}/segments/{index}",
                        content=base64.b64decode(part["payload_base64"]),
                        headers=bearer(**part["request_headers"]),
                    )
                    assert put.status_code == 201, put.text
                listed = await client.get(f"/v1/sessions/{archive_id}/segments", headers=bearer())
                assert [item["index"] for item in listed.json()["data"]["received"]] == [0, 1]
                done = await client.post(
                    f"/v1/sessions/{archive_id}/complete", json=archive["manifest"]["body"],
                    headers=bearer(**archive["manifest"]["request_headers"],
                                   **{"Idempotency-Key": f"complete-{archive_id}"}),
                )
                assert done.status_code == 200, done.text
                assert done.json()["data"]["ingest_status"] == "INGESTED"
                async with tenant_transaction(tenant_pool, tenant.tenant_id) as connection:
                    rows = await connection.fetch(
                        "SELECT frame_count, start_monotonic_ns, cipher, compression "
                        "FROM screening.session_segments WHERE session_id=$1", UUID(archive_id))
                    total_frames = await connection.fetchval(
                        "SELECT total_frames FROM screening.session_manifests "
                        "WHERE session_id=$1", UUID(archive_id))
                assert len(rows) == 2 and all(set(row.values()) == {None} for row in rows)
                assert total_frames is None

                # D8: a session created before revoke resumes after re-activation.
                pending = session_body()
                assert (await create(pending)).status_code == 201
                await access.revoke_terminal(
                    tenant_id=tenant.tenant_id, account_id=group.account_id,
                    client_installation_id=installation, revoked_at=datetime.now(UTC),
                )
                revoked = await create(session_body())
                assert revoked.status_code == 401
                assert revoked.json()["error"]["code"] == "E-TRM-401-REVOKED"
                async with tenant_transaction(activation_pool, tenant.tenant_id) as connection:
                    assert await connection.fetchval(
                        "SELECT status FROM device.terminals WHERE terminal_id=$1",
                        installation) == "REVOKED"
                await _activate(access, tenant.tenant_id, group, installation)
                await upload_and_complete(pending["session_id"])

                # D5: a retired pair's projection no longer admits new sessions.
                retired = await client.post(
                    f"/v1/inventory/insoles/{insole_id}/retire", headers=bearer())
                assert retired.status_code == 200, retired.text
                assert (await create(session_body())).status_code == 403
                assert (await create(session_body(device_id=uuid4()))).status_code == 403
        finally:
            for pool in pools:
                await pool.close()

    asyncio.run(exercise())


@pytest.mark.skipif(_live_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_terminal_projection_never_takes_over_a_hardware_installation() -> None:
    import asyncpg

    tenant_dsn, activation_dsn, platform_dsn = _live_dsns() or ("", "", "")

    async def exercise() -> None:
        pools = [
            await asyncpg.create_pool(dsn, min_size=1, max_size=2)
            for dsn in (tenant_dsn, activation_dsn, platform_dsn)
        ]
        tenant_pool, activation_pool, platform_pool = pools
        try:
            access = PostgresAccessRepository(
                tenant_pool=tenant_pool, activation_pool=activation_pool,
                platform_pool=platform_pool,
            )
            nonce = os.urandom(32)
            seeded = []
            for index in (72, 73):
                tenant = TenantSeed(uuid4(), f"RAY-728 collision {uuid4()}")
                group = _group(index, run_nonce=nonce)
                await access.provision_tenant(tenant, group, created_at=group.license_valid_from)
                hardware_installation = uuid4()
                await access.activate_account_atomically(
                    login_name_hmac=group.login_name_hmac,
                    activation_code_hash=group.activation_code_hash,
                    hardware_identity=group.hardware_identity,
                    password_hash="$ffp-scrypt$good", installation_id=hardware_installation,
                    activated_at=group.license_valid_from + timedelta(minutes=1),
                    license_key_id="license/2-test",
                    license_document_json='{"schema_version":"license/2"}',
                    license_signature="s" * 86,
                )
                await access.set_terminal_seats(
                    license_id=group.license_id, seats=2, changed_at=datetime.now(UTC)
                )
                seeded.append((tenant, group, hardware_installation))
            (tenant, group, own_hardware), (_, _, foreign_hardware) = seeded
            # Same tenant (hardware projection row) and another tenant (RLS-hidden row).
            for taken in (own_hardware, foreign_hardware):
                with pytest.raises(TerminalInstallationOwned):
                    await _activate(access, tenant.tenant_id, group, taken)
                assert await access.terminal(taken) is None
            async with tenant_transaction(activation_pool, tenant.tenant_id) as connection:
                row = await connection.fetchrow(
                    "SELECT status,client_public_key FROM device.terminals WHERE terminal_id=$1",
                    own_hardware)
            assert (row["status"], row["client_public_key"]) == ("ACTIVE", "tenant-access-v1")

            # Reverse order: a hardware login never takes over a terminal's projection.
            terminal_id = uuid4()
            await _activate(access, tenant.tenant_id, group, terminal_id)
            with pytest.raises(AccessRepositoryConflict):
                await access.register_or_touch_installation(
                    tenant_id=tenant.tenant_id, account_id=group.account_id,
                    installation_id=terminal_id, seen_at=datetime.now(UTC),
                )
            await access.revoke_terminal(
                tenant_id=tenant.tenant_id, account_id=group.account_id,
                client_installation_id=terminal_id, revoked_at=datetime.now(UTC),
            )
            async with tenant_transaction(activation_pool, tenant.tenant_id) as connection:
                row = await connection.fetchrow(
                    "SELECT status,client_public_key FROM device.terminals WHERE terminal_id=$1",
                    terminal_id)
                installations = await connection.fetchval(
                    "SELECT count(*) FROM device.client_installations "
                    "WHERE client_installation_id=$1", terminal_id)
            assert (row["status"], row["client_public_key"]) == ("REVOKED", "terminal-access-v1")
            assert installations == 0
        finally:
            for pool in pools:
                await pool.close()

    asyncio.run(exercise())
