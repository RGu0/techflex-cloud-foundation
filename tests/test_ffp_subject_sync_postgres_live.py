"""RAY-907 subject sync against live PostgreSQL role pools.

The static migration checks always run. The live flow needs the three role
DSNs of a database migrated through 0018 (FeetForcePlate 0017; plus the admin DSN for the audit
check). The upgrade check needs ``FEETFORCEPLATE_TEST_PRE0017_ADMIN_DSN``: an
admin DSN of a disposable database migrated through 0017 only; it seeds
subjects, applies 0018 and verifies the backfill.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.postgres import PostgresAccessRepository
from techflex_cloud_foundation.server.access_control.repository import TenantSeed
from techflex_cloud_foundation.server.access_control.terminal_service import TerminalAccessService
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)
from techflex_cloud_foundation.server.subject_sync.postgres import PostgresSubjectSyncRepository
from techflex_cloud_foundation.server.subject_sync.service import SubjectSyncService
from tests.test_ffp_postgres_access_repository import _group, _live_dsns
from tests.test_ffp_terminal_data_plane_postgres_live import _activate

ROOT = Path(__file__).resolve().parents[1]
MIGRATION = ROOT / "src/techflex_cloud_foundation/schema/sql/0018_subject_sync.sql"
SECRET = b"tenant-token-secret-must-be-at-least-32-bytes"
TABLES = (
    "subject.subject_revision_counters", "subject.tag_revision_counters",
    "subject.tags", "subject.subject_tags",
)
CHILD_TABLES = (
    "identity_profiles", "analysis_profiles", "external_identifiers", "consents",
    "subject_tags",
)


def test_migration_is_additive_rls_scoped_and_tenant_role_only() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    assert sql.startswith("BEGIN;") and sql.rstrip().endswith("COMMIT;")
    for forbidden in ("DROP ", "DELETE FROM", "TRUNCATE", "SECURITY DEFINER"):
        assert forbidden not in sql
    for table in TABLES:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" in sql
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;" in sql
    assert sql.count("USING (tenant_id = ops.current_tenant_id())") == len(TABLES)
    grants = [line for line in sql.splitlines() if line.startswith("GRANT ")]
    assert len(grants) == len(TABLES)
    assert all(line.endswith("TO ffp_tenant_app;") for line in grants)
    assert "GRANT SELECT, INSERT ON subject.tags TO ffp_tenant_app;" in grants
    assert "UNIQUE (tenant_id, name_key)" in sql
    assert "CREATE UNIQUE INDEX ux_subjects_tenant_revision" in sql
    assert "ON subject.subjects (tenant_id, revision)\nWHERE revision > 0;" in sql
    assert "name_lookup_hmac bytea" in sql


def test_triggers_are_created_after_the_creation_order_backfill() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")
    backfill = sql.index("ORDER BY created_at, subject_uuid")
    seeded = sql.index("SELECT tenant_id, max(revision) FROM subject.subjects")
    triggers = [sql.index(f"CREATE TRIGGER {name}_touch_subject") for name in CHILD_TABLES]
    assert backfill < seeded < sql.index("CREATE TRIGGER subjects_assign_revision")
    assert all(seeded < position for position in triggers)
    assert "BEFORE INSERT OR UPDATE ON subject.subjects" in sql
    for name in CHILD_TABLES:
        assert f"AFTER INSERT OR UPDATE OR DELETE ON subject.{name}" in sql


def test_plan_applies_and_backs_up_subject_sync_migration() -> None:
    from techflex_cloud_foundation.schema import DEFAULT_PLAN
    from techflex_cloud_foundation.schema.plan import Probe

    ids = [step.step_id for step in DEFAULT_PLAN]
    step = DEFAULT_PLAN[ids.index("0018_subject_sync")]
    assert ids.index("0018_subject_sync") > ids.index("0016_insole_session_archive")
    # A database that ran the migration as FeetForcePlate 0017 is recognised, not re-run.
    assert step.probe == Probe(column=("subject", "subjects", "revision"))
    grant = DEFAULT_PLAN[ids.index("grants_0018_subject_sync_to_backup")]
    assert grant.inline_sql is not None
    assert "subject.tags, subject.subject_tags\nTO ffp_seed_backup" in grant.inline_sql
    backup = (ROOT / "deploy/aliyun/seed/backup.sh").read_text(encoding="utf-8")
    assert "0017_schema_migrations,0018_subject_sync" in backup


@pytest.mark.skipif(
    not os.environ.get("FEETFORCEPLATE_TEST_PRE0017_ADMIN_DSN"),
    reason="no disposable database migrated through 0017 is configured",
)
def test_migration_backfills_existing_subjects_in_creation_order() -> None:
    import asyncpg

    async def exercise() -> None:
        admin = await asyncpg.connect(os.environ["FEETFORCEPLATE_TEST_PRE0017_ADMIN_DSN"])
        try:
            assert not await admin.fetchval(
                "SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE "
                "table_schema='subject' AND table_name='subjects' AND column_name='revision')"
            ), "database is already migrated through 0018"
            base = datetime(2026, 1, 1, tzinfo=UTC)
            tenants = {uuid4(): [], uuid4(): []}
            for index, tenant_id in enumerate(tenants):
                await admin.execute(
                    "INSERT INTO iam.tenants (tenant_id, name, status) "
                    "VALUES ($1,$2,'ACTIVE')", tenant_id, f"RAY-907 upgrade {index}",
                )
                # Inserted out of creation order on purpose.
                for offset in (3, 1, 2):
                    subject_uuid = uuid4()
                    await admin.execute(
                        "INSERT INTO subject.subjects (subject_uuid, tenant_id, status, "
                        "created_at, updated_at) VALUES ($1,$2,'ACTIVE',$3,$3)",
                        subject_uuid, tenant_id, base + timedelta(days=offset),
                    )
                    tenants[tenant_id].append((offset, subject_uuid))
            await admin.execute(MIGRATION.read_text(encoding="utf-8"))
            for tenant_id, subjects in tenants.items():
                rows = await admin.fetch(
                    "SELECT subject_uuid, revision FROM subject.subjects WHERE tenant_id=$1 "
                    "ORDER BY revision", tenant_id,
                )
                expected = [uuid for _, uuid in sorted(subjects)]
                assert [row["subject_uuid"] for row in rows] == expected
                assert [row["revision"] for row in rows] == [1, 2, 3]
                assert await admin.fetchval(
                    "SELECT last_revision FROM subject.subject_revision_counters "
                    "WHERE tenant_id=$1", tenant_id) == 3
                # The triggers continue the sequence from the backfilled maximum.
                first = expected[0]
                await admin.execute(
                    """INSERT INTO subject.consents (consent_record_id, tenant_id,
                       subject_uuid, policy_version, purpose_codes, data_categories,
                       evidence_type, evidence_hash, granted_at)
                       VALUES ($1,$2,$3,'p/1','{S}','{D}','OPERATOR_CONFIRMED',$4,now())""",
                    uuid4(), tenant_id, first, "0" * 64,
                )
                assert await admin.fetchval(
                    "SELECT revision FROM subject.subjects WHERE subject_uuid=$1", first
                ) == 4
                assert await admin.fetchval(
                    "SELECT name_lookup_hmac IS NULL FROM subject.identity_profiles "
                    "WHERE subject_uuid=$1", first) is None
        finally:
            await admin.close()

    asyncio.run(exercise())


async def _tenant(access, index: int):
    tenant = TenantSeed(uuid4(), f"RAY-907 clinic {index} {uuid4()}")
    group = _group(index, run_nonce=os.urandom(32))
    await access.provision_tenant(tenant, group, created_at=group.license_valid_from)
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
    return tenant.tenant_id, group, installation


@pytest.mark.skipif(_live_dsns() is None, reason="three PostgreSQL role DSNs are not configured")
def test_subject_sync_flow_over_live_role_pools() -> None:
    import asyncpg

    tenant_dsn, activation_dsn, platform_dsn = _live_dsns() or ("", "", "")
    admin_dsn = os.environ.get("FEETFORCEPLATE_TEST_ADMIN_DSN", "")

    async def exercise() -> None:
        pools = [
            await asyncpg.create_pool(dsn, min_size=1, max_size=6)
            for dsn in (tenant_dsn, activation_dsn, platform_dsn)
        ]
        tenant_pool, activation_pool, platform_pool = pools
        try:
            access = PostgresAccessRepository(
                tenant_pool=tenant_pool, activation_pool=activation_pool,
                platform_pool=platform_pool,
            )
            tenant_a, group_a, terminal_a = await _tenant(access, 81)
            tenant_b, group_b, terminal_b = await _tenant(access, 82)
            private_key = Ed25519PrivateKey.generate()
            signer = LicenseDocumentSigner(
                private_key=private_key, key_id="license/2-key-1",
                public_keys={"license/2-key-1": private_key.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw)},
            )
            tokens = TerminalAccessTokenIssuer(secret=SECRET, key_id="tenant/1")
            identity = IdentityProtector(
                encryption_key=b"e" * 32, lookup_hmac_key=b"h" * 32, key_version="identity/1"
            )
            terminal_access = TerminalAccessService(
                access, login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
                terminal_tokens=tokens,
                refresh_tokens=TerminalRefreshTokenFactory(
                    digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"),
                license_signer=signer,
            )
            data = PostgresPlatformRepository(tenant_pool, platform_pool=platform_pool)
            app = create_app(ServiceContainer(
                subjects=SubjectConsentService(data, identity),
                terminal_access=terminal_access,
                terminal_tokens=tokens,
                subject_sync=SubjectSyncService(
                    PostgresSubjectSyncRepository(tenant_pool), terminal_access, identity
                ),
            ))

            def bearer(tenant_id, group, installation, key=None):
                token = tokens.issue(
                    tenant_id=tenant_id, account_id=group.account_id,
                    license_id=group.license_id, client_installation_id=installation,
                )
                headers = {"Authorization": f"Bearer {token}"}
                return headers | ({} if key is None else {"Idempotency-Key": key})

            def a(key=None):
                return bearer(tenant_a, group_a, terminal_a, key)

            def b(key=None):
                return bearer(tenant_b, group_b, terminal_b, key)

            run = uuid4().hex[:8]
            number = {"issuer": "ray-907", "id_type": "medical_record_number"}

            async with AsyncClient(
                transport=ASGITransport(app=app), base_url="https://cloud.test"
            ) as client:
                async def create(name, external_id, headers=a):
                    subject_uuid = uuid4()
                    response = await client.post("/v1/subjects", headers=headers(str(uuid4())), json={
                        "subject_uuid": str(subject_uuid),
                        "external_identifier": {**number, "external_id": external_id},
                        "identity_profile": {"display_name": name, "contact": "secret-contact"},
                        "analysis_profile": {"height_cm": {"state": "PROVIDED", "value": 168.0}},
                    })
                    assert response.status_code == 201, response.text
                    return subject_uuid

                async def download(headers=a, **params):
                    response = await client.get("/v1/subjects", headers=headers(), params=params)
                    assert response.status_code == 200, response.text
                    return response.json()["data"]

                async def record(subject_uuid):
                    items = (await download(limit=500))["items"]
                    return next(i for i in items if i["subject_uuid"] == str(subject_uuid))

                async def patch(subject_uuid, body, key=None, headers=a):
                    return await client.patch(
                        f"/v1/subjects/{subject_uuid}", headers=headers(key or str(uuid4())),
                        json=body)

                subjects = [await create("Zhang San", f"A-{run}-{i}") for i in range(4)]
                # Complete, ordered paging.
                seen, cursor = [], None
                while True:
                    page = await download(limit=3, **({} if cursor is None else {"cursor": cursor}))
                    seen += page["items"]
                    cursor = page["next_cursor"]
                    if not page["has_more"]:
                        break
                assert [i["subject_uuid"] for i in seen] == [str(s) for s in subjects]
                revisions = [i["revision"] for i in seen]
                assert revisions == sorted(set(revisions))
                assert all(i["identity_profile"] == {"display_name": "Zhang San"} for i in seen)
                assert "secret-contact" not in str(seen)
                assert (await download(cursor=cursor))["items"] == []

                # Consent create and revoke re-deliver the subject.
                consent_id = uuid4()
                granted = await client.post("/v1/consents", headers=a(str(uuid4())), json={
                    "consent_record_id": str(consent_id), "subject_uuid": str(subjects[0]),
                    "policy_version": "privacy-policy/1.0", "purpose_codes": ["SCREENING_SERVICE"],
                    "data_categories": ["PRESSURE_RAW"], "granted_at": datetime.now(UTC).isoformat(),
                    "evidence_type": "OPERATOR_CONFIRMED", "terminal_signature": "signed-client-evidence",
                })
                assert granted.status_code == 201, granted.text
                page = await download(cursor=cursor)
                assert [i["subject_uuid"] for i in page["items"]] == [str(subjects[0])]
                assert page["items"][0]["consents"][0]["consent_record_id"] == str(consent_id)
                revoked = await client.post(
                    f"/v1/consents/{consent_id}/revoke", headers=a(str(uuid4())),
                    json={"revoked_at": datetime.now(UTC).isoformat(), "reason_code": "SUBJECT_REQUEST"})
                assert revoked.status_code == 200, revoked.text
                page = await download(cursor=page["next_cursor"])
                assert page["items"][0]["consents"][0]["revocation_reason_code"] == "SUBJECT_REQUEST"

                # Tags.
                tag_id = uuid4()
                tag = await client.post("/v1/subject-tags", headers=a("tag-key"),
                                        json={"tag_id": str(tag_id), "name": f"Follow {run}"})
                assert tag.status_code == 201, tag.text
                replay = await client.post("/v1/subject-tags", headers=a("tag-key"),
                                           json={"tag_id": str(tag_id), "name": f"Follow {run}"})
                assert (replay.status_code, replay.json()["data"]) == (201, tag.json()["data"])
                conflict = await client.post("/v1/subject-tags", headers=a(str(uuid4())),
                                             json={"tag_id": str(uuid4()), "name": f"FOLLOW {run}"})
                assert conflict.status_code == 200 and conflict.json()["data"]["conflict"] is True
                tags = (await client.get("/v1/subject-tags", headers=a())).json()["data"]["items"]
                assert [t["tag_id"] for t in tags] == [str(tag_id)]
                assert (await client.get("/v1/subject-tags", headers=b())).json()["data"]["items"] == []

                # PATCH: merge, replace, supersede, replay, conflict.
                target = subjects[1]
                current = await record(target)
                body = {
                    "base_revision": current["revision"],
                    "analysis_profile": {"weight_kg": {"state": "PROVIDED", "value": 61.5}},
                    "identity_profile": {"display_name": "Li Si"},
                    "tag_ids": [str(tag_id)],
                    "external_identifier": {**number, "external_id": f"NEW-{run}"},
                    "status": "ARCHIVED",
                }
                patched = await patch(target, body, key="patch-key")
                assert patched.status_code == 200, patched.text
                updated = patched.json()["data"]
                assert updated["revision"] > current["revision"]
                assert set(updated["analysis_profile"]) == {"height_cm", "weight_kg"}
                assert updated["identity_profile"] == {"display_name": "Li Si"}
                assert updated["tag_ids"] == [str(tag_id)]
                assert updated["status"] == "ARCHIVED"
                assert updated == await record(target)
                again = await patch(target, body, key="patch-key")
                assert (again.status_code, again.json()["data"]) == (200, updated)
                other = await patch(target, {**body, "status": "ACTIVE"}, key="patch-key")
                assert other.json()["error"]["code"] == "E-API-409"
                stale = await patch(target, {**body, "status": "ACTIVE"})
                assert stale.status_code == 409
                assert stale.json()["error"]["code"] == "E-SUB-409-REVISION-CONFLICT"
                assert stale.json()["error"]["details"]["current"] == updated
                old = await client.post("/v1/subjects/resolve", headers=a(),
                                        json={**number, "external_id": f"A-{run}-1"})
                assert old.status_code == 404, old.text

                taken = await patch(subjects[2], {
                    "base_revision": (await record(subjects[2]))["revision"],
                    "external_identifier": {**number, "external_id": f"A-{run}-0"}})
                assert taken.json()["error"]["code"] == "E-SUB-409-NUMBER-TAKEN"
                assert taken.json()["error"]["details"]["subject_uuid"] == str(subjects[0])
                unknown = await patch(subjects[2], {
                    "base_revision": (await record(subjects[2]))["revision"],
                    "tag_ids": [str(uuid4())]})
                assert unknown.json()["error"]["code"] == "E-SUB-422-UNKNOWN-TAG"

                # Name lookup: normalized, exact, ACTIVE and ARCHIVED only.
                found = await client.post("/v1/subjects/search-by-name", headers=a(),
                                          json={"display_name": "  ZHANG SAN "})
                assert {i["subject_uuid"] for i in found.json()["data"]["items"]} == {
                    str(subjects[0]), str(subjects[2]), str(subjects[3])}
                archived = await client.post("/v1/subjects/search-by-name", headers=a(),
                                             json={"display_name": "li si"})
                assert [i["subject_uuid"] for i in archived.json()["data"]["items"]] == [str(target)]

                # Isolation: the other institution sees nothing and gets 404.
                assert (await download(b))["items"] == []
                hidden = await client.post("/v1/subjects/search-by-name", headers=b(),
                                           json={"display_name": "Zhang San"})
                assert hidden.json()["data"]["items"] == []
                foreign = await patch(subjects[0], {"base_revision": 1, "status": "ARCHIVED"},
                                      headers=b)
                assert foreign.status_code == 404, foreign.text

                # Concurrent writers on one subject neither deadlock nor reuse a revision.
                hot = subjects[3]
                base_revision = (await record(hot))["revision"]

                async def consent_writer(index):
                    return await client.post("/v1/consents", headers=a(str(uuid4())), json={
                        "consent_record_id": str(uuid4()), "subject_uuid": str(hot),
                        "policy_version": "privacy-policy/1.0",
                        "purpose_codes": ["SCREENING_SERVICE"], "data_categories": ["PRESSURE_RAW"],
                        "granted_at": datetime.now(UTC).isoformat(),
                        "evidence_type": "OPERATOR_CONFIRMED",
                        "terminal_signature": f"signed-client-evidence-{index}",
                    })

                results = await asyncio.gather(
                    *(consent_writer(index) for index in range(4)),
                    # A profile edit, so the consents still see an ACTIVE subject.
                    *(patch(hot, {"base_revision": base_revision, "analysis_profile": {
                        "weight_kg": {"state": "PROVIDED", "value": 60.0 + index}}})
                      for index in range(3)),
                )
                assert [r.status_code for r in results[:4]] == [201] * 4
                patch_codes = sorted(r.status_code for r in results[4:])
                assert patch_codes.count(200) <= 1 and set(patch_codes) <= {200, 409}
                final = await record(hot)
                assert len(final["consents"]) == 4
                everything = (await download(limit=500))["items"]
                all_revisions = [i["revision"] for i in everything]
                assert all_revisions == sorted(set(all_revisions))

                # Writers of one number serialize: exactly one wins, the others
                # get E-SUB-409-NUMBER-TAKEN (never 500 or a deadlock), also
                # against a concurrent create with that number.
                for round_index in range(3):
                    racers = [await create(f"Racer {i}", f"R-{run}-{round_index}-{i}")
                              for i in range(3)]
                    contested = f"CONTESTED-{run}-{round_index}"
                    bases = [(await record(uuid))["revision"] for uuid in racers]

                    async def create_contested(contested=contested):
                        response = await client.post(
                            "/v1/subjects", headers=a(str(uuid4())), json={
                                "subject_uuid": str(uuid4()),
                                "external_identifier": {**number, "external_id": contested},
                                "analysis_profile": {}})
                        return response

                    outcomes = await asyncio.gather(
                        *(patch(uuid, {"base_revision": base, "external_identifier": {
                            **number, "external_id": contested}})
                          for uuid, base in zip(racers, bases, strict=True)),
                        create_contested(),
                    )
                    patch_results = outcomes[:3]
                    assert all(r.status_code in (200, 409) for r in patch_results), [
                        r.text for r in patch_results]
                    created = outcomes[3]
                    assert created.status_code in (200, 201), created.text
                    winners = [r for r in patch_results if r.status_code == 200]
                    if created.status_code == 201:
                        assert winners == []
                    else:
                        assert len(winners) == 1 and created.json()["data"]["conflict"]
                    assert all(r.json()["error"]["code"] == "E-SUB-409-NUMBER-TAKEN"
                               for r in patch_results if r.status_code == 409)

            if admin_dsn:
                admin = await asyncpg.connect(admin_dsn)
                try:
                    audits = await admin.fetch(
                        "SELECT actor_type, actor_id, action, safe_context FROM ops.audit_logs "
                        "WHERE tenant_id = ANY($1::uuid[]) AND action='subject.search-by-name' "
                        "ORDER BY occurred_at", [tenant_a, tenant_b])
                    assert len(audits) == 3
                    assert {row["actor_id"] for row in audits} == {terminal_a, terminal_b}
                    assert all("zhang" not in str(row).lower() and "li si" not in str(row).lower()
                               for row in audits)
                    stored = await admin.fetchval(
                        "SELECT count(*) FROM subject.external_identifiers WHERE subject_uuid=$1 "
                        "AND status='SUPERSEDED'", target)
                    assert stored == 1
                    keys = await admin.fetch(
                        "SELECT response_json::text AS body FROM ops.idempotency_keys "
                        "WHERE tenant_id=$1 AND scope IN ('subject.patch','subject-tag.create')",
                        tenant_a)
                    assert keys and all("Li Si" not in row["body"] for row in keys)
                finally:
                    await admin.close()
        finally:
            for pool in pools:
                await pool.close()

    asyncio.run(exercise())
