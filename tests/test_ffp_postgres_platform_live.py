"""``PostgresPlatformRepository`` against a real PostgreSQL (RAY-830 ``ingestion-repository``).

The schema is installed by the shipped runner (0001-0017 plus the deployment role
step) into an ephemeral cluster, and the repository connects through a login role
that inherits ``ffp_tenant_app`` -- the least-privilege role of the seed
deployment -- so row-level security is really in force. Prerequisite rows
(tenant, activated terminal, insole device) are inserted as the cluster
superuser; subjects and consents go through the repository itself.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any, TypeVar
from uuid import UUID, uuid4

import pytest

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ConsentRevokeRequest,
    ExternalIdentifierInput,
    ManifestSegment,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    SubjectCreateRequest,
    TestProtocol,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    ManifestConflict,
    ManifestIncomplete,
    ResourceNotFound,
    SegmentDigestConflict,
    TenantAccessDenied,
)
from techflex_cloud_foundation.schema import RoleMissing, apply_migrations
from techflex_cloud_foundation.server.postgres import PostgresPlatformRepository, tenant_transaction
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)
from tests.pg_cluster import Cluster, find_postgres_bin, running_cluster
from tests.test_schema_migrations import ROLE_STEP

asyncpg = pytest.importorskip("asyncpg")
BIN = find_postgres_bin()
pytestmark = pytest.mark.skipif(BIN is None, reason="no PostgreSQL server installation found")

T = TypeVar("T")
DB = "ingestion_live"
TENANT_LOGIN = "ffp_seed_tenant"
ELIGIBILITY = "principal can_upload; manifest digest matched"
POLICY = "seed-completion-eligibility/1"


@pytest.fixture(scope="module")
def cluster() -> Iterator[Cluster]:
    assert BIN is not None
    with running_cluster(BIN) as running:

        async def install() -> None:
            admin = await asyncpg.connect(
                host=running.socket_dir, port=running.port, user="postgres", database="postgres"
            )
            try:
                await admin.execute(f"CREATE DATABASE {DB}")
            finally:
                await admin.close()
            conn = await _superuser(running)
            try:
                with pytest.raises(RoleMissing):
                    await apply_migrations(conn)
                await conn.execute(ROLE_STEP)
                await apply_migrations(conn)
                await conn.execute(ROLE_STEP)  # the installer re-runs it after migrating
                await conn.execute(
                    f"CREATE ROLE {TENANT_LOGIN} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
                    "INHERIT NOBYPASSRLS; GRANT ffp_tenant_app TO " + TENANT_LOGIN
                )
            finally:
                await conn.close()

        asyncio.run(install())
        yield running


async def _superuser(cluster: Cluster) -> Any:
    return await asyncpg.connect(
        host=cluster.socket_dir, port=cluster.port, user="postgres", database=DB
    )


def _run(cluster: Cluster, body: Callable[[Harness], Awaitable[T]]) -> T:
    async def go() -> T:
        admin = await _superuser(cluster)
        pool = await asyncpg.create_pool(
            host=cluster.socket_dir,
            port=cluster.port,
            user=TENANT_LOGIN,
            database=DB,
            min_size=1,
            max_size=4,
        )
        try:
            return await body(Harness(admin, pool))
        finally:
            await pool.close()
            await admin.close()

    return asyncio.run(go())


class Tenant:
    def __init__(self, tenant_id: UUID, terminal_id: UUID, device_id: UUID) -> None:
        self.tenant_id = tenant_id
        self.terminal_id = terminal_id
        self.device_id = device_id
        self.principal = IngestionPrincipal(
            tenant_id=tenant_id,
            terminal_id=terminal_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            allow_new_test=True,
            allow_upload=True,
            account_id=uuid4(),
            license_id=uuid4(),
            terminal_access=True,
        )


class Harness:
    def __init__(self, admin: Any, pool: Any) -> None:
        self.admin = admin
        self.pool = pool
        self.repository = PostgresPlatformRepository(pool)
        self.subjects = SubjectConsentService(
            self.repository,
            IdentityProtector(
                encryption_key=b"e" * 32, lookup_hmac_key=b"h" * 32, key_version="identity/1"
            ),
        )

    async def tenant(self) -> Tenant:
        tenant = Tenant(uuid4(), uuid4(), uuid4())
        await self.admin.execute(
            "INSERT INTO iam.tenants (tenant_id, name, status) VALUES ($1, $2, 'ACTIVE')",
            tenant.tenant_id,
            f"live {tenant.tenant_id}",
        )
        await self.admin.execute(
            "INSERT INTO device.terminals (terminal_id, tenant_id, installation_id, "
            "client_public_key, status) VALUES ($1, $2, $1, 'terminal-access-v1', 'ACTIVE')",
            tenant.terminal_id,
            tenant.tenant_id,
        )
        await self.admin.execute(
            "INSERT INTO device.devices (device_id, tenant_id, model, status) "
            "VALUES ($1, $2, 'insole-pair', 'ACTIVE')",
            tenant.device_id,
            tenant.tenant_id,
        )
        return tenant

    async def subject_and_consent(self, tenant: Tenant) -> tuple[UUID, UUID]:
        subject = await self.subjects.create_subject(
            tenant.principal,
            SubjectCreateRequest(
                subject_uuid=uuid4(),
                external_identifier=ExternalIdentifierInput(
                    issuer="site-main", id_type="medical_record_number", external_id="A-123456"
                ),
                analysis_profile={},
            ),
            f"subject-{uuid4()}",
        )
        consent_id = uuid4()
        await self.subjects.create_consent(
            tenant.principal,
            ConsentCreateRequest(
                consent_record_id=consent_id,
                subject_uuid=subject.subject_uuid,
                policy_version="privacy-policy/1.0",
                purpose_codes=("SCREENING_SERVICE",),
                data_categories=("PRESSURE_RAW",),
                granted_at=datetime.now(UTC),
                evidence_type="OPERATOR_CONFIRMED",
                terminal_signature="signed-terminal-evidence",
            ),
            f"consent-{uuid4()}",
        )
        return subject.subject_uuid, consent_id

    async def session(
        self, tenant: Tenant, key: str | None = None
    ) -> tuple[UUID, SessionCreateRequest]:
        subject_uuid, consent_id = await self.subject_and_consent(tenant)
        request = SessionCreateRequest(
            session_id=uuid4(),
            subject_uuid=subject_uuid,
            consent_record_id=consent_id,
            site_id=None,
            terminal_id=tenant.terminal_id,
            client_installation_id=tenant.terminal_id,
            device_id=tenant.device_id,
            test_protocol=TestProtocol(id="standard-screening", version="1.0"),
            versions=SessionVersions(
                app="0.1.0",
                protocol_profile="do-p4864/1",
                payload_schema="raw-segment/1",
                calibration="calibration/1",
            ),
            started_at=datetime.now(UTC),
            config_snapshot={"screening_duration_seconds": 30},
        )
        await self.repository.create_session(tenant.principal, request, key or f"s-{uuid4()}")
        return request.session_id, request


def _segment(index: int, payload: bytes | None = None) -> SegmentMetadata:
    payload = payload or f"segment-{index}".encode()
    return SegmentMetadata(
        segment_index=index,
        start_frame_index=index * 10,
        frame_count=10,
        start_monotonic_ns=100 + index * 100,
        end_monotonic_ns=199 + index * 100,
        compression="zstd",
        cipher="aes-256-gcm",
        size_bytes=len(payload),
        sha256=hashlib.sha256(payload).hexdigest(),
        payload_schema_version="raw-segment/1",
    )


def _manifest(*segments: SegmentMetadata, ended_at: datetime | None = None) -> SessionManifest:
    return SessionManifest(
        segment_count=len(segments),
        total_frames=sum(s.frame_count for s in segments),
        total_bytes=sum(s.size_bytes for s in segments),
        segments=tuple(
            ManifestSegment(
                index=s.segment_index,
                sha256=s.sha256,
                size_bytes=s.size_bytes,
                frame_count=s.frame_count,
            )
            for s in segments
        ),
        ended_at=ended_at or datetime.now(UTC),
        local_quality_outcome="VALID",
        schema_version="session-manifest/1",
    )


def _key(session_id: UUID, tenant: Tenant, metadata: SegmentMetadata) -> str:
    return (
        f"tenants/{tenant.tenant_id}/sessions/{session_id}/segments/"
        f"{metadata.segment_index}-{metadata.sha256}.ffps"
    )


# ------------------------------------------------------------------ isolation


def test_the_repository_connects_as_a_row_level_security_role(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        row = await h.pool.fetchrow(
            "SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user"
        )
        assert (row["rolsuper"], row["rolbypassrls"]) == (False, False)

    _run(cluster, body)


def test_tenant_b_cannot_see_or_touch_tenant_a_sessions(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a, b = await h.tenant(), await h.tenant()
        session_id, _ = await h.session(a)
        segment = _segment(0)
        await h.repository.register_segment(
            a.principal, session_id, segment, _key(session_id, a, segment)
        )

        # Through the repository, tenant B gets "not found", never A's row.
        with pytest.raises(ResourceNotFound):
            await h.repository.session(b.principal, session_id)
        with pytest.raises(ResourceNotFound):
            await h.repository.status(b.principal, session_id)
        with pytest.raises(ResourceNotFound):
            await h.repository.register_segment(b.principal, session_id, segment, "b/object")
        assert not await h.repository.object_is_referenced(
            b.tenant_id, _key(session_id, a, segment)
        )
        assert await h.repository.object_is_referenced(a.tenant_id, _key(session_id, a, segment))

        # Directly on the table, RLS shows each tenant only its own rows ...
        async with tenant_transaction(h.pool, b.tenant_id) as conn:
            assert await conn.fetchval("SELECT count(*) FROM screening.sessions") == 0
            assert await conn.fetchval("SELECT count(*) FROM screening.session_segments") == 0
        async with tenant_transaction(h.pool, a.tenant_id) as conn:
            assert await conn.fetchval("SELECT count(*) FROM screening.sessions") == 1
            # ... and cannot write another tenant's rows.
            with pytest.raises(asyncpg.PostgresError):
                await conn.execute(
                    "INSERT INTO ops.idempotency_keys (idempotency_record_id, tenant_id, scope, "
                    "idempotency_key, request_sha256, response_status, response_json, "
                    "resource_type, resource_id, expires_at) VALUES ($1, $2, 's', 'k', $3, 200, "
                    "'{}', 't', $1, now())",
                    uuid4(),
                    b.tenant_id,
                    "0" * 64,
                )

    _run(cluster, body)


def test_the_tenant_context_does_not_leak_between_transactions(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        await h.session(a)
        async with h.pool.acquire() as conn:
            async with tenant_transaction(h.pool, a.tenant_id):
                pass
            # Same pooled connection, new transaction, no context: nothing is visible
            # (the policy yields no rows, or refuses the unset setting).
            try:
                visible = await conn.fetchval("SELECT count(*) FROM screening.sessions")
            except asyncpg.PostgresError:
                visible = 0
            assert visible == 0

    _run(cluster, body)


def test_a_terminal_of_another_tenant_cannot_be_used(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a, b = await h.tenant(), await h.tenant()
        stranger = IngestionPrincipal(
            tenant_id=a.tenant_id,
            terminal_id=b.terminal_id,
            expires_at=a.principal.expires_at,
            allow_new_test=True,
            allow_upload=True,
            terminal_access=True,
        )
        subject_uuid, consent_id = await h.subject_and_consent(a)
        request = SessionCreateRequest(
            session_id=uuid4(),
            subject_uuid=subject_uuid,
            consent_record_id=consent_id,
            site_id=None,
            terminal_id=b.terminal_id,
            client_installation_id=b.terminal_id,
            device_id=a.device_id,
            test_protocol=TestProtocol(id="standard-screening", version="1.0"),
            versions=SessionVersions(
                app="0.1.0",
                protocol_profile="do-p4864/1",
                payload_schema="raw-segment/1",
                calibration="calibration/1",
            ),
            started_at=datetime.now(UTC),
        )
        with pytest.raises(TenantAccessDenied):
            await h.repository.create_session(stranger, request, "stranger")

    _run(cluster, body)


# ------------------------------------------------------------------- sessions


def test_create_session_is_idempotent_and_refuses_a_changed_body(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        session_id, request = await h.session(a, key="create-1")

        replay = await h.repository.create_session(a.principal, request, "create-1")
        assert replay.session_id == session_id and replay.idempotent_replay is True

        # Same key and a different body, and same session id under another key.
        changed = request.model_copy(update={"config_snapshot": {"screening_duration_seconds": 31}})
        with pytest.raises(IdempotencyConflict):
            await h.repository.create_session(a.principal, changed, "create-1")
        with pytest.raises(IdempotencyConflict):
            await h.repository.create_session(a.principal, changed, "create-2")

        record = await h.repository.session(a.principal, session_id)
        assert record.request.config_snapshot == {"screening_duration_seconds": 30}
        assert record.ingest_status == "RECEIVING"
        assert (
            await h.admin.fetchval(
                "SELECT count(*) FROM screening.sessions WHERE session_id = $1", session_id
            )
            == 1
        )

    _run(cluster, body)


def test_a_session_needs_its_subject_and_a_live_consent(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        session_id, request = await h.session(a)
        await h.subjects.revoke_consent(
            a.principal,
            request.consent_record_id,
            ConsentRevokeRequest(revoked_at=datetime.now(UTC), reason_code="WITHDRAWN"),
            "revoke-1",
        )
        fresh = request.model_copy(update={"session_id": uuid4()})
        with pytest.raises(TenantAccessDenied):
            await h.repository.create_session(a.principal, fresh, "after-revoke")
        stray = request.model_copy(update={"session_id": uuid4(), "subject_uuid": uuid4()})
        with pytest.raises(TenantAccessDenied):
            await h.repository.create_session(a.principal, stray, "unknown-subject")

    _run(cluster, body)


# ------------------------------------------------------------ subject, consent


def test_subjects_are_per_tenant_and_a_duplicate_identifier_is_a_conflict(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a, b = await h.tenant(), await h.tenant()

        def request() -> SubjectCreateRequest:
            return SubjectCreateRequest(
                subject_uuid=uuid4(),
                external_identifier=ExternalIdentifierInput(
                    issuer="site-main", id_type="medical_record_number", external_id=" A-1 "
                ),
                analysis_profile={},
            )

        first = await h.subjects.create_subject(a.principal, request(), "dup-1")
        again = await h.subjects.create_subject(a.principal, request(), "dup-2")
        other = await h.subjects.create_subject(b.principal, request(), "dup-1")

        assert not first.conflict and again.conflict
        assert again.subject_uuid == first.subject_uuid
        assert other.subject_uuid != first.subject_uuid and not other.conflict
        # No plaintext identifier reaches the table.
        stored = await h.admin.fetchval(
            "SELECT encrypted_value FROM subject.external_identifiers WHERE subject_uuid = $1",
            first.subject_uuid,
        )
        assert b"A-1" not in stored

    _run(cluster, body)


def test_consent_create_replay_conflict_and_revocation(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a, b = await h.tenant(), await h.tenant()
        subject_uuid, consent_id = await h.subject_and_consent(a)
        assert await h.repository.is_consent_active(a.tenant_id, consent_id)
        assert not await h.repository.is_consent_active(b.tenant_id, consent_id)

        base = dict(
            consent_record_id=consent_id,
            subject_uuid=subject_uuid,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW",),
            granted_at=datetime.now(UTC),
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-terminal-evidence",
        )
        changed = ConsentCreateRequest(**{**base, "policy_version": "privacy-policy/2.0"})
        with pytest.raises(IdempotencyConflict):
            await h.subjects.create_consent(a.principal, changed, "consent-changed")
        with pytest.raises(TenantAccessDenied):  # tenant B has no such subject
            await h.subjects.create_consent(b.principal, ConsentCreateRequest(**base), "other")

        revoked_at = datetime.now(UTC)
        revoke = ConsentRevokeRequest(revoked_at=revoked_at, reason_code="WITHDRAWN")
        first = await h.subjects.revoke_consent(a.principal, consent_id, revoke, "revoke")
        replay = await h.subjects.revoke_consent(a.principal, consent_id, revoke, "revoke")
        assert first == replay and first.revoked_at == revoked_at
        assert not await h.repository.is_consent_active(a.tenant_id, consent_id)
        with pytest.raises(IdempotencyConflict):
            await h.subjects.revoke_consent(
                a.principal,
                consent_id,
                ConsentRevokeRequest(
                    revoked_at=revoked_at + timedelta(seconds=1), reason_code="WITHDRAWN"
                ),
                "revoke-later",
            )
        with pytest.raises(ResourceNotFound):
            await h.subjects.revoke_consent(b.principal, consent_id, revoke, "revoke-b")

    _run(cluster, body)


# ------------------------------------------------------------------- segments


def test_segments_register_idempotently_and_conflict_on_a_different_digest(
    cluster: Cluster,
) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        session_id, _ = await h.session(a)
        seg0, seg1 = _segment(0), _segment(1)
        key0, key1 = _key(session_id, a, seg0), _key(session_id, a, seg1)

        assert await h.repository.get_segment(a.principal, session_id, 0) is None
        first = await h.repository.register_segment(a.principal, session_id, seg0, key0)
        again = await h.repository.register_segment(a.principal, session_id, seg0, key0)
        await h.repository.register_segment(a.principal, session_id, seg1, key1)
        assert first.object_key == again.object_key == key0
        assert first.metadata == seg0

        listed = await h.repository.list_segments(a.principal, session_id)
        assert [r.metadata.segment_index for r in listed] == [0, 1]
        assert (await h.repository.get_segment(a.principal, session_id, 1)).object_key == key1  # type: ignore[union-attr]

        other = _segment(0, b"different bytes")
        with pytest.raises(SegmentDigestConflict):
            await h.repository.register_segment(
                a.principal, session_id, other, _key(session_id, a, other)
            )
        assert not await h.repository.object_is_referenced(a.tenant_id, _key(session_id, a, other))
        assert await h.repository.object_is_referenced(a.tenant_id, key0)

        with pytest.raises(ResourceNotFound):
            await h.repository.list_segments(a.principal, uuid4())

    _run(cluster, body)


def test_mark_segment_conflict_closes_the_session_to_segments(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        session_id, _ = await h.session(a)
        await h.repository.mark_segment_conflict(a.principal, session_id, 0)

        status = await h.repository.status(a.principal, session_id)
        assert status.ingest_status == "CONFLICT"
        problem = await h.admin.fetchrow(
            "SELECT problem_type, status, segment_index FROM screening.ingest_problems "
            "WHERE session_id = $1",
            session_id,
        )
        assert tuple(problem) == ("CONTENT_CONFLICT", "OPEN", 0)
        seg = _segment(2)
        with pytest.raises(SegmentDigestConflict):
            await h.repository.register_segment(
                a.principal, session_id, seg, _key(session_id, a, seg)
            )
        with pytest.raises(ResourceNotFound):
            await h.repository.mark_segment_conflict(a.principal, uuid4(), 0)

    _run(cluster, body)


# ------------------------------------------------------------------- manifest


def test_complete_manifest_records_a_receipt_and_replays_it(cluster: Cluster) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        session_id, _ = await h.session(a)
        seg0, seg1 = _segment(0), _segment(1)
        for seg in (seg0, seg1):
            await h.repository.register_segment(
                a.principal, session_id, seg, _key(session_id, a, seg)
            )
        manifest = _manifest(seg0, seg1)
        digest = canonical_sha256(manifest)
        manifest_key = f"tenants/{a.tenant_id}/sessions/{session_id}/manifests/{digest}.json"
        completed_at = datetime.now(UTC)

        async def complete(key: str, m: SessionManifest = manifest, d: str = digest):  # type: ignore[no-untyped-def]
            return await h.repository.complete_manifest(
                a.principal,
                session_id,
                m,
                d,
                manifest_key,
                key,
                eligibility_reason=ELIGIBILITY,
                eligibility_policy_version=POLICY,
                completed_at=completed_at,
            )

        first = await complete("complete-1")
        replay = await complete("complete-1")
        assert first.ingest_status == "INGESTED" and not first.idempotent_replay
        assert replay.idempotent_replay and replay.manifest_sha256 == first.manifest_sha256
        assert replay.completed_at == first.completed_at == completed_at
        assert (replay.eligibility_reason, replay.eligibility_policy_version) == (
            ELIGIBILITY,
            POLICY,
        )

        # A second key for the same manifest is also a replay, not a second event.
        assert (await complete("complete-2")).idempotent_replay

        status = await h.repository.status(a.principal, session_id)
        assert (status.ingest_status, status.validity_status) == ("INGESTED", "VALID")
        assert await h.repository.expected_segment_count(a.principal, session_id) == 2
        assert await h.repository.object_is_referenced(a.tenant_id, manifest_key)
        events = await h.admin.fetch(
            "SELECT event_type, aggregate_version FROM ops.outbox_events WHERE aggregate_id = $1",
            session_id,
        )
        assert [tuple(e) for e in events] == [("session.ingested.v1", 2)]

        changed = _manifest(seg0, seg1, ended_at=manifest.ended_at + timedelta(seconds=1))
        with pytest.raises(ManifestConflict):
            await complete("complete-3", changed, canonical_sha256(changed))
        seg = _segment(3)
        with pytest.raises(SegmentDigestConflict):  # an ingested session takes no more segments
            await h.repository.register_segment(
                a.principal, session_id, seg, _key(session_id, a, seg)
            )

    _run(cluster, body)


def test_an_incomplete_manifest_is_refused_and_leaves_a_problem_not_an_event(
    cluster: Cluster,
) -> None:
    async def body(h: Harness) -> None:
        a = await h.tenant()
        session_id, _ = await h.session(a)
        seg0, seg1 = _segment(0), _segment(1)
        await h.repository.register_segment(
            a.principal, session_id, seg0, _key(session_id, a, seg0)
        )
        manifest = _manifest(seg0, seg1)
        digest = canonical_sha256(manifest)

        with pytest.raises(ManifestIncomplete):
            await h.repository.complete_manifest(
                a.principal,
                session_id,
                manifest,
                digest,
                f"m/{digest}.json",
                "incomplete",
                eligibility_reason=ELIGIBILITY,
                eligibility_policy_version=POLICY,
                completed_at=datetime.now(UTC),
            )

        assert (await h.repository.status(a.principal, session_id)).ingest_status == "RECEIVING"
        assert (
            await h.admin.fetchval(
                "SELECT count(*) FROM ops.outbox_events WHERE aggregate_id = $1", session_id
            )
            == 0
        )
        assert (
            await h.admin.fetchval(
                "SELECT problem_type FROM screening.ingest_problems WHERE session_id = $1",
                session_id,
            )
            == "MISSING_SEGMENT"
        )
        # The late segment arrives and the same manifest then completes.
        await h.repository.register_segment(
            a.principal, session_id, seg1, _key(session_id, a, seg1)
        )
        done = await h.repository.complete_manifest(
            a.principal,
            session_id,
            manifest,
            digest,
            f"m/{digest}.json",
            "complete",
            eligibility_reason=ELIGIBILITY,
            eligibility_policy_version=POLICY,
            completed_at=datetime.now(UTC),
        )
        assert done.ingest_status == "INGESTED" and not done.idempotent_replay

    _run(cluster, body)
