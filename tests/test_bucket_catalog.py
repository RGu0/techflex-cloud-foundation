"""Public contract tests for the logical bucket catalog and presigned grants."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib

import pytest

from techflex_cloud_foundation import (
    BucketBinding,
    BucketCatalog,
    BucketCatalogMalformed,
    BucketEncryption,
    BucketPolicy,
    BucketRole,
    BucketRoleUnknown,
    InMemoryObjectStore,
    InMemoryPresignedGrantStore,
    ObjectConflict,
    PresignedGrantAuthority,
    PresignedGrantConstraintViolation,
    PresignedGrantExpired,
    PresignedGrantMalformed,
    PresignedGrantReplayed,
    PresignedGrantSignatureInvalid,
    RetentionClass,
)

pytestmark = pytest.mark.anyio


@pytest.fixture()
def anyio_backend() -> str:
    return "asyncio"


NOW = datetime(2026, 9, 3, 12, 0, 0, tzinfo=UTC)
PAYLOAD = b"catalog-payload-" * 64
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
OTHER = b"other-payload"
OTHER_DIGEST = hashlib.sha256(OTHER).hexdigest()
TENANT = "t-4f8a2c19"
ARTIFACT = "art-91d37be2"
SECRET = b"grant-signing-secret-material!!"[:32].ljust(32, b"0")

BINDINGS = (
    BucketBinding(
        role=BucketRole.RAW_IMMUTABLE,
        physical_bucket="phys-raw",
        policy=BucketPolicy(
            encryption=BucketEncryption.SSE_KMS,
            versioning=True,
            retention=RetentionClass.ARCHIVAL,
        ),
    ),
    BucketBinding(
        role=BucketRole.DERIVED,
        physical_bucket="phys-derived",
        policy=BucketPolicy(
            encryption=BucketEncryption.SSE_KMS,
            versioning=False,
            retention=RetentionClass.EPHEMERAL,
        ),
    ),
)


async def _chunks(payload: bytes, size: int = 100):
    for offset in range(0, len(payload), size):
        yield payload[offset : offset + size]


@pytest.fixture()
def store() -> InMemoryObjectStore:
    return InMemoryObjectStore()


@pytest.fixture()
def catalog(store: InMemoryObjectStore) -> BucketCatalog:
    return BucketCatalog(BINDINGS, store)


@pytest.fixture()
def authority(catalog: BucketCatalog) -> PresignedGrantAuthority:
    return PresignedGrantAuthority(
        catalog=catalog, store=InMemoryPresignedGrantStore(), secret=SECRET
    )


def _issue(authority: PresignedGrantAuthority, **overrides):
    params = {
        "tenant_id": TENANT,
        "role": BucketRole.RAW_IMMUTABLE,
        "artifact_id": ARTIFACT,
        "content_sha256": DIGEST,
        "size_bytes": len(PAYLOAD),
        "purpose": "artifact-upload",
        "now": NOW,
        "expires_at": NOW + timedelta(minutes=5),
    }
    params.update(overrides)
    return authority.issue_upload_grant(**params)


class TestCatalog:
    def test_undeclared_role_is_refused(self, catalog: BucketCatalog) -> None:
        with pytest.raises(BucketRoleUnknown):
            catalog.binding_for("tenant-photos")

    def test_unbound_declared_role_is_refused(self, catalog: BucketCatalog) -> None:
        with pytest.raises(BucketRoleUnknown):
            catalog.binding_for(BucketRole.REPORTS_EXPORTS)

    def test_duplicate_role_binding_is_refused(
        self, store: InMemoryObjectStore
    ) -> None:
        with pytest.raises(BucketCatalogMalformed):
            BucketCatalog((BINDINGS[0], BINDINGS[0]), store)

    def test_derive_object_key_layout(self, catalog: BucketCatalog) -> None:
        key = catalog.derive_object_key(
            tenant_id=TENANT,
            role=BucketRole.RAW_IMMUTABLE,
            artifact_id=ARTIFACT,
            content_sha256=DIGEST,
        )

        assert key == f"raw-immutable/{TENANT}/{ARTIFACT}/{DIGEST}"

    @pytest.mark.parametrize(
        "tenant_id",
        ["Zhang San", "t-1", "t/../escape", "archive-2024-001.pdf", ""],
    )
    def test_business_identifiers_never_enter_keys(
        self, catalog: BucketCatalog, tenant_id: str
    ) -> None:
        with pytest.raises(BucketCatalogMalformed):
            catalog.derive_object_key(
                tenant_id=tenant_id,
                role=BucketRole.RAW_IMMUTABLE,
                artifact_id=ARTIFACT,
                content_sha256=DIGEST,
            )


class TestPublish:
    async def test_publish_routes_by_role(
        self, catalog: BucketCatalog, store: InMemoryObjectStore
    ) -> None:
        published = await catalog.publish(
            tenant_id=TENANT,
            role=BucketRole.RAW_IMMUTABLE,
            artifact_id=ARTIFACT,
            content_sha256=DIGEST,
            size_bytes=len(PAYLOAD),
            chunks=_chunks(PAYLOAD),
        )

        assert published.role is BucketRole.RAW_IMMUTABLE
        assert published.physical_bucket == "phys-raw"
        assert published.object_key == f"raw-immutable/{TENANT}/{ARTIFACT}/{DIGEST}"
        assert await store.read(published.object_key) == PAYLOAD

    async def test_replay_with_identical_content_is_idempotent(
        self, catalog: BucketCatalog
    ) -> None:
        request = {
            "tenant_id": TENANT,
            "role": BucketRole.RAW_IMMUTABLE,
            "artifact_id": ARTIFACT,
            "content_sha256": DIGEST,
            "size_bytes": len(PAYLOAD),
        }
        await catalog.publish(chunks=_chunks(PAYLOAD), **request)
        replayed = await catalog.publish(chunks=_chunks(PAYLOAD), **request)

        assert replayed.sha256 == DIGEST

    async def test_same_key_with_different_content_conflicts(
        self, catalog: BucketCatalog, store: InMemoryObjectStore
    ) -> None:
        key = catalog.derive_object_key(
            tenant_id=TENANT,
            role=BucketRole.RAW_IMMUTABLE,
            artifact_id=ARTIFACT,
            content_sha256=DIGEST,
        )
        await store.put_verified(
            key, _chunks(OTHER), expected_sha256=OTHER_DIGEST, expected_size=len(OTHER)
        )

        with pytest.raises(ObjectConflict):
            await catalog.publish(
                tenant_id=TENANT,
                role=BucketRole.RAW_IMMUTABLE,
                artifact_id=ARTIFACT,
                content_sha256=DIGEST,
                size_bytes=len(PAYLOAD),
                chunks=_chunks(PAYLOAD),
            )

    async def test_publish_with_unknown_role_is_refused(
        self, catalog: BucketCatalog
    ) -> None:
        with pytest.raises(BucketRoleUnknown):
            await catalog.publish(
                tenant_id=TENANT,
                role="client-chosen-bucket",
                artifact_id=ARTIFACT,
                content_sha256=DIGEST,
                size_bytes=len(PAYLOAD),
                chunks=_chunks(PAYLOAD),
            )


class TestPresignedGrants:
    def test_issue_then_consume(self, authority: PresignedGrantAuthority) -> None:
        grant = _issue(authority)

        consumed = authority.consume_upload_grant(
            grant,
            purpose="artifact-upload",
            content_sha256=DIGEST,
            size_bytes=len(PAYLOAD),
            now=NOW + timedelta(minutes=1),
        )

        assert consumed is grant
        assert grant.object_key == f"raw-immutable/{TENANT}/{ARTIFACT}/{DIGEST}"
        assert grant.physical_bucket == "phys-raw"

    def test_expired_grant_is_refused(self, authority: PresignedGrantAuthority) -> None:
        grant = _issue(authority)

        with pytest.raises(PresignedGrantExpired):
            authority.consume_upload_grant(
                grant,
                purpose="artifact-upload",
                content_sha256=DIGEST,
                size_bytes=len(PAYLOAD),
                now=grant.expires_at,
            )

    def test_issue_refuses_past_expiry(self, authority: PresignedGrantAuthority) -> None:
        with pytest.raises(PresignedGrantMalformed):
            _issue(authority, expires_at=NOW)

    def test_issue_refuses_long_lifetime(
        self, authority: PresignedGrantAuthority
    ) -> None:
        with pytest.raises(PresignedGrantMalformed):
            _issue(authority, expires_at=NOW + timedelta(hours=1))

    def test_digest_mismatch_is_refused(
        self, authority: PresignedGrantAuthority
    ) -> None:
        grant = _issue(authority)

        with pytest.raises(PresignedGrantConstraintViolation):
            authority.consume_upload_grant(
                grant,
                purpose="artifact-upload",
                content_sha256=OTHER_DIGEST,
                size_bytes=len(PAYLOAD),
                now=NOW + timedelta(minutes=1),
            )

    def test_size_mismatch_is_refused(
        self, authority: PresignedGrantAuthority
    ) -> None:
        grant = _issue(authority)

        with pytest.raises(PresignedGrantConstraintViolation):
            authority.consume_upload_grant(
                grant,
                purpose="artifact-upload",
                content_sha256=DIGEST,
                size_bytes=len(PAYLOAD) + 1,
                now=NOW + timedelta(minutes=1),
            )

    def test_purpose_mismatch_is_refused(
        self, authority: PresignedGrantAuthority
    ) -> None:
        grant = _issue(authority, purpose="artifact-upload")

        with pytest.raises(PresignedGrantConstraintViolation):
            authority.consume_upload_grant(
                grant,
                purpose="report-export",
                content_sha256=DIGEST,
                size_bytes=len(PAYLOAD),
                now=NOW + timedelta(minutes=1),
            )

    def test_tampered_grant_is_refused(
        self, authority: PresignedGrantAuthority
    ) -> None:
        grant = _issue(authority)
        forged = replace(grant, size_bytes=grant.size_bytes + 4096)

        with pytest.raises(PresignedGrantSignatureInvalid):
            authority.consume_upload_grant(
                forged,
                purpose="artifact-upload",
                content_sha256=DIGEST,
                size_bytes=forged.size_bytes,
                now=NOW + timedelta(minutes=1),
            )

    def test_replay_is_refused(self, authority: PresignedGrantAuthority) -> None:
        grant = _issue(authority)
        later = NOW + timedelta(minutes=1)
        authority.consume_upload_grant(
            grant,
            purpose="artifact-upload",
            content_sha256=DIGEST,
            size_bytes=len(PAYLOAD),
            now=later,
        )

        with pytest.raises(PresignedGrantReplayed):
            authority.consume_upload_grant(
                grant,
                purpose="artifact-upload",
                content_sha256=DIGEST,
                size_bytes=len(PAYLOAD),
                now=later,
            )
