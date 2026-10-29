from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import unittest
from uuid import uuid4

from techflex_cloud_foundation.contracts.cloud import (
    SegmentMetadata,
    SessionCreateRequest,
    SessionVersions,
    TestProtocol,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import (
    DigestMismatch,
    SchemaUnsupported,
    SegmentDigestConflict,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore


async def chunks(value: bytes, size: int = 7):
    for offset in range(0, len(value), size):
        yield value[offset : offset + size]


class SegmentIngestionTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tenant_id = uuid4()
        self.other_tenant_id = uuid4()
        self.site_id = uuid4()
        self.terminal_id = uuid4()
        self.other_terminal_id = uuid4()
        self.device_id = uuid4()
        self.subject_uuid = uuid4()
        self.consent_id = uuid4()
        self.session_id = uuid4()
        self.context = TerminalContext(
            tenant_id=self.tenant_id,
            terminal_id=self.terminal_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        self.other_context = TerminalContext(
            tenant_id=self.other_tenant_id,
            terminal_id=self.other_terminal_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        self.repository = InMemoryPlatformRepository()
        self.repository.add_terminal(self.tenant_id, self.site_id, self.terminal_id)
        self.repository.add_terminal(self.other_tenant_id, uuid4(), self.other_terminal_id)
        self.repository.add_device(self.tenant_id, self.device_id, model="DO-P4864")
        self.repository.add_subject(self.tenant_id, self.subject_uuid)
        self.repository.add_consent(
            self.tenant_id,
            self.subject_uuid,
            self.consent_id,
            granted_at=datetime.now(UTC),
        )
        self.objects = InMemoryObjectStore()
        self.service = IngestionService(
            repository=self.repository,
            object_store=SegmentObjectStore(self.objects),
            supported_payload_schemas={"raw-segment/1"},
            supported_manifest_schemas={"session-manifest/1"},
        )
        self.request = SessionCreateRequest(
            session_id=self.session_id,
            subject_uuid=self.subject_uuid,
            consent_record_id=self.consent_id,
            site_id=self.site_id,
            terminal_id=self.terminal_id,
            client_installation_id=self.terminal_id,
            device_id=self.device_id,
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
        await self.service.create_session(self.context, self.request, "create-session")

    def metadata(self, payload: bytes, *, index: int = 0, sha256: str | None = None) -> SegmentMetadata:
        return SegmentMetadata(
            segment_index=index,
            start_frame_index=index * 10,
            frame_count=10,
            start_monotonic_ns=100 + index * 100,
            end_monotonic_ns=199 + index * 100,
            compression="zstd",
            cipher="aes-256-gcm",
            size_bytes=len(payload),
            sha256=sha256 or hashlib.sha256(payload).hexdigest(),
            payload_schema_version="raw-segment/1",
        )

    async def test_same_index_same_digest_is_idempotent(self) -> None:
        payload = b"accepted immutable encrypted segment"
        metadata = self.metadata(payload)

        first = await self.service.put_segment(
            self.context, self.session_id, 0, metadata, chunks(payload)
        )
        second = await self.service.put_segment(
            self.context, self.session_id, 0, metadata, chunks(payload)
        )

        self.assertEqual(first.object_key, second.object_key)
        self.assertFalse(first.idempotent_replay)
        self.assertTrue(second.idempotent_replay)
        self.assertEqual(self.objects.object_count, 1)

    async def test_upload_denial_also_blocks_existing_segment_replay(self) -> None:
        payload = b"immutable segment accepted before upload was disabled"
        metadata = self.metadata(payload)
        accepted = await self.service.put_segment(
            self.context, self.session_id, 0, metadata, chunks(payload)
        )
        denied = IngestionPrincipal(
            tenant_id=self.tenant_id,
            terminal_id=self.terminal_id,
            expires_at=self.context.expires_at,
            allow_new_test=True,
            allow_upload=False,
        )

        # Even a byte-identical retry must pass the current upload gate before
        # returning the stored acknowledgement; grant/session history cannot
        # turn upload revocation into an idempotent success.
        with self.assertRaises(TenantAccessDenied):
            await self.service.put_segment(
                denied, self.session_id, 0, metadata, chunks(payload)
            )

        self.assertEqual(await self.objects.read(accepted.object_key), payload)
        self.assertEqual(self.objects.object_count, 1)

    async def test_revocation_blocks_new_sessions_but_allows_existing_session_upload(self) -> None:
        self.repository.set_terminal_status(
            self.tenant_id,
            self.terminal_id,
            "REVOKED",
        )
        payload = b"sealed before terminal revocation"

        acknowledgement = await self.service.put_segment(
            self.context,
            self.session_id,
            0,
            self.metadata(payload),
            chunks(payload),
        )

        self.assertEqual(acknowledgement.status.value, "ACKNOWLEDGED")
        with self.assertRaises(TenantAccessDenied):
            await self.service.create_session(
                self.context,
                self.request.model_copy(update={"session_id": uuid4()}),
                "create-after-revocation",
            )

    async def test_same_index_different_digest_conflicts_without_overwrite(self) -> None:
        original = b"original encrypted segment"
        replacement = b"different encrypted segment"
        first = await self.service.put_segment(
            self.context, self.session_id, 0, self.metadata(original), chunks(original)
        )

        with self.assertRaises(SegmentDigestConflict):
            await self.service.put_segment(
                self.context,
                self.session_id,
                0,
                self.metadata(replacement),
                chunks(replacement),
            )

        self.assertEqual(await self.objects.read(first.object_key), original)
        self.assertEqual(self.objects.object_count, 1)
        self.assertEqual(self.repository.problem_types(self.tenant_id, self.session_id), ["CONTENT_CONFLICT"])

    async def test_digest_mismatch_never_creates_object_or_database_reference(self) -> None:
        payload = b"payload"
        metadata = self.metadata(payload, sha256="0" * 64)

        with self.assertRaises(DigestMismatch):
            await self.service.put_segment(
                self.context, self.session_id, 0, metadata, chunks(payload)
            )

        self.assertEqual(self.objects.object_count, 0)
        self.assertEqual(await self.repository.list_segments(self.context, self.session_id), ())

    async def test_schema_version_must_match_supported_session_contract(self) -> None:
        payload = b"payload"
        metadata = self.metadata(payload).model_copy(
            update={"payload_schema_version": "raw-segment/2"}
        )

        with self.assertRaises(SchemaUnsupported):
            await self.service.put_segment(
                self.context, self.session_id, 0, metadata, chunks(payload)
            )

    async def test_cross_tenant_session_access_is_denied(self) -> None:
        with self.assertRaises(TenantAccessDenied):
            await self.service.list_segments(self.other_context, self.session_id)

    async def test_route_index_must_equal_signed_metadata_index(self) -> None:
        payload = b"payload"
        with self.assertRaises(ValueError):
            await self.service.put_segment(
                self.context,
                self.session_id,
                1,
                self.metadata(payload, index=0),
                chunks(payload),
            )

    async def test_database_failure_compensates_unreferenced_object(self) -> None:
        payload = b"object written before database failure"
        metadata = self.metadata(payload)

        async def fail_registration(*args, **kwargs):
            raise RuntimeError("injected database failure")

        self.repository.register_segment = fail_registration

        with self.assertRaisesRegex(RuntimeError, "injected database failure"):
            await self.service.put_segment(
                self.context, self.session_id, 0, metadata, chunks(payload)
            )

        self.assertEqual(self.objects.object_count, 0)
        self.assertEqual(await self.repository.list_segments(self.context, self.session_id), ())

    async def test_database_race_digest_conflict_records_problem_and_cleans_object(self) -> None:
        payload = b"racing conflicting payload"
        metadata = self.metadata(payload)

        async def conflict_registration(*args, **kwargs):
            raise SegmentDigestConflict("injected concurrent conflict")

        self.repository.register_segment = conflict_registration

        with self.assertRaises(SegmentDigestConflict):
            await self.service.put_segment(
                self.context, self.session_id, 0, metadata, chunks(payload)
            )

        self.assertEqual(self.objects.object_count, 0)
        self.assertEqual(
            self.repository.problem_types(self.tenant_id, self.session_id),
            ["CONTENT_CONFLICT"],
        )


if __name__ == "__main__":
    unittest.main()
