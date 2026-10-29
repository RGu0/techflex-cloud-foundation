from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import unittest
from uuid import uuid4

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    TestProtocol,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import (
    ManifestConflict,
    ManifestIncomplete,
    QualityGateRejected,
)
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore


async def one_chunk(payload: bytes):
    yield payload


class ManifestOutboxTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tenant_id = uuid4()
        self.site_id = uuid4()
        self.terminal_id = uuid4()
        self.device_id = uuid4()
        self.subject_uuid = uuid4()
        self.consent_id = uuid4()
        self.session_id = uuid4()
        self.context = TerminalContext(
            tenant_id=self.tenant_id,
            terminal_id=self.terminal_id,
            expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        self.repository = InMemoryPlatformRepository()
        self.repository.add_terminal(self.tenant_id, self.site_id, self.terminal_id)
        self.repository.add_device(self.tenant_id, self.device_id, model="DO-P4864")
        self.repository.add_subject(self.tenant_id, self.subject_uuid)
        self.repository.add_consent(
            self.tenant_id, self.subject_uuid, self.consent_id, datetime.now(UTC)
        )
        self.objects = InMemoryObjectStore()
        self.service = IngestionService(
            self.repository,
            SegmentObjectStore(self.objects),
            supported_payload_schemas={"raw-segment/1"},
            supported_manifest_schemas={"session-manifest/1"},
        )
        await self.service.create_session(
            self.context,
            SessionCreateRequest(
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
            ),
            "create-session",
        )
        self.payloads = (b"segment-zero", b"segment-one")

    def metadata(self, index: int) -> SegmentMetadata:
        payload = self.payloads[index]
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

    def manifest(self, quality: str = "VALID") -> SessionManifest:
        metadata = (self.metadata(0), self.metadata(1))
        return SessionManifest(
            segment_count=2,
            total_frames=20,
            total_bytes=sum(item.size_bytes for item in metadata),
            segments=tuple(
                ManifestSegment(
                    index=item.segment_index,
                    sha256=item.sha256,
                    size_bytes=item.size_bytes,
                    frame_count=item.frame_count,
                )
                for item in metadata
            ),
            ended_at=datetime.now(UTC),
            local_quality_outcome=quality,
            schema_version="session-manifest/1",
        )

    async def upload(self, index: int) -> None:
        await self.service.put_segment(
            self.context,
            self.session_id,
            index,
            self.metadata(index),
            one_chunk(self.payloads[index]),
        )

    async def test_missing_segment_never_emits_ingested_event(self) -> None:
        await self.upload(0)
        manifest = self.manifest()

        with self.assertRaises(ManifestIncomplete):
            await self.service.complete_session(
                self.context,
                self.session_id,
                manifest,
                canonical_sha256(manifest),
                "complete-session",
            )

        self.assertEqual(self.repository.events("session.ingested.v1"), ())
        status = await self.service.get_status(self.context, self.session_id)
        self.assertNotEqual(status.ingest_status, "INGESTED")
        segments = await self.service.list_segments(self.context, self.session_id)
        self.assertEqual(segments.missing, (1,))

    async def test_verified_manifest_emits_one_event_under_idempotent_replay(self) -> None:
        await self.upload(0)
        await self.upload(1)
        manifest = self.manifest()
        digest = canonical_sha256(manifest)

        first = await self.service.complete_session(
            self.context, self.session_id, manifest, digest, "complete-session"
        )
        second = await self.service.complete_session(
            self.context, self.session_id, manifest, digest, "complete-session"
        )

        self.assertEqual(first.manifest_sha256, second.manifest_sha256)
        self.assertFalse(first.idempotent_replay)
        self.assertTrue(second.idempotent_replay)
        self.assertEqual(len(self.repository.events("session.ingested.v1")), 1)
        self.assertEqual((await self.service.get_status(self.context, self.session_id)).ingest_status, "INGESTED")

    async def test_completion_receipt_fields_replay_identically(self) -> None:
        await self.upload(0)
        await self.upload(1)
        manifest = self.manifest()
        digest = canonical_sha256(manifest)

        first = await self.service.complete_session(
            self.context, self.session_id, manifest, digest, "complete-session"
        )
        second = await self.service.complete_session(
            self.context, self.session_id, manifest, digest, "complete-session"
        )

        # CP-06 receipt facts are recorded at completion and replayed
        # identically, so the canonical receipt digest is re-derivable.
        self.assertEqual(first.manifest_object_key, second.manifest_object_key)
        self.assertTrue(first.manifest_object_key)
        self.assertEqual(first.eligibility_reason, second.eligibility_reason)
        self.assertIn("can_upload", first.eligibility_reason)
        self.assertEqual(
            first.eligibility_policy_version, "seed-completion-eligibility/1"
        )
        self.assertEqual(
            first.eligibility_policy_version, second.eligibility_policy_version
        )
        self.assertEqual(first.completed_at, second.completed_at)

    async def test_different_manifest_digest_conflicts_without_second_event(self) -> None:
        await self.upload(0)
        await self.upload(1)
        first = self.manifest()
        await self.service.complete_session(
            self.context,
            self.session_id,
            first,
            canonical_sha256(first),
            "complete-session",
        )
        changed = first.model_copy(update={"ended_at": first.ended_at + timedelta(seconds=1)})

        with self.assertRaises(ManifestConflict):
            await self.service.complete_session(
                self.context,
                self.session_id,
                changed,
                canonical_sha256(changed),
                "complete-session-2",
            )

        self.assertEqual(len(self.repository.events("session.ingested.v1")), 1)

    async def test_invalid_quality_never_emits_formal_analysis_event(self) -> None:
        await self.upload(0)
        await self.upload(1)
        manifest = self.manifest(quality="INVALID")

        with self.assertRaises(QualityGateRejected):
            await self.service.complete_session(
                self.context,
                self.session_id,
                manifest,
                canonical_sha256(manifest),
                "complete-invalid",
            )

        self.assertEqual(self.repository.events("session.ingested.v1"), ())


if __name__ == "__main__":
    unittest.main()
