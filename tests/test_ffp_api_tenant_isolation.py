from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import AccessCapabilities
from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
)
from techflex_cloud_foundation.contracts.cloud import (
    TestProtocol as ProtocolContract,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.access_auth import TenantAccessTokenIssuer
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore


class TenantAccessIsolationApiTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC)
        self.left_tenant = uuid4()
        self.right_tenant = uuid4()
        self.left_installation = uuid4()
        self.left_replacement_installation = uuid4()
        self.right_installation = uuid4()
        self.site_id = uuid4()
        self.right_site_id = uuid4()
        self.device_id = uuid4()
        self.right_device_id = uuid4()
        self.subject_id = uuid4()
        self.right_subject_id = uuid4()
        self.consent_id = uuid4()
        self.right_consent_id = uuid4()
        self.session_id = uuid4()
        repository = InMemoryPlatformRepository()
        repository.add_terminal(
            self.left_tenant,
            self.site_id,
            self.left_installation,
        )
        repository.add_terminal(
            self.right_tenant,
            self.right_site_id,
            self.right_installation,
        )
        repository.add_terminal(
            self.left_tenant,
            self.site_id,
            self.left_replacement_installation,
        )
        repository.add_device(self.left_tenant, self.device_id, "DO-P4864")
        repository.add_device(self.right_tenant, self.right_device_id, "DO-P4864")
        repository.add_subject(self.left_tenant, self.subject_id)
        repository.add_subject(self.right_tenant, self.right_subject_id)
        repository.add_consent(
            self.left_tenant,
            self.subject_id,
            self.consent_id,
            self.now,
        )
        repository.add_consent(
            self.right_tenant,
            self.right_subject_id,
            self.right_consent_id,
            self.now,
        )
        issuer = TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes",
            key_id="tenant/1",
        )
        capabilities = AccessCapabilities(
            allow_new_test=True,
            allow_upload=True,
            allow_report_view=True,
        )
        self.left_token = issuer.issue(
            tenant_id=self.left_tenant,
            account_id=uuid4(),
            license_id=uuid4(),
            hardware_id="usb-serial-left0000000000000001",
            client_installation_id=self.left_installation,
            token_version=1,
            capabilities=capabilities,
            now=self.now,
        )
        self.right_token = issuer.issue(
            tenant_id=self.right_tenant,
            account_id=uuid4(),
            license_id=uuid4(),
            hardware_id="usb-serial-right000000000000001",
            client_installation_id=self.right_installation,
            token_version=1,
            capabilities=capabilities,
            now=self.now,
        )
        self.left_replacement_token = issuer.issue(
            tenant_id=self.left_tenant,
            account_id=uuid4(),
            license_id=uuid4(),
            hardware_id="usb-serial-left0000000000000001",
            client_installation_id=self.left_replacement_installation,
            token_version=1,
            capabilities=capabilities,
            now=self.now,
        )
        ingestion = IngestionService(
            repository,
            SegmentObjectStore(InMemoryObjectStore()),
            supported_payload_schemas={"raw-segment/1"},
            supported_manifest_schemas={"session-manifest/1"},
        )
        app = create_app(
            ServiceContainer(ingestion=ingestion, tenant_tokens=issuer)
        )
        self.client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://cloud.test",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    def headers(self, token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "X-Correlation-ID": str(uuid4()),
        }

    def session_request(self, **updates) -> SessionCreateRequest:
        values = {
            "session_id": self.session_id,
            "subject_uuid": self.subject_id,
            "consent_record_id": self.consent_id,
            "site_id": self.site_id,
            "terminal_id": self.left_installation,
            "client_installation_id": self.left_installation,
            "device_id": self.device_id,
            "test_protocol": ProtocolContract(id="standard-screening", version="1.0"),
            "versions": SessionVersions(
                app="0.1.0",
                protocol_profile="do-p4864/1",
                payload_schema="raw-segment/1",
                calibration="calibration/1",
            ),
            "started_at": self.now,
        }
        values.update(updates)
        return SessionCreateRequest(**values)

    def segment_contracts(self, payload: bytes) -> tuple[SegmentMetadata, SessionManifest]:
        metadata = SegmentMetadata(
            segment_index=0,
            start_frame_index=0,
            frame_count=10,
            start_monotonic_ns=100,
            end_monotonic_ns=200,
            compression="zstd",
            cipher="aes-256-gcm",
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            payload_schema_version="raw-segment/1",
        )
        manifest = SessionManifest(
            segment_count=1,
            total_frames=metadata.frame_count,
            total_bytes=metadata.size_bytes,
            segments=(
                ManifestSegment(
                    index=metadata.segment_index,
                    sha256=metadata.sha256,
                    size_bytes=metadata.size_bytes,
                    frame_count=metadata.frame_count,
                ),
            ),
            ended_at=self.now,
            local_quality_outcome="VALID",
        )
        return metadata, manifest

    def segment_headers(self, token: str, metadata: SegmentMetadata) -> dict[str, str]:
        headers = self.headers(token)
        headers.update(
            {
                "X-Content-SHA256": metadata.sha256,
                "X-Schema-Version": metadata.payload_schema_version,
                "X-Segment-Metadata": encode_segment_metadata(metadata),
                "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream",
            }
        )
        return headers

    def completion_headers(self, token: str, manifest: SessionManifest) -> dict[str, str]:
        headers = self.headers(token)
        headers.update(
            {
                "Idempotency-Key": "complete-historical-session",
                "X-Content-SHA256": canonical_sha256(manifest),
                "X-Schema-Version": manifest.schema_version,
            }
        )
        return headers

    async def test_right_tenant_cannot_read_left_tenant_session(self) -> None:
        request = self.session_request()
        left_headers = self.headers(self.left_token)
        left_headers["Idempotency-Key"] = "left-session"
        created = await self.client.post(
            "/v1/sessions",
            headers=left_headers,
            json=request.model_dump(mode="json"),
        )
        self.assertEqual(created.status_code, 201, created.text)

        payload = b"left tenant captured segment"
        metadata, manifest = self.segment_contracts(payload)
        denied_put = await self.client.put(
            f"/v1/sessions/{self.session_id}/segments/0",
            headers=self.segment_headers(self.right_token, metadata),
            content=payload,
        )
        denied_list = await self.client.get(
            f"/v1/sessions/{self.session_id}/segments",
            headers=self.headers(self.right_token),
        )
        denied_complete = await self.client.post(
            f"/v1/sessions/{self.session_id}/complete",
            headers=self.completion_headers(self.right_token, manifest),
            json=manifest.model_dump(mode="json"),
        )
        denied_status = await self.client.get(
            f"/v1/sessions/{self.session_id}/status",
            headers=self.headers(self.right_token),
        )

        for response in (denied_put, denied_list, denied_complete, denied_status):
            self.assertEqual(response.status_code, 403, response.text)
            self.assertNotIn(self.left_token, response.text)
            self.assertNotIn(self.right_token, response.text)

    async def test_replacement_installation_can_read_its_tenants_session_status(
        self,
    ) -> None:
        request = self.session_request()
        create_headers = self.headers(self.left_token)
        create_headers["Idempotency-Key"] = "replacement-readable-session"
        created = await self.client.post(
            "/v1/sessions",
            headers=create_headers,
            json=request.model_dump(mode="json"),
        )
        self.assertEqual(created.status_code, 201, created.text)

        status = await self.client.get(
            f"/v1/sessions/{self.session_id}/status",
            headers=self.headers(self.left_replacement_token),
        )

        self.assertEqual(status.status_code, 200, status.text)
        self.assertEqual(status.json()["data"]["session_id"], str(self.session_id))

    async def test_replacement_principal_can_resume_historical_capture_to_completion(
        self,
    ) -> None:
        headers = self.headers(self.left_replacement_token)
        headers["Idempotency-Key"] = "historical-capture-session"

        created = await self.client.post(
            "/v1/sessions",
            headers=headers,
            json=self.session_request().model_dump(mode="json"),
        )

        self.assertEqual(created.status_code, 201, created.text)

        payload = b"captured by historical installation"
        metadata, manifest = self.segment_contracts(payload)
        uploaded = await self.client.put(
            f"/v1/sessions/{self.session_id}/segments/0",
            headers=self.segment_headers(self.left_replacement_token, metadata),
            content=payload,
        )
        listed = await self.client.get(
            f"/v1/sessions/{self.session_id}/segments",
            headers=self.headers(self.left_replacement_token),
        )
        completed = await self.client.post(
            f"/v1/sessions/{self.session_id}/complete",
            headers=self.completion_headers(self.left_replacement_token, manifest),
            json=manifest.model_dump(mode="json"),
        )
        status = await self.client.get(
            f"/v1/sessions/{self.session_id}/status",
            headers=self.headers(self.left_replacement_token),
        )

        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(completed.status_code, 200, completed.text)
        self.assertEqual(status.status_code, 200, status.text)
        self.assertEqual(status.json()["data"]["ingest_status"], "INGESTED")

    async def test_cross_tenant_capture_references_are_denied(self) -> None:
        cases = {
            "installation": {
                "terminal_id": self.right_installation,
                "client_installation_id": self.right_installation,
                "site_id": self.right_site_id,
            },
            "hardware_asset": {"device_id": self.right_device_id},
            "subject": {"subject_uuid": self.right_subject_id},
            "consent": {"consent_record_id": self.right_consent_id},
        }
        for label, updates in cases.items():
            with self.subTest(reference=label):
                headers = self.headers(self.left_token)
                headers["Idempotency-Key"] = f"cross-tenant-{label}"
                request = self.session_request(session_id=uuid4(), **updates)

                response = await self.client.post(
                    "/v1/sessions",
                    headers=headers,
                    json=request.model_dump(mode="json"),
                )

                self.assertEqual(response.status_code, 403, response.text)


if __name__ == "__main__":
    unittest.main()
