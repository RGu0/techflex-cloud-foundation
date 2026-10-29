from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ExternalIdentifierInput,
    ManifestSegment,
    ProfileValue,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    SubjectCreateRequest,
    TestProtocol,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)


class IngestionApiContractTests(unittest.IsolatedAsyncioTestCase):
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
        self.repository = InMemoryPlatformRepository()
        self.repository.add_terminal(self.tenant_id, self.site_id, self.terminal_id)
        self.repository.add_terminal(self.other_tenant_id, uuid4(), self.other_terminal_id)
        self.repository.add_device(self.tenant_id, self.device_id, "DO-P4864")
        self.repository.add_subject(self.tenant_id, self.subject_uuid)
        self.repository.add_consent(
            self.tenant_id, self.subject_uuid, self.consent_id, datetime.now(UTC)
        )
        self.objects = InMemoryObjectStore()
        self.ingestion = IngestionService(
            self.repository,
            SegmentObjectStore(self.objects),
            supported_payload_schemas={"raw-segment/1"},
            supported_manifest_schemas={"session-manifest/1"},
        )
        self.issuer = TerminalTokenIssuer(
            secret=b"test-only-server-secret-at-least-32-bytes",
            key_id="test-key",
            token_ttl=timedelta(minutes=10),
        )
        self.subjects = SubjectConsentService(
            self.repository,
            IdentityProtector(
                encryption_key=b"e" * 32,
                lookup_hmac_key=b"h" * 32,
                key_version="identity/1",
            ),
        )
        app = create_app(
            ServiceContainer(
                ingestion=self.ingestion,
                token_issuer=self.issuer,
                subjects=self.subjects,
            )
        )
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")
        self.token = self.issuer.issue(self.tenant_id, self.terminal_id)
        self.other_token = self.issuer.issue(self.other_tenant_id, self.other_terminal_id)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    def headers(self, *, token: str | None = None, terminal_id=None) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token or self.token}",
            "X-Terminal-ID": str(terminal_id or self.terminal_id),
            "X-Correlation-ID": str(uuid4()),
        }

    def session_request(self) -> SessionCreateRequest:
        return SessionCreateRequest(
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
        )

    def test_session_contract_requires_explicit_matching_installation_identity(self) -> None:
        request = self.session_request()

        self.assertEqual(request.client_installation_id, self.terminal_id)

        with self.assertRaisesRegex(
            ValidationError,
            "client installation must match legacy terminal id",
        ):
            SessionCreateRequest(
                **{
                    **request.model_dump(),
                    "client_installation_id": uuid4(),
                }
            )

    def metadata(self, payload: bytes, index: int) -> SegmentMetadata:
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

    async def create_session(self) -> None:
        headers = self.headers()
        headers["Idempotency-Key"] = "create-session"
        response = await self.client.post(
            "/v1/sessions",
            headers=headers,
            json=self.session_request().model_dump(mode="json"),
        )
        self.assertEqual(response.status_code, 201, response.text)

    async def upload(self, index: int, payload: bytes):
        metadata = self.metadata(payload, index)
        headers = self.headers()
        headers.update(
            {
                "X-Content-SHA256": metadata.sha256,
                "X-Schema-Version": metadata.payload_schema_version,
                "X-Segment-Metadata": encode_segment_metadata(metadata),
                "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream",
            }
        )
        return await self.client.put(
            f"/v1/sessions/{self.session_id}/segments/{index}",
            headers=headers,
            content=payload,
        )

    async def test_session_create_replay_and_segment_conflict_contract(self) -> None:
        request = self.session_request()
        headers = self.headers()
        headers["Idempotency-Key"] = "create-session"
        first = await self.client.post(
            "/v1/sessions", headers=headers, json=request.model_dump(mode="json")
        )
        second = await self.client.post(
            "/v1/sessions", headers=headers, json=request.model_dump(mode="json")
        )
        self.assertEqual(first.status_code, 201)
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()["data"]["idempotent_replay"])

        accepted = await self.upload(0, b"accepted segment")
        conflict = await self.upload(0, b"different segment")

        self.assertEqual(accepted.status_code, 201)
        self.assertEqual(conflict.status_code, 409)
        self.assertEqual(conflict.json()["error"]["code"], "E-SYN-409")
        self.assertNotIn("accepted segment", conflict.text)
        self.assertNotIn(self.token, conflict.text)

    async def test_missing_query_and_manifest_gate(self) -> None:
        await self.create_session()
        payloads = (b"segment zero", b"segment one")
        self.assertEqual((await self.upload(0, payloads[0])).status_code, 201)
        query = await self.client.get(
            f"/v1/sessions/{self.session_id}/segments", headers=self.headers()
        )
        self.assertEqual(query.status_code, 200)
        self.assertEqual(query.json()["data"]["received"][0]["index"], 0)

        metadata = tuple(self.metadata(payload, index) for index, payload in enumerate(payloads))
        manifest = SessionManifest(
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
            local_quality_outcome="VALID",
        )
        complete_headers = self.headers()
        complete_headers.update(
            {
                "Idempotency-Key": "complete-session",
                "X-Content-SHA256": canonical_sha256(manifest),
                "X-Schema-Version": manifest.schema_version,
            }
        )
        incomplete = await self.client.post(
            f"/v1/sessions/{self.session_id}/complete",
            headers=complete_headers,
            json=manifest.model_dump(mode="json"),
        )
        self.assertEqual(incomplete.status_code, 422)
        self.assertEqual(self.repository.events("session.ingested.v1"), ())
        missing_after_manifest = await self.client.get(
            f"/v1/sessions/{self.session_id}/segments", headers=self.headers()
        )
        self.assertEqual(missing_after_manifest.json()["data"]["missing"], [1])

        self.assertEqual((await self.upload(1, payloads[1])).status_code, 201)
        complete = await self.client.post(
            f"/v1/sessions/{self.session_id}/complete",
            headers=complete_headers,
            json=manifest.model_dump(mode="json"),
        )
        self.assertEqual(complete.status_code, 200, complete.text)
        self.assertEqual(len(self.repository.events("session.ingested.v1")), 1)

    async def test_terminal_header_mismatch_and_cross_tenant_access_are_denied(self) -> None:
        mismatch = await self.client.get(
            f"/v1/sessions/{self.session_id}/status",
            headers=self.headers(terminal_id=uuid4()),
        )
        self.assertEqual(mismatch.status_code, 403)

        await self.create_session()
        other_headers = self.headers(
            token=self.other_token, terminal_id=self.other_terminal_id
        )
        cross_tenant = await self.client.get(
            f"/v1/sessions/{self.session_id}/status", headers=other_headers
        )
        self.assertEqual(cross_tenant.status_code, 403)

    async def test_subject_resolution_and_consent_lifecycle_contract(self) -> None:
        subject_id = uuid4()
        external = ExternalIdentifierInput(
            issuer="site-main",
            id_type="medical_record_number",
            external_id="A-123456",
        )
        subject = SubjectCreateRequest(
            subject_uuid=subject_id,
            external_identifier=external,
            analysis_profile={
                "height_cm": ProfileValue(state="PROVIDED", value=168.0),
                "condition_tags": ProfileValue(state="UNKNOWN", value=None),
            },
        )
        create_headers = self.headers()
        create_headers["Idempotency-Key"] = "create-subject"
        created = await self.client.post(
            "/v1/subjects",
            headers=create_headers,
            json=subject.model_dump(mode="json"),
        )
        self.assertEqual(created.status_code, 201, created.text)
        self.assertEqual(created.json()["data"]["subject_uuid"], str(subject_id))
        self.assertNotIn(external.external_id, created.text)

        resolved = await self.client.post(
            "/v1/subjects/resolve",
            headers=self.headers(),
            json={
                "issuer": external.issuer,
                "id_type": external.id_type,
                "external_id": " a-123456 ",
            },
        )
        self.assertEqual(resolved.status_code, 200)
        self.assertEqual(resolved.json()["data"]["subject_uuid"], str(subject_id))

        consent = ConsentCreateRequest(
            consent_record_id=uuid4(),
            subject_uuid=subject_id,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW",),
            granted_at=datetime.now(UTC),
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-terminal-evidence",
        )
        consent_headers = self.headers()
        consent_headers["Idempotency-Key"] = "create-consent"
        granted = await self.client.post(
            "/v1/consents",
            headers=consent_headers,
            json=consent.model_dump(mode="json"),
        )
        self.assertEqual(granted.status_code, 201, granted.text)

        revoke_headers = self.headers()
        revoke_headers["Idempotency-Key"] = "revoke-consent"
        revoked = await self.client.post(
            f"/v1/consents/{consent.consent_record_id}/revoke",
            headers=revoke_headers,
            json={
                "revoked_at": datetime.now(UTC).isoformat(),
                "reason_code": "SUBJECT_WITHDRAWN",
            },
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assertIsNotNone(revoked.json()["data"]["revoked_at"])


if __name__ == "__main__":
    unittest.main()
