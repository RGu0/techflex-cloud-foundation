from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import unittest
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient
from pydantic import SecretStr

from techflex_cloud_foundation.contracts.access_control import (
    ActivateAccountRequest,
    HardwareLeaseRequest,
    LicenseControlAction,
    LicenseControlRequest,
    PlatformRole,
    ProvisionTenantRequest,
    RefreshRequest,
)
from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ExternalIdentifierInput,
    HeartbeatDevice,
    HeartbeatHealth,
    HeartbeatRequest,
    HeartbeatSync,
    ManifestSegment,
    MissingValueState,
    ProfileValue,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    SubjectCreateRequest,
)
from techflex_cloud_foundation.contracts.cloud import (
    TestProtocol as ProtocolContract,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
)
from techflex_cloud_foundation.server.access_control.capture_grants import CaptureGrantService
from techflex_cloud_foundation.server.access_control.lease_service import HardwareLeaseService
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationService,
)
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.device_management.service import DeviceManagementService
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)


class TenantAccessIngestionTests(unittest.IsolatedAsyncioTestCase):
    def altered_token(self, **changes):
        fields = dict(tenant_id=self.provisioned.tenant_id, account_id=self.session.account_id,
                      license_id=self.session.license_id, hardware_id=self.session.hardware_id,
                      client_installation_id=self.installation_id, token_version=1,
                      capabilities=self.session.capabilities.model_copy(update={"allow_new_test": False}), now=self.now)
        fields.update(changes)
        return self.tenant_tokens.issue(**fields)

    async def test_authorization_rejects_wrong_identity_token_and_bound_request(self):
        refreshed, authorization = await self.suspended_grant()
        original = self.session_request(authorization.session_id)
        for token, request, auth in (
            (self.altered_token(tenant_id=uuid4()), original, authorization),
            (self.altered_token(account_id=uuid4()), original, authorization),
            (self.altered_token(client_installation_id=uuid4()), original, authorization),
            (refreshed.access_token, original.model_copy(update={"device_id": uuid4()}), authorization),
            (refreshed.access_token, original.model_copy(update={"session_id": uuid4()}), authorization),
            (refreshed.access_token, original, authorization.model_copy(update={"token": SecretStr("wrong-token-value-at-least-20")})),
        ):
            response = await self.client.post("/v1/sessions", headers={**self.headers(token), "Idempotency-Key": str(uuid4()), **auth.headers()}, json=request.model_dump(mode="json"))
            self.assertEqual(response.status_code, 403, response.text)
            self.assertEqual(len(self.data_repository._sessions), 0)
        key = (self.provisioned.tenant_id, authorization.session_id)
        self.assertEqual(self.data_repository._capture_grants[key].state, "ISSUED")
        self.data_repository._capture_grants[key] = replace(self.data_repository._capture_grants[key], state="RETIRED")
        response = await self.client.post("/v1/sessions", headers={**self.headers(refreshed.access_token), "Idempotency-Key": "retired", **authorization.headers()}, json=original.model_dump(mode="json"))
        self.assertEqual(response.status_code, 403, response.text)
        self.assertFalse(self.data_repository._sessions)

    async def test_historical_grant_survives_delay_and_replacement_entitlement(self):
        _, authorization = await self.suspended_grant()
        key = (self.provisioned.tenant_id, authorization.session_id)
        historical = replace(self.data_repository._capture_grants[key], issued_at=self.now - timedelta(days=60))
        self.data_repository._capture_grants[key] = historical
        token = self.altered_token(license_id=uuid4(), hardware_id="usb-serial-replacement-0123456789")
        headers = {**self.headers(token), "Idempotency-Key": "historical", **authorization.headers()}
        request = self.session_request(authorization.session_id)
        response = await self.client.post("/v1/sessions", headers=headers, json=request.model_dump(mode="json"))
        self.assertEqual(response.status_code, 201, response.text)
        consumed = self.data_repository._capture_grants[key]
        self.assertEqual((consumed.hardware_id, consumed.license_id), (historical.hardware_id, historical.license_id))
        changed = request.model_copy(update={"config_snapshot": {"changed": True}})
        response = await self.client.post("/v1/sessions", headers=headers, json=changed.model_dump(mode="json"))
        self.assertEqual(response.status_code, 409, response.text)

    async def test_allow_upload_false_denies_every_resume_endpoint(self):
        refreshed, authorization = await self.suspended_grant()
        request = self.session_request(authorization.session_id)
        response = await self.client.post("/v1/sessions", headers={**self.headers(refreshed.access_token), "Idempotency-Key": "first", **authorization.headers()}, json=request.model_dump(mode="json"))
        self.assertEqual(response.status_code, 201, response.text)
        token = self.altered_token(capabilities=self.session.capabilities.model_copy(update={"allow_upload": False, "allow_new_test": True}))
        headers = {**self.headers(token), "Idempotency-Key": "denied", **authorization.headers()}
        base = f"/v1/sessions/{request.session_id}"
        manifest = SessionManifest(segment_count=1, total_frames=1, total_bytes=1, segments=(ManifestSegment(index=0, sha256="b" * 64, size_bytes=1, frame_count=1),), ended_at=self.now, local_quality_outcome="VALID")
        metadata = SegmentMetadata(segment_index=0, start_frame_index=0, frame_count=1, start_monotonic_ns=0, end_monotonic_ns=1, compression="zstd", cipher="aes-256-gcm", size_bytes=1, sha256=hashlib.sha256(b"x").hexdigest(), payload_schema_version="raw-segment/1")
        responses = [
            await self.client.post("/v1/sessions", headers=headers, json=request.model_dump(mode="json")),
            await self.client.get(base + "/status", headers=headers),
            await self.client.get(base + "/segments", headers=headers),
            await self.client.put(base + "/segments/0", headers={**headers, "X-Content-SHA256": metadata.sha256, "X-Schema-Version": metadata.payload_schema_version, "X-Segment-Metadata": encode_segment_metadata(metadata), "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream"}, content=b"x"),
            await self.client.post(base + "/complete", headers={**headers, "X-Content-SHA256": canonical_sha256(manifest), "X-Schema-Version": manifest.schema_version}, json=manifest.model_dump(mode="json")),
        ]
        for response in responses:
            self.assertEqual(response.status_code, 403, response.text)
        self.assertFalse(self.data_repository._segments)
        self.assertFalse(self.data_repository._manifests)

    async def test_completion_rejects_manifest_different_from_registration(self):
        refreshed, authorization = await self.suspended_grant()
        metadata = SegmentMetadata(segment_index=0, start_frame_index=0, frame_count=1, start_monotonic_ns=0, end_monotonic_ns=1, compression="zstd", cipher="aes-256-gcm", size_bytes=1, sha256=hashlib.sha256(b"x").hexdigest(), payload_schema_version="raw-segment/1")
        expected = SessionManifest(segment_count=1, total_frames=1, total_bytes=1, segments=(ManifestSegment(index=0, sha256=metadata.sha256, size_bytes=1, frame_count=1),), ended_at=self.now, local_quality_outcome="VALID")
        authorization = authorization.model_copy(update={"manifest_sha256": canonical_sha256(expected)})
        request = self.session_request(authorization.session_id)
        response = await self.client.post("/v1/sessions", headers={**self.headers(refreshed.access_token), "Idempotency-Key": "first", **authorization.headers()}, json=request.model_dump(mode="json"))
        self.assertEqual(response.status_code, 201, response.text)
        manifest = SessionManifest(segment_count=1, total_frames=1, total_bytes=1, segments=(ManifestSegment(index=0, sha256="b" * 64, size_bytes=1, frame_count=1),), ended_at=self.now, local_quality_outcome="VALID")
        response = await self.client.post(f"/v1/sessions/{request.session_id}/complete", headers={**self.headers(refreshed.access_token), "Idempotency-Key": "complete", "X-Content-SHA256": canonical_sha256(manifest), "X-Schema-Version": manifest.schema_version}, json=manifest.model_dump(mode="json"))
        self.assertEqual(response.status_code, 409, response.text)
        self.assertFalse(self.data_repository._manifests)
        uploaded = await self.client.put(f"/v1/sessions/{request.session_id}/segments/0", headers={**self.headers(refreshed.access_token), "X-Content-SHA256": metadata.sha256, "X-Schema-Version": metadata.payload_schema_version, "X-Segment-Metadata": encode_segment_metadata(metadata), "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream"}, content=b"x")
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        completed = await self.client.post(f"/v1/sessions/{request.session_id}/complete", headers={**self.headers(refreshed.access_token), "Idempotency-Key": "complete", "X-Content-SHA256": canonical_sha256(expected), "X-Schema-Version": expected.schema_version}, json=expected.model_dump(mode="json"))
        self.assertEqual(completed.status_code, 200, completed.text)

    async def test_migration_permit_consumer_requires_both_prebound_digests(self):
        refreshed, authorization = await self.suspended_grant()
        key = (self.provisioned.tenant_id, authorization.session_id)
        request = self.session_request(authorization.session_id)
        # Issuance/owner review belongs to Task 5; this fixture exercises only
        # the repository's already-approved, immutable permit consumer.
        self.data_repository._migration_permits[key] = replace(
            self.data_repository._capture_grants.pop(key),
            consumed_request_sha256=canonical_sha256(request), expected_manifest_sha256="a" * 64,
            final_subject_uuid=request.subject_uuid, consent_record_id=request.consent_record_id,
            consent_sha256=canonical_sha256(self.consent_request()),
        )
        authorization = authorization.model_copy(update={"kind": "migration_permit"})
        for body, auth in (
            (request.model_copy(update={"config_snapshot": {"changed": True}}), authorization),
            (request, authorization.model_copy(update={"manifest_sha256": "b" * 64})),
        ):
            result = await self.client.post("/v1/sessions", headers={**self.headers(refreshed.access_token), "Idempotency-Key": str(uuid4()), **auth.headers()}, json=body.model_dump(mode="json"))
            self.assertEqual(result.status_code, 403, result.text)
            self.assertFalse(self.data_repository._sessions)
        headers = {**self.headers(refreshed.access_token), "Idempotency-Key": "permit", **authorization.headers()}
        for status in (201, 200):
            result = await self.client.post("/v1/sessions", headers=headers, json=request.model_dump(mode="json"))
            self.assertEqual(result.status_code, status, result.text)
        self.assertEqual(self.data_repository._migration_permits[key].state, "CONSUMED")

    async def suspended_grant(self):
        await self.create_subject_and_consent(self.session.access_token)
        issued = await self.client.post("/v1/access/capture-grants", headers=self.headers(self.session.access_token), json={"count": 1})
        self.assertEqual(issued.status_code, 201, issued.text)
        grant = issued.json()["data"]["grants"][0]
        authorization = SessionAuthorization(session_id=grant["session_id"], kind="grant", token=grant["token"], manifest_sha256="a" * 64)
        await self.platform.control_license(self.operator, self.provisioned.license_id, LicenseControlRequest(action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"))
        refreshed = await self.tenant_access.refresh(RefreshRequest(refresh_token=self.session.refresh_token, client_installation_id=self.installation_id))
        return refreshed, authorization

    async def test_authorized_suspended_registration_and_lost_response_replay(self):
        refreshed, authorization = await self.suspended_grant()
        request = self.session_request(authorization.session_id)
        async def register(key, auth=authorization):
            return await self.client.post("/v1/sessions", headers={**self.headers(refreshed.access_token), "Idempotency-Key": key, **auth.headers()}, json=request.model_dump(mode="json"))
        first, replay = await asyncio.gather(register("first"), register("lost-response"))
        self.assertEqual(sorted([first.status_code, replay.status_code]), [200, 201])
        self.assertEqual(len(self.data_repository._sessions), 1)
        row = self.data_repository._capture_grants[(self.provisioned.tenant_id, request.session_id)]
        self.assertEqual(row.state, "CONSUMED")
        self.assertEqual(row.consumed_request_sha256, canonical_sha256(request))
        self.assertEqual(sum(event[3] == "CONSUMED" for event in self.data_repository._capture_audits), 1)
        changed = await register("different-manifest", authorization.model_copy(update={"manifest_sha256": "b" * 64}))
        self.assertEqual(changed.status_code, 409, changed.text)

    async def test_suspended_existing_bare_session_replays(self):
        await self.create_subject_and_consent(self.session.access_token)
        self.assertEqual((await self.create_session(self.session.access_token, self.session_id)).status_code, 201)
        await self.platform.control_license(self.operator, self.provisioned.license_id, LicenseControlRequest(action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"))
        refreshed = await self.tenant_access.refresh(RefreshRequest(refresh_token=self.session.refresh_token, client_installation_id=self.installation_id))
        replay = await self.create_session(refreshed.access_token, self.session_id)
        self.assertEqual(replay.status_code, 200, replay.text)

    async def test_authorization_headers_are_not_ignored(self):
        await self.create_subject_and_consent(self.session.access_token)
        for headers in ({"X-Capture-Authorization": "grant " + "x" * 32}, {"X-Expected-Manifest-SHA256": "a" * 64}, {"X-Capture-Authorization": "unknown " + "x" * 32, "X-Expected-Manifest-SHA256": "a" * 64}):
            response = await self.client.post("/v1/sessions", headers={**self.headers(self.session.access_token), "Idempotency-Key": str(uuid4()), **headers}, json=self.session_request(uuid4()).model_dump(mode="json"))
            self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(len(self.data_repository._sessions), 0)

    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC)
        self.access_repository = InMemoryAccessRepository()
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        signer = LicenseDocumentSigner(
            private_key=private_key,
            key_id="license/2-key-1",
            public_keys={"license/2-key-1": public_key},
        )
        self.tenant_tokens = TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes",
            key_id="tenant/1",
        )
        self.tenant_access = TenantAuthenticationService(
            self.access_repository,
            login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
            activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
            tenant_tokens=self.tenant_tokens,
            refresh_tokens=RefreshTokenFactory(
                digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
            ),
            license_signer=signer,
            now=lambda: self.now,
        )
        self.platform = PlatformProvisioningService(
            self.access_repository,
            login_lookup_hmac_key=b"login-lookup-key-must-contain-32-bytes",
            activation_hmac_key=b"activation-key-must-contain-at-least-32-bytes",
            license_signer=signer,
            now=lambda: self.now,
        )
        self.operator = PlatformAccessContext(
            platform_identity_id=uuid4(),
            roles=frozenset({PlatformRole.OPERATIONS}),
            token_version=1,
            expires_at=self.now + timedelta(minutes=15),
        )
        self.provisioned = await self.platform.provision_tenant(
            self.operator,
            ProvisionTenantRequest(
                tenant_name="Seed Clinic",
                account_name="seed-clinic",
                hardware_id="usb-serial-0123456789abcdef0123",
                license_period_months=12,
            ),
        )
        self.installation_id = uuid4()
        self.session = await self.tenant_access.activate(
            ActivateAccountRequest(
                account_name=self.provisioned.account_name,
                activation_code=self.provisioned.activation_code,
                password="correct-horse-battery-staple",
                password_confirmation="correct-horse-battery-staple",
                hardware_id=self.provisioned.hardware_id,
                client_installation_id=self.installation_id,
            ),
            source_fingerprint=b"tenant-ingestion-test",
        )

        group = await self.access_repository.access_group_for_license(
            self.provisioned.license_id
        )
        hardware = await self.access_repository.hardware(group.hardware_id)
        self.device_id = hardware.hardware_id
        self.site_id = uuid4()
        self.subject_id = uuid4()
        self.consent_id = uuid4()
        self.session_id = uuid4()
        self.data_repository = InMemoryPlatformRepository(access_repository=self.access_repository)
        # Compatibility/audit records only. License authority remains in the access repository.
        self.data_repository.add_terminal(
            self.provisioned.tenant_id,
            self.site_id,
            self.installation_id,
        )
        self.data_repository.add_device(
            self.provisioned.tenant_id,
            self.device_id,
            hardware.model,
        )
        self.data_repository.bind_terminal_device(
            self.provisioned.tenant_id,
            self.installation_id,
            self.device_id,
            self.now,
        )
        ingestion = IngestionService(
            self.data_repository,
            SegmentObjectStore(InMemoryObjectStore()),
            supported_payload_schemas={"raw-segment/1"},
            supported_manifest_schemas={"session-manifest/1"},
        )
        subjects = SubjectConsentService(
            self.data_repository,
            IdentityProtector(
                encryption_key=b"e" * 32,
                lookup_hmac_key=b"h" * 32,
                key_version="identity/1",
            ),
        )
        devices = DeviceManagementService(
            self.data_repository,
            TerminalTokenIssuer(
                secret=b"legacy-terminal-token-secret-at-least-32-bytes",
                key_id="terminal/legacy-test",
                token_ttl=timedelta(minutes=15),
            ),
            activation_code_hmac_key=b"legacy-activation-key-at-least-32-bytes",
            now=lambda: self.now,
        )
        app = create_app(
            ServiceContainer(
                ingestion=ingestion,
                subjects=subjects,
                devices=devices,
                hardware_leases=HardwareLeaseService(
                    self.access_repository,
                    now=lambda: self.now,
                ),
                tenant_access=self.tenant_access,
                capture_grants=CaptureGrantService(self.data_repository),
                tenant_tokens=self.tenant_tokens,
            )
        )
        self.client = AsyncClient(
            transport=ASGITransport(app=app),
            base_url="https://cloud.test",
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    @staticmethod
    def headers(token: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {token}",
            "X-Correlation-ID": str(uuid4()),
        }

    def session_request(self, session_id: UUID) -> SessionCreateRequest:
        return SessionCreateRequest(
            session_id=session_id,
            subject_uuid=self.subject_id,
            consent_record_id=self.consent_id,
            site_id=self.site_id,
            terminal_id=self.installation_id,
            client_installation_id=self.installation_id,
            device_id=self.device_id,
            test_protocol=ProtocolContract(id="standard-screening", version="1.0"),
            versions=SessionVersions(
                app="0.1.0",
                protocol_profile="do-p4864/1",
                payload_schema="raw-segment/1",
                calibration="calibration/1",
            ),
            started_at=self.now,
        )

    def consent_request(self) -> ConsentCreateRequest:
        return ConsentCreateRequest(
            consent_record_id=self.consent_id,
            subject_uuid=self.subject_id,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW", "ANALYSIS_PROFILE"),
            granted_at=self.now,
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-client-evidence",
        )

    async def create_session(self, token: str, session_id: UUID):
        headers = self.headers(token)
        headers["Idempotency-Key"] = f"create-{session_id}"
        return await self.client.post(
            "/v1/sessions",
            headers=headers,
            json=self.session_request(session_id).model_dump(mode="json"),
        )

    async def create_subject_and_consent(self, token: str) -> None:
        subject_headers = self.headers(token)
        subject_headers["Idempotency-Key"] = "create-seed-subject"
        subject = SubjectCreateRequest(
            subject_uuid=self.subject_id,
            external_identifier=ExternalIdentifierInput(
                issuer="seed-clinic",
                id_type="medical_record_number",
                external_id="SEED-001",
            ),
            analysis_profile={
                "height_cm": ProfileValue(
                    state=MissingValueState.PROVIDED,
                    value=168.0,
                )
            },
        )
        created = await self.client.post(
            "/v1/subjects",
            headers=subject_headers,
            json=subject.model_dump(mode="json"),
        )
        self.assertEqual(created.status_code, 201, created.text)

        consent_headers = self.headers(token)
        consent_headers["Idempotency-Key"] = "create-seed-consent"
        consent = self.consent_request()
        granted = await self.client.post(
            "/v1/consents",
            headers=consent_headers,
            json=consent.model_dump(mode="json"),
        )
        self.assertEqual(granted.status_code, 201, granted.text)

    async def test_suspension_blocks_new_test_but_existing_upload_continues(self) -> None:
        await self.create_subject_and_consent(self.session.access_token)
        existing = await self.create_session(self.session.access_token, self.session_id)
        self.assertEqual(existing.status_code, 201, existing.text)

        await self.platform.control_license(
            self.operator,
            self.provisioned.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.SUSPEND,
                reason_code="CUSTOMER_REQUEST",
            ),
        )
        refreshed = await self.tenant_access.refresh(
            RefreshRequest(
                refresh_token=self.session.refresh_token,
                client_installation_id=self.installation_id,
            )
        )
        self.assertFalse(refreshed.capabilities.allow_new_test)
        self.assertTrue(refreshed.capabilities.allow_upload)

        rejected_lease = await self.client.post(
            "/v1/access/hardware-lease",
            headers=self.headers(refreshed.access_token),
            json=HardwareLeaseRequest(
                hardware_id=self.session.hardware_id,
                client_installation_id=self.installation_id,
            ).model_dump(mode="json"),
        )
        self.assertEqual(rejected_lease.status_code, 409, rejected_lease.text)

        blocked_session_id = uuid4()
        blocked = await self.create_session(refreshed.access_token, blocked_session_id)
        self.assertEqual(blocked.status_code, 403, blocked.text)

        not_created = await self.client.get(
            f"/v1/sessions/{blocked_session_id}/status",
            headers=self.headers(refreshed.access_token),
        )
        self.assertEqual(not_created.status_code, 404, not_created.text)

        payload = b"captured before suspension"
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
        headers = self.headers(refreshed.access_token)
        headers.update(
            {
                "X-Content-SHA256": metadata.sha256,
                "X-Schema-Version": metadata.payload_schema_version,
                "X-Segment-Metadata": encode_segment_metadata(metadata),
                "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream",
            }
        )
        uploaded = await self.client.put(
            f"/v1/sessions/{self.session_id}/segments/0",
            headers=headers,
            content=payload,
        )
        self.assertEqual(uploaded.status_code, 201, uploaded.text)

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
            ended_at=self.now + timedelta(seconds=1),
            local_quality_outcome="VALID",
        )
        complete_headers = self.headers(refreshed.access_token)
        complete_headers.update(
            {
                "Idempotency-Key": "complete-suspended-session",
                "X-Content-SHA256": canonical_sha256(manifest),
                "X-Schema-Version": manifest.schema_version,
            }
        )
        completed = await self.client.post(
            f"/v1/sessions/{self.session_id}/complete",
            headers=complete_headers,
            json=manifest.model_dump(mode="json"),
        )
        self.assertEqual(completed.status_code, 200, completed.text)

    async def test_tenant_token_requires_its_own_installation_audit_identity(self) -> None:
        alien_installation = uuid4()
        alien_token = self.tenant_tokens.issue(
            tenant_id=self.provisioned.tenant_id,
            account_id=self.session.account_id,
            license_id=self.session.license_id,
            hardware_id=self.session.hardware_id,
            client_installation_id=alien_installation,
            token_version=1,
            capabilities=self.session.capabilities,
            now=self.now,
        )

        response = await self.create_session(alien_token, uuid4())

        self.assertEqual(response.status_code, 403, response.text)
        self.assertNotIn(alien_token, response.text)

    async def test_tenant_access_token_records_heartbeat_for_its_installation(self) -> None:
        headers = self.headers(self.session.access_token)
        headers.update(
            {
                "X-Terminal-ID": str(self.installation_id),
                "Idempotency-Key": "seed-heartbeat-1",
            }
        )
        heartbeat = HeartbeatRequest(
            app_version="0.1.0",
            config_version="seed/1",
            protocol_version="do-p4864/1",
            device=HeartbeatDevice(
                device_id=self.device_id,
                model="DO-P4864",
                connection_state="READY",
            ),
            sync=HeartbeatSync(
                last_successful_sync=self.now,
                pending_sessions=0,
                pending_bytes=0,
            ),
            health=HeartbeatHealth(
                disk_free_bytes=1_000_000,
                clock_skew_seconds=0.0,
            ),
            observed_at=self.now,
        )

        response = await self.client.post(
            f"/v1/terminals/{self.installation_id}/heartbeats",
            headers=headers,
            json=heartbeat.model_dump(mode="json"),
        )

        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["data"]["terminal_id"], str(self.installation_id))
