"""RAY-728 R1: activated terminals reach the subject, consent and session routes."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import unittest
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import (
    ActivateAccountRequest,
    LicenseControlAction,
    LicenseControlRequest,
    PlatformRole,
    ProvisionTenantRequest,
)
from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ExternalIdentifierInput,
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
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.capture_grants import CaptureGrantService
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationService,
)
from techflex_cloud_foundation.server.access_control.terminal_service import TerminalAccessService
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.contract_export import build_vectors
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)

LOGIN_KEY = b"login-lookup-key-must-contain-32-bytes"
ACTIVATION_KEY = b"activation-key-must-contain-at-least-32-bytes"
TOKEN_SECRET = b"tenant-token-secret-must-be-at-least-32-bytes"
PASSWORD = "correct-horse-battery-staple"
RESOLVE = {
    "issuer": "gait-clinic",
    "id_type": "medical_record_number",
    "external_id": "GAIT-001",
}


class TerminalDataPlaneTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.access = InMemoryAccessRepository()
        private_key = Ed25519PrivateKey.generate()
        signer = LicenseDocumentSigner(
            private_key=private_key,
            key_id="license/2-key-1",
            public_keys={
                "license/2-key-1": private_key.public_key().public_bytes(
                    Encoding.Raw, PublicFormat.Raw
                )
            },
        )
        tenant_tokens = TenantAccessTokenIssuer(secret=TOKEN_SECRET, key_id="tenant/1")
        # Same secret and key id as tenant tokens, as in seed composition.
        terminal_tokens = TerminalAccessTokenIssuer(secret=TOKEN_SECRET, key_id="tenant/1")
        tenant_access = TenantAuthenticationService(
            self.access,
            login_lookup_hmac_key=LOGIN_KEY,
            activation_hmac_key=ACTIVATION_KEY,
            tenant_tokens=tenant_tokens,
            refresh_tokens=RefreshTokenFactory(
                digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
            ),
            license_signer=signer,
            now=lambda: self.now,
        )
        self.platform = PlatformProvisioningService(
            self.access,
            login_lookup_hmac_key=LOGIN_KEY,
            activation_hmac_key=ACTIVATION_KEY,
            license_signer=signer,
            now=lambda: self.now,
        )
        self.operator = PlatformAccessContext(
            platform_identity_id=uuid4(),
            roles=frozenset({PlatformRole.OPERATIONS}),
            token_version=1,
            expires_at=self.now + timedelta(minutes=15),
        )
        provisioned = await self.platform.provision_tenant(
            self.operator,
            ProvisionTenantRequest(
                tenant_name="Gait Clinic",
                account_name="gait-clinic",
                hardware_id="usb-serial-0123456789abcdef0123",
                license_period_months=12,
            ),
        )
        await tenant_access.activate(
            ActivateAccountRequest(
                account_name=provisioned.account_name,
                activation_code=provisioned.activation_code,
                password=PASSWORD,
                password_confirmation=PASSWORD,
                hardware_id=provisioned.hardware_id,
                client_installation_id=uuid4(),
            ),
            source_fingerprint=b"terminal-data-plane-test",
        )
        self.tenant_id = provisioned.tenant_id
        self.account_name = provisioned.account_name
        self.license_id = provisioned.license_id
        await self.access.set_terminal_seats(
            license_id=self.license_id, seats=2, changed_at=self.now
        )
        group = await self.access.access_group_for_license(self.license_id)
        self.hardware_device_id = (await self.access.hardware(group.hardware_id)).hardware_id

        self.data = InMemoryPlatformRepository(access_repository=self.access)
        self.insole_id = uuid4()
        # Stand-ins for the RAY-728 D3 projections; the PostgreSQL live test
        # covers the projection writes themselves.
        self.data.add_device(self.tenant_id, self.insole_id, "insole-pair")
        self.data.add_device(self.tenant_id, self.hardware_device_id, "dop4864")
        app = create_app(
            ServiceContainer(
                ingestion=IngestionService(
                    self.data,
                    SegmentObjectStore(InMemoryObjectStore()),
                    # Both schemas, as deployed (RAY-825).
                    supported_payload_schemas={"raw-segment/1", "insole-session-archive/1"},
                    supported_manifest_schemas={"session-manifest/1", "insole-session-manifest/1"},
                ),
                subjects=SubjectConsentService(
                    self.data,
                    IdentityProtector(
                        encryption_key=b"e" * 32,
                        lookup_hmac_key=b"h" * 32,
                        key_version="identity/1",
                    ),
                ),
                tenant_access=tenant_access,
                tenant_tokens=tenant_tokens,
                capture_grants=CaptureGrantService(self.data),
                terminal_access=TerminalAccessService(
                    self.access,
                    login_lookup_hmac_key=LOGIN_KEY,
                    terminal_tokens=terminal_tokens,
                    refresh_tokens=TerminalRefreshTokenFactory(
                        digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
                    ),
                    license_signer=signer,
                    now=lambda: self.now,
                ),
                terminal_tokens=terminal_tokens,
            )
        )
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")
        self.terminal = await self.activate()
        self.installation_id = UUID(self.terminal["client_installation_id"])
        self.subject_id = uuid4()
        self.consent_id = uuid4()

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def activate(self, installation_id: UUID | None = None, *, expect: int = 201):
        installation_id = installation_id or uuid4()
        response = await self.client.post(
            "/v1/access/terminal-activate",
            json={
                "account_name": self.account_name,
                "password": PASSWORD,
                "terminal_name": "Gait lab",
                "client_installation_id": str(installation_id),
                "platform": "android",
            },
        )
        self.assertEqual(response.status_code, expect, response.text)
        if expect != 201:
            return response
        # Activation projects the terminal into device.terminals (D3).
        self.data.add_terminal(self.tenant_id, None, installation_id)
        return response.json()["data"]

    async def revoke(self, credentials: dict, target: UUID) -> None:
        response = await self.client.post(
            f"/v1/access/terminals/{target}/revoke", headers=self.headers(credentials)
        )
        self.assertEqual(response.status_code, 200, response.text)
        self.data.set_terminal_status(self.tenant_id, target, "REVOKED")

    @staticmethod
    def headers(credentials: dict, **extra: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {credentials['access_token']}", **extra}

    @staticmethod
    def error_code(response) -> str:
        return response.json()["error"]["code"]

    def session_request(self, session_id: UUID | None = None, **changes) -> dict:
        request = SessionCreateRequest(
            session_id=session_id or uuid4(),
            subject_uuid=self.subject_id,
            consent_record_id=self.consent_id,
            site_id=None,
            terminal_id=self.installation_id,
            client_installation_id=self.installation_id,
            device_id=self.insole_id,
            test_protocol=ProtocolContract(id="walk-10m", version="1.0"),
            versions=SessionVersions(
                app="0.1.0",
                protocol_profile="insole/1",
                payload_schema="raw-segment/1",
                calibration="calibration/1",
            ),
            started_at=self.now,
        )
        return request.model_copy(update=changes).model_dump(mode="json")

    async def create_subject_and_consent(self, credentials: dict) -> None:
        subject = SubjectCreateRequest(
            subject_uuid=self.subject_id,
            external_identifier=ExternalIdentifierInput(
                issuer="gait-clinic", id_type="medical_record_number", external_id="GAIT-001"
            ),
            analysis_profile={
                "height_cm": ProfileValue(state=MissingValueState.PROVIDED, value=168.0)
            },
        )
        created = await self.client.post(
            "/v1/subjects",
            headers=self.headers(credentials, **{"Idempotency-Key": "subject"}),
            json=subject.model_dump(mode="json"),
        )
        self.assertEqual(created.status_code, 201, created.text)
        resolved = await self.client.post(
            "/v1/subjects/resolve",
            headers=self.headers(credentials),
            json=RESOLVE,
        )
        self.assertEqual(resolved.status_code, 200, resolved.text)
        consent = ConsentCreateRequest(
            consent_record_id=self.consent_id,
            subject_uuid=self.subject_id,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW", "ANALYSIS_PROFILE"),
            granted_at=self.now,
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-client-evidence",
        )
        granted = await self.client.post(
            "/v1/consents",
            headers=self.headers(credentials, **{"Idempotency-Key": "consent"}),
            json=consent.model_dump(mode="json"),
        )
        self.assertEqual(granted.status_code, 201, granted.text)

    async def create_session(self, credentials: dict, body: dict, **extra: str):
        return await self.client.post(
            "/v1/sessions",
            headers=self.headers(credentials, **{"Idempotency-Key": str(uuid4()), **extra}),
            json=body,
        )

    def segment(self) -> tuple[SegmentMetadata, bytes]:
        payload = b"insole segment"
        return SegmentMetadata(
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
        ), payload

    async def put_segment(self, credentials: dict, session_id: str):
        metadata, payload = self.segment()
        return await self.client.put(
            f"/v1/sessions/{session_id}/segments/0",
            headers=self.headers(
                credentials,
                **{
                    "X-Content-SHA256": metadata.sha256,
                    "X-Schema-Version": metadata.payload_schema_version,
                    "X-Segment-Metadata": encode_segment_metadata(metadata),
                    "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream",
                },
            ),
            content=payload,
        )

    async def complete(self, credentials: dict, session_id: str):
        metadata, _ = self.segment()
        manifest = SessionManifest(
            segment_count=1,
            total_frames=metadata.frame_count,
            total_bytes=metadata.size_bytes,
            segments=(
                ManifestSegment(
                    index=0,
                    sha256=metadata.sha256,
                    size_bytes=metadata.size_bytes,
                    frame_count=metadata.frame_count,
                ),
            ),
            ended_at=self.now + timedelta(seconds=1),
            local_quality_outcome="VALID",
        )
        return await self.client.post(
            f"/v1/sessions/{session_id}/complete",
            headers=self.headers(
                credentials,
                **{
                    "Idempotency-Key": f"complete-{session_id}",
                    "X-Content-SHA256": canonical_sha256(manifest),
                    "X-Schema-Version": manifest.schema_version,
                },
            ),
            json=manifest.model_dump(mode="json"),
        )

    async def test_terminal_token_uploads_subject_consent_and_session(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        body = self.session_request()
        created = await self.create_session(self.terminal, body)
        self.assertEqual(created.status_code, 201, created.text)
        replay = await self.client.post(
            "/v1/sessions",
            headers=self.headers(self.terminal, **{"Idempotency-Key": "same"}),
            json=body,
        )
        self.assertEqual(replay.status_code, 200, replay.text)
        session_id = body["session_id"]
        uploaded = await self.put_segment(self.terminal, session_id)
        self.assertEqual(uploaded.status_code, 201, uploaded.text)
        listed = await self.client.get(
            f"/v1/sessions/{session_id}/segments", headers=self.headers(self.terminal)
        )
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.json()["data"]["missing"], [])
        completed = await self.complete(self.terminal, session_id)
        self.assertEqual(completed.status_code, 200, completed.text)
        status = await self.client.get(
            f"/v1/sessions/{session_id}/status", headers=self.headers(self.terminal)
        )
        self.assertEqual(status.status_code, 200, status.text)

    async def test_terminal_header_is_optional_but_must_match(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        matched = await self.create_session(
            self.terminal, self.session_request(), **{"X-Terminal-ID": str(self.installation_id)}
        )
        self.assertEqual(matched.status_code, 201, matched.text)
        mismatched = await self.create_session(
            self.terminal, self.session_request(), **{"X-Terminal-ID": str(uuid4())}
        )
        self.assertEqual(mismatched.status_code, 403, mismatched.text)

    async def test_invalid_bearer_keeps_generic_authentication_error(self) -> None:
        response = await self.create_session(
            {"access_token": "not-a-token"}, self.session_request()
        )
        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(self.error_code(response), "E-AUT-401")
        basic = await self.client.post(
            "/v1/sessions",
            headers={
                "Authorization": f"Basic {self.terminal['access_token']}",
                "Idempotency-Key": str(uuid4()),
            },
            json=self.session_request(),
        )
        self.assertEqual(basic.status_code, 401, basic.text)

    async def test_session_must_name_the_calling_terminal(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        other = uuid4()
        # The contract already rejects terminal_id != client_installation_id (422).
        for changes in (
            {"terminal_id": other, "client_installation_id": other},
            {"site_id": uuid4()},
        ):
            response = await self.create_session(self.terminal, self.session_request(**changes))
            self.assertEqual(response.status_code, 403, f"{changes}: {response.text}")
        self.assertFalse(self.data._sessions)

    async def test_device_must_be_an_active_insole_pair_of_the_institution(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        retired = uuid4()
        self.data.add_device(self.tenant_id, retired, "insole-pair", "RETIRED")
        for device_id in (uuid4(), retired, self.hardware_device_id):
            response = await self.create_session(
                self.terminal, self.session_request(device_id=device_id)
            )
            self.assertEqual(response.status_code, 403, response.text)
        self.assertFalse(self.data._sessions)

    async def test_other_terminal_cannot_touch_the_session(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        body = self.session_request()
        self.assertEqual((await self.create_session(self.terminal, body)).status_code, 201)
        other = await self.activate()
        session_id = body["session_id"]
        self.assertEqual((await self.put_segment(other, session_id)).status_code, 403)
        for path in ("segments", "status"):
            response = await self.client.get(
                f"/v1/sessions/{session_id}/{path}", headers=self.headers(other)
            )
            self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual((await self.complete(other, session_id)).status_code, 403)

    async def test_license_decides_new_tests_per_request_but_upload_continues(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        body = self.session_request()
        self.assertEqual((await self.create_session(self.terminal, body)).status_code, 201)
        await self.platform.control_license(
            self.operator,
            self.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"
            ),
        )
        # The same, still unexpired access token: the License is read per request.
        blocked = await self.create_session(self.terminal, self.session_request())
        self.assertEqual(blocked.status_code, 403, blocked.text)
        self.assertEqual((await self.put_segment(self.terminal, body["session_id"])).status_code, 201)
        self.assertEqual((await self.complete(self.terminal, body["session_id"])).status_code, 200)

    async def test_capture_authorization_is_not_supported_for_terminals(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        for extra in (
            {"X-Capture-Authorization": "grant opaque-token-value-at-least-20"},
            {"X-Expected-Manifest-SHA256": "a" * 64},
        ):
            response = await self.create_session(self.terminal, self.session_request(), **extra)
            self.assertEqual(response.status_code, 403, response.text)
        grants = await self.client.post(
            "/v1/access/capture-grants", headers=self.headers(self.terminal), json={"count": 1}
        )
        self.assertEqual(grants.status_code, 401, grants.text)

    async def test_self_revoked_terminal_is_rejected_on_every_data_route(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        body = self.session_request()
        self.assertEqual((await self.create_session(self.terminal, body)).status_code, 201)
        await self.revoke(self.terminal, self.installation_id)
        again = await self.client.post(
            f"/v1/access/terminals/{self.installation_id}/revoke",
            headers=self.headers(self.terminal),
        )
        self.assertEqual(self.error_code(again), "E-TRM-401-REVOKED")
        session_id = body["session_id"]
        responses = [
            await self.create_session(self.terminal, self.session_request()),
            await self.put_segment(self.terminal, session_id),
            await self.complete(self.terminal, session_id),
            await self.client.get(
                f"/v1/sessions/{session_id}/status", headers=self.headers(self.terminal)
            ),
            await self.client.post(
                "/v1/subjects/resolve",
                headers=self.headers(self.terminal),
                json=RESOLVE,
            ),
        ]
        for response in responses:
            self.assertEqual(response.status_code, 401, response.text)
            self.assertEqual(self.error_code(response), "E-TRM-401-REVOKED")

    async def test_reactivation_reuses_id_and_resumes_sessions_created_before_revoke(self) -> None:
        await self.create_subject_and_consent(self.terminal)
        body = self.session_request()
        self.assertEqual((await self.create_session(self.terminal, body)).status_code, 201)
        await self.revoke(self.terminal, self.installation_id)

        # Both seats taken while revoked: re-activation needs a seat again.
        first = await self.activate()
        second = await self.activate()
        full = await self.activate(self.installation_id, expect=409)
        self.assertEqual(self.error_code(full), "E-TRM-409-SEAT-LIMIT")
        await self.revoke(second, UUID(second["client_installation_id"]))
        self.assertTrue(first)

        reactivated = await self.activate(self.installation_id)
        self.assertEqual(reactivated["client_installation_id"], str(self.installation_id))
        session_id = body["session_id"]
        self.assertEqual((await self.put_segment(reactivated, session_id)).status_code, 201)
        self.assertEqual((await self.complete(reactivated, session_id)).status_code, 200)

    async def test_every_vector_scenario_is_replayed(self) -> None:
        vectors = build_vectors()["terminal_data_plane"]
        await self.create_subject_and_consent(self.terminal)
        retired = uuid4()
        self.data.add_device(self.tenant_id, retired, "insole-pair", "RETIRED")
        other_id = uuid4()

        async def full_upload():
            return await self.create_session(self.terminal, self.session_request())

        async def session_of_other_terminal():
            body = self.session_request()
            await self.create_session(self.terminal, body)
            other = await self.activate()
            return await self.put_segment(other, body["session_id"])

        async def license_without_new_test():
            body = self.session_request()
            await self.create_session(self.terminal, body)
            await self.platform.control_license(
                self.operator, self.license_id,
                LicenseControlRequest(
                    action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"),
            )
            blocked = await self.create_session(self.terminal, self.session_request())
            self.existing_upload = await self.put_segment(self.terminal, body["session_id"])
            return blocked

        async def revoked_terminal():
            await self.revoke(self.terminal, self.installation_id)
            return await self.create_session(self.terminal, self.session_request())

        actions = {
            "full_upload": full_upload,
            "x_terminal_id_mismatch": lambda: self.create_session(
                self.terminal, self.session_request(), **{"X-Terminal-ID": str(uuid4())}),
            "session_names_other_terminal": lambda: self.create_session(
                self.terminal,
                self.session_request(terminal_id=other_id, client_installation_id=other_id)),
            "site_id_present": lambda: self.create_session(
                self.terminal, self.session_request(site_id=uuid4())),
            "unknown_insole": lambda: self.create_session(
                self.terminal, self.session_request(device_id=uuid4())),
            "retired_insole": lambda: self.create_session(
                self.terminal, self.session_request(device_id=retired)),
            "capture_authorization_header": lambda: self.create_session(
                self.terminal, self.session_request(),
                **{"X-Capture-Authorization": "grant opaque-token-value-at-least-20"}),
            "session_of_other_terminal": session_of_other_terminal,
            # State-changing scenarios run last.
            "license_without_new_test": license_without_new_test,
            "revoked_terminal": revoked_terminal,
        }
        scenarios = {scenario["name"]: scenario for scenario in vectors["scenarios"]}
        self.assertEqual(set(scenarios), set(actions))
        for name, action in actions.items():
            expect = scenarios[name]["expect"]
            response = await action()
            self.assertEqual(response.status_code, expect["http_status"], f"{name}: {response.text}")
            if "code" in expect:
                self.assertEqual(self.error_code(response), expect["code"], name)
            if "existing_session_upload" in scenarios[name]:
                self.assertEqual(
                    self.existing_upload.status_code,
                    scenarios[name]["existing_session_upload"]["http_status"],
                )


if __name__ == "__main__":
    unittest.main()
