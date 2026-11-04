"""Independent R2 HTTP admission guards for neutral and legacy session inputs."""
from __future__ import annotations

import asyncio
import copy
from dataclasses import replace
import json
from pathlib import Path
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.contracts.access_control import (
    AccessCapabilities,
    LicenseControlAction,
    LicenseControlRequest,
)
from techflex_cloud_foundation.contracts.identity_recovery import RecoveryCaseCreateRequest
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.payload_contracts import default_payload_schema_registry
from techflex_cloud_foundation.server.access_auth import TenantAccessTokenIssuer
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.identity_recovery.repository import (
    InMemoryRecoveryCaseRepository,
)
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests import test_ffp_terminal_data_plane as terminal_cases


def published_session(schema):
    path = Path(__file__).resolve().parents[1] / "docs/contracts/session-create-vectors.json"
    entries = json.loads(path.read_text())["schemas"]
    entry = next(row for row in entries if row["schema"] == schema)
    return copy.deepcopy(entry["session"]["document"])


class Admission:
    def __init__(self, **service_options):
        self.tenant, self.terminal, self.site = uuid4(), uuid4(), uuid4()
        self.account, self.license = uuid4(), uuid4()
        self.repository = InMemoryPlatformRepository()
        self.repository.add_terminal(self.tenant, self.site, self.terminal)
        self.issuer = TenantAccessTokenIssuer(
            secret=b"r2-authorization-test-secret-32-bytes", key_id="test",
        )
        self.service = IngestionService(
            self.repository, SegmentObjectStore(InMemoryObjectStore()), **service_options,
        )
        self.app = create_app(ServiceContainer(ingestion=self.service, tenant_tokens=self.issuer))

    def document(self, schema="insole-session-archive/1"):
        document = published_session(schema)
        document.update(session_id=str(uuid4()), client_installation_id=str(self.terminal),
                        site_id=str(self.site))
        return document

    def headers(self, *, tenant=None, terminal=None, allow_new=True, allow_upload=True):
        token = self.issuer.issue(
            tenant_id=tenant or self.tenant, client_installation_id=terminal or self.terminal,
            account_id=self.account, license_id=self.license, hardware_id="test-hardware-identity",
            token_version=1,
            capabilities=AccessCapabilities(allow_new_test=allow_new, allow_upload=allow_upload),
        )
        return {"Authorization": "Bearer " + token, "Idempotency-Key": str(uuid4())}

    async def post(self, document, headers=None):
        async with AsyncClient(
            transport=ASGITransport(app=self.app), base_url="https://test",
        ) as client:
            return await client.post(
                "/v1/sessions", json=document, headers=headers or self.headers(),
            )


@pytest.mark.parametrize("change", [
    "subject_null", "subject_only", "terminal_only", "legacy_version_only",
    "unknown_top", "unknown_version", "missing_site", "unknown_schema", "gait_business_field",
])
def test_invalid_or_partial_legacy_input_cannot_fall_back_to_core(change):
    async def exercise():
        admission = Admission()
        body = admission.document()
        if change == "subject_null":
            body["subject_uuid"] = None
        elif change == "subject_only":
            body["subject_uuid"] = str(uuid4())
        elif change == "terminal_only":
            body["terminal_id"] = str(admission.terminal)
        elif change == "legacy_version_only":
            body["versions"]["calibration"] = "legacy/1"
        elif change == "unknown_top":
            body["unexpected"] = "must reject"
        elif change == "unknown_version":
            body["versions"]["unexpected"] = "must reject"
        elif change == "missing_site":
            del body["site_id"]
        elif change == "unknown_schema":
            body["versions"]["payload_schema"] = "unregistered/1"
        else:
            body = admission.document("gait-session-archive/1")
            body["subject_uuid"] = str(uuid4())
        response = await admission.post(body)
        assert response.status_code == 422, response.text
        assert not admission.repository._sessions
        assert not admission.repository._idempotency
    asyncio.run(exercise())


def test_complete_legacy_insole_with_unknown_field_is_not_a_core_request():
    async def exercise():
        admission = Admission()
        body = published_session("raw-segment/1")
        body["versions"]["payload_schema"] = "insole-session-archive/1"
        body["unexpected"] = True
        response = await admission.post(body)
        assert response.status_code == 422, response.text
        assert not admission.repository._sessions
    asyncio.run(exercise())


@pytest.mark.parametrize("identity", [
    "other_installation", "other_site", "null_site", "other_tenant", "inactive",
])
def test_core_admission_preserves_registered_identity_and_site(identity):
    async def exercise():
        admission = Admission()
        body, headers = admission.document(), admission.headers()
        if identity == "other_installation":
            other = uuid4()
            admission.repository.add_terminal(admission.tenant, admission.site, other)
            body["client_installation_id"] = str(other)
        elif identity == "other_site":
            body["site_id"] = str(uuid4())
        elif identity == "null_site":
            body["site_id"] = None
        elif identity == "other_tenant":
            headers = admission.headers(tenant=uuid4())
        else:
            key = (admission.tenant, admission.terminal)
            admission.repository._terminals[key] = replace(
                admission.repository._terminals[key], status="REVOKED",
            )
        response = await admission.post(body, headers)
        assert response.status_code == 403, response.text
        assert not admission.repository._sessions
        assert not admission.repository._idempotency
    asyncio.run(exercise())


def test_explicit_allowlist_still_restricts_an_injected_registry():
    async def exercise():
        admission = Admission(payload_registry=default_payload_schema_registry(),
                              supported_payload_schemas={"insole-session-archive/1"})
        response = await admission.post(admission.document("gait-session-archive/1"))
        assert response.status_code == 422, response.text
        assert not admission.repository._sessions
        accepted = await admission.post(admission.document())
        assert accepted.status_code == 201, accepted.text
    asyncio.run(exercise())


def test_new_test_permission_and_upload_permission_have_distinct_replay_rules():
    async def exercise():
        admission = Admission()
        body = admission.document()
        blocked = await admission.post(body, admission.headers(allow_new=False))
        assert blocked.status_code == 403, blocked.text
        assert not admission.repository._sessions
        created = await admission.post(body)
        assert created.status_code == 201, created.text
        replay = await admission.post(body, admission.headers(allow_new=False))
        assert replay.status_code == 200, replay.text
        blocked_upload = await admission.post(body, admission.headers(allow_upload=False))
        assert blocked_upload.status_code == 403, blocked_upload.text
        assert len(admission.repository._sessions) == 1
    asyncio.run(exercise())


@pytest.mark.parametrize("extra", [
    {"X-Capture-Authorization": "grant opaque-token-value-at-least-20",
     "X-Expected-Manifest-SHA256": "a" * 64},
    {"X-Capture-Authorization": "grant opaque-token-value-at-least-20"},
    {"X-Expected-Manifest-SHA256": "a" * 64},
])
def test_core_capture_headers_cannot_be_ignored_or_downgraded(extra):
    async def exercise():
        admission = Admission()
        response = await admission.post(admission.document(), {**admission.headers(), **extra})
        assert response.status_code == (403 if len(extra) == 2 else 422), response.text
        assert not admission.repository._sessions
        assert not admission.repository._capture_audits
    asyncio.run(exercise())


def test_core_session_cannot_bypass_real_identity_recovery_case_guard():
    async def exercise():
        admission = Admission()
        body = admission.document()
        recovery = InMemoryRecoveryCaseRepository(admission.repository)
        admission.repository.recovery_case_guard = recovery
        subject = uuid4()
        identifier = recovery.add_subject(admission.tenant, subject)
        request = RecoveryCaseCreateRequest(
            session_id=UUID(body["session_id"]), original_subject_uuid=uuid4(),
            cloud_subject_uuid=subject,
            envelope_sha256="a" * 64, identifier_issuer="test", identifier_type="test",
            external_identifier_id=identifier, terminal_id=admission.terminal,
        )
        await recovery.create_case(
            admission.tenant, admission.terminal, request, "b" * 64, "c" * 64,
        )
        response = await admission.post(body)
        assert response.status_code == 403, response.text
        assert not admission.repository._sessions
        assert not admission.repository._idempotency
    asyncio.run(exercise())


def test_real_terminal_authority_checks_core_identity_license_and_revocation():
    async def exercise():
        # Reuse real activation, credential verification and License services,
        # not a forged principal or dependency override.
        fixture = terminal_cases.TerminalDataPlaneTests()
        await fixture.asyncSetUp()
        try:
            body = published_session("insole-session-archive/1")
            body.update(session_id=str(uuid4()), site_id=None,
                        client_installation_id=str(fixture.installation_id))
            headers = fixture.headers(fixture.terminal, **{"Idempotency-Key": str(uuid4())})
            for changed in (
                {**body, "site_id": str(uuid4())},
                {**body, "client_installation_id": str(uuid4())},
            ):
                denied = await fixture.client.post("/v1/sessions", json=changed, headers=headers)
                assert denied.status_code == 403, denied.text
            created = await fixture.client.post("/v1/sessions", json=body, headers=headers)
            assert created.status_code == 201, created.text
            other = await fixture.activate()
            stolen = await fixture.client.get(
                f"/v1/sessions/{body['session_id']}/status", headers=fixture.headers(other),
            )
            assert stolen.status_code == 403, stolen.text
            await fixture.platform.control_license(
                fixture.operator, fixture.license_id,
                LicenseControlRequest(
                    action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST",
                ),
            )
            denied = await fixture.client.post(
                "/v1/sessions", json={**body, "session_id": str(uuid4())},
                headers={**headers, "Idempotency-Key": str(uuid4())},
            )
            assert denied.status_code == 403, denied.text
            replay = await fixture.client.post("/v1/sessions", json=body, headers=headers)
            assert replay.status_code == 200, replay.text
            await fixture.revoke(fixture.terminal, fixture.installation_id)
            denied = await fixture.client.post("/v1/sessions", json=body, headers=headers)
            assert denied.status_code == 401, denied.text
            assert fixture.error_code(denied) == "E-TRM-401-REVOKED"
        finally:
            await fixture.asyncTearDown()
    asyncio.run(exercise())
