import asyncio
from dataclasses import replace
from datetime import timedelta
import hashlib
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.access_control import (
    LicenseControlAction,
    LicenseControlRequest,
    PlatformRole,
    RefreshRequest,
)
from techflex_cloud_foundation.contracts.capture_grants import (
    SessionAuthorization,
    UploadMigrationPermitRequest,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.access_control.capture_grants import CaptureGrantService
from techflex_cloud_foundation.server.access_control.repository import (
    PlatformIdentityRecord,
    PlatformRoleBindingRecord,
)
from tests.test_ffp_tenant_access_ingestion import TenantAccessIngestionTests


class CaptureGrantApiTests(TenantAccessIngestionTests):
    async def migration_owner(self):
        identity = PlatformIdentityRecord(uuid4(), b"owner-test", "Owner", "unused", "ACTIVE", 1, self.now)
        await self.access_repository.create_platform_identity(identity, (
            PlatformRoleBindingRecord(uuid4(), identity.platform_identity_id, PlatformRole.OWNER, self.now - timedelta(seconds=1)),
        ))
        return replace(self.operator, platform_identity_id=identity.platform_identity_id, roles=frozenset({PlatformRole.OWNER}))

    def migration_request(self, **changes):
        fields = dict(tenant_id=self.provisioned.tenant_id, account_id=self.session.account_id,
                      license_id=self.session.license_id, installation_id=self.installation_id,
                      hardware_id=self.session.hardware_id, session_id=self.session_id,
                      request_sha256="a" * 64, manifest_sha256="b" * 64,
                      final_subject_uuid=self.subject_id, consent_record_id=self.consent_id,
                      consent_sha256=canonical_sha256(self.consent_request()),
                      evidence_reference="evidence/ray-513/review-1", reason="LEGACY_VALID_SESSION_REVIEWED",
                      identity_conflict=False, reconciliation_reference=None,
                      local_valid_reviewed=True, immutable_manifest_reviewed=True,
                      original_consent_reviewed=True, historical_authorization_reviewed=True)
        fields.update(changes)
        return UploadMigrationPermitRequest(**fields)

    async def test_migration_unverifiable_reconciliation_denied_and_audited(self):
        service = CaptureGrantService(self.data_repository)
        owner = await self.migration_owner()
        for reference in (uuid4(),):
            with self.assertRaises(TenantAccessDenied):
                await service.approve_migration(owner, self.migration_request(
                    identity_conflict=True, reconciliation_reference=reference,
                    original_envelope_sha256="d" * 64, original_subject_uuid=uuid4()))
        self.assertFalse(self.data_repository._migration_permits)
        self.assertEqual(len(self.data_repository._migration_audits), 1)

    async def test_migration_owner_approval_stores_only_digest_and_rejects_reissue(self):
        owner = await self.migration_owner()
        service = CaptureGrantService(self.data_repository)
        request = self.migration_request()
        permit = await service.approve_migration(owner, request)
        raw = permit.token.get_secret_value()
        stored = self.data_repository._migration_permits[(request.tenant_id, request.session_id)]
        self.assertEqual(stored.token_sha256, hashlib.sha256(raw.encode()).digest())
        self.assertEqual(stored.consumed_request_sha256, request.request_sha256)
        self.assertEqual(stored.expected_manifest_sha256, request.manifest_sha256)
        self.assertNotIn(raw, repr(self.data_repository._migration_audits))
        with self.assertRaises(TenantAccessDenied):
            await service.approve_migration(owner, request)
        self.assertEqual(len(self.data_repository._migration_permits), 1)

    async def test_migration_denies_roles_missing_reviews_and_wrong_history(self):
        owner = await self.migration_owner()
        service = CaptureGrantService(self.data_repository)
        attempts = [(replace(owner, roles=frozenset({role})), self.migration_request())
                    for role in (PlatformRole.OPERATIONS, PlatformRole.SUPPORT)]
        attempts += [(owner, self.migration_request(**{field: False})) for field in
                     ("local_valid_reviewed", "immutable_manifest_reviewed", "original_consent_reviewed", "historical_authorization_reviewed")]
        attempts += [(owner, self.migration_request(**{field: uuid4()})) for field in
                     ("account_id", "license_id", "installation_id")]
        attempts += [(owner, self.migration_request(hardware_id="usb-serial-ffffffffffffffffffff"))]
        for context, request in attempts:
            with self.assertRaises(TenantAccessDenied):
                await service.approve_migration(context, request)
        self.assertEqual(len(self.data_repository._migration_audits), len(attempts))
        self.assertFalse(self.data_repository._migration_permits)

    async def test_migration_revoked_owner_binding_denies_stale_context(self):
        owner = await self.migration_owner()
        self.access_repository._platform_role_bindings.clear()
        with self.assertRaises(TenantAccessDenied):
            await CaptureGrantService(self.data_repository).approve_migration(owner, self.migration_request())
        self.assertFalse(self.data_repository._migration_permits)

    async def test_migration_historical_closed_binding_remains_eligible(self):
        owner = await self.migration_owner()
        self.access_repository._group_history = [replace(row, closed_at=self.now + timedelta(seconds=1),
            close_reason_code="REPLACED") for row in self.access_repository._group_history]
        license_record = self.access_repository._licenses[self.session.license_id]
        self.access_repository._licenses[self.session.license_id] = replace(license_record, status="SUSPENDED")
        result = await CaptureGrantService(self.data_repository).approve_migration(owner, self.migration_request())
        self.assertEqual(result.session_id, self.session_id)

    async def test_migration_approved_permit_upload_binding_and_replay(self):
        owner = await self.migration_owner()
        await self.create_subject_and_consent(self.session.access_token)
        await self.platform.control_license(self.operator, self.provisioned.license_id,
            LicenseControlRequest(action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"))
        refreshed = await self.tenant_access.refresh(RefreshRequest(
            refresh_token=self.session.refresh_token, client_installation_id=self.installation_id))
        body = self.session_request(self.session_id)
        permit = await CaptureGrantService(self.data_repository).approve_migration(owner,
            self.migration_request(request_sha256=canonical_sha256(body)))
        auth = SessionAuthorization(session_id=permit.session_id, token=permit.token,
                                    kind="migration_permit", manifest_sha256="b" * 64)
        for changed, authorization in (
            (body.model_copy(update={"session_id": uuid4()}), auth),
            (body.model_copy(update={"config_snapshot": {"changed": True}}), auth),
            (body, auth.model_copy(update={"manifest_sha256": "c" * 64})),
        ):
            response = await self.client.post("/v1/sessions", json=changed.model_dump(mode="json"),
                headers={**self.headers(refreshed.access_token), **authorization.headers(), "Idempotency-Key": str(uuid4())})
            self.assertEqual(response.status_code, 403, response.text)
            self.assertFalse(self.data_repository._sessions)
            self.assertEqual(self.data_repository._migration_permits[(self.provisioned.tenant_id, self.session_id)].state, "ISSUED")
        for expected in (201, 200):
            response = await self.client.post("/v1/sessions", json=body.model_dump(mode="json"),
                headers={**self.headers(refreshed.access_token), **auth.headers(), "Idempotency-Key": "approved-permit"})
            self.assertEqual(response.status_code, expected, response.text)
        self.assertEqual(self.data_repository._migration_permits[(self.provisioned.tenant_id, self.session_id)].state, "CONSUMED")

    async def issue(self, count=1):
        return await self.client.post(
            "/v1/access/capture-grants", headers=self.headers(self.session.access_token),
            json={"count": count},
        )

    async def retire(self, session_id):
        return await self.client.post(
            "/v1/access/capture-grants/retire", headers=self.headers(self.session.access_token),
            json={"session_id": session_id, "reason": "CANCELED"},
        )

    async def test_issue_cap_retire_and_secret_storage(self):
        response = await self.issue(50)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        grants = response.json()["data"]["grants"]
        self.assertEqual(len({g["session_id"] for g in grants}), 50)
        self.assertEqual(len({g["token"] for g in grants}), 50)
        self.assertEqual((await self.issue()).status_code, 403)
        for grant in grants:
            self.assertGreaterEqual(len(grant["token"]), 32)
            self.assertNotIn(grant["token"], repr(self.data_repository._capture_grants))
            self.assertNotIn(grant["token"], repr(self.data_repository._capture_audits))
            stored = self.data_repository._capture_grants[(self.provisioned.tenant_id, UUID(grant["session_id"]))]
            self.assertEqual(stored.token_sha256, hashlib.sha256(grant["token"].encode()).digest())
            self.assertEqual(stored.hardware_id, self.device_id)
        self.assertEqual((await self.retire(grants[0]["session_id"])).status_code, 200)
        self.assertEqual((await self.retire(grants[0]["session_id"])).status_code, 403)
        self.assertEqual(len((await self.issue(50)).json()["data"]["grants"]), 1)

    async def test_live_suspension_denies_stale_active_token_without_mutation(self):
        grant = (await self.issue()).json()["data"]["grants"][0]
        await self.platform.control_license(
            self.operator, self.provisioned.license_id,
            LicenseControlRequest(action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"),
        )
        self.assertEqual((await self.issue()).status_code, 403)
        self.assertEqual((await self.retire(grant["session_id"])).status_code, 403)
        self.assertEqual(len(self.data_repository._capture_grants), 1)
        await self.platform.control_license(
            self.operator, self.provisioned.license_id,
            LicenseControlRequest(action=LicenseControlAction.RESTORE, reason_code="CUSTOMER_REQUEST"),
        )
        self.assertEqual((await self.retire(grant["session_id"])).status_code, 200)
        self.assertEqual((await self.issue()).status_code, 201)

    async def test_consumed_grant_cannot_retire(self):
        grant = (await self.issue()).json()["data"]["grants"][0]
        key = next(iter(self.data_repository._capture_grants))
        self.data_repository._capture_grants[key] = replace(
            self.data_repository._capture_grants[key], state="CONSUMED"
        )
        self.assertEqual((await self.retire(grant["session_id"])).status_code, 403)

    async def test_concurrent_last_slot_has_one_winner(self):
        self.assertEqual((await self.issue(49)).status_code, 201)
        results = await asyncio.gather(self.issue(), self.issue())
        self.assertEqual(sorted(response.status_code for response in results), [201, 403])
        self.assertEqual(len(self.data_repository._capture_grants), 50)

    async def test_revoked_installation_and_wrong_hardware_denied(self):
        installation = self.access_repository._installations[self.installation_id]
        self.access_repository._installations[self.installation_id] = replace(installation, status="REVOKED")
        self.assertEqual((await self.issue()).status_code, 403)
        self.access_repository._installations[self.installation_id] = installation
        hardware = self.access_repository._hardware[self.device_id]
        self.access_repository._hardware[self.device_id] = replace(hardware, status="RETIRED")
        self.assertEqual((await self.issue()).status_code, 403)
        self.assertEqual(len(self.data_repository._capture_grants), 0)
