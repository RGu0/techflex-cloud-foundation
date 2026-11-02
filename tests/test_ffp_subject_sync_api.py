"""RAY-907 R1: subject download, PATCH, name lookup and tag dictionary routes."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
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
from techflex_cloud_foundation.contracts.subject_sync import (
    SUBJECT_CURSOR_SCHEMA,
    SUBJECT_NAME_SEARCH_MAX_RESULTS,
    SubjectRecord,
)
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationService,
)
from techflex_cloud_foundation.server.access_control.terminal_service import TerminalAccessService
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.contract_export import build_openapi, build_vectors
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)
from techflex_cloud_foundation.server.subject_sync.repository import InMemorySubjectSyncRepository
from techflex_cloud_foundation.server.subject_sync.service import (
    SubjectSyncService,
    decode_cursor,
    encode_cursor,
)

LOGIN_KEY = b"login-lookup-key-must-contain-32-bytes"
ACTIVATION_KEY = b"activation-key-must-contain-at-least-32-bytes"
TOKEN_SECRET = b"tenant-token-secret-must-be-at-least-32-bytes"
REFRESH_KEY = b"refresh-digest-key-must-be-at-least-32-bytes"
PASSWORD = "correct-horse-battery-staple"
NUMBER = {"issuer": "gait-clinic", "id_type": "medical_record_number"}
NAME = "Zhang San"
CONTACT = "+86 138 0000 0000"


class SubjectSyncApiTests(unittest.IsolatedAsyncioTestCase):
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
        terminal_tokens = TerminalAccessTokenIssuer(secret=TOKEN_SECRET, key_id="tenant/1")
        self.tenant_access = TenantAuthenticationService(
            self.access,
            login_lookup_hmac_key=LOGIN_KEY,
            activation_hmac_key=ACTIVATION_KEY,
            tenant_tokens=tenant_tokens,
            refresh_tokens=RefreshTokenFactory(digest_key=REFRESH_KEY),
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
        terminal_access = TerminalAccessService(
            self.access,
            login_lookup_hmac_key=LOGIN_KEY,
            terminal_tokens=terminal_tokens,
            refresh_tokens=TerminalRefreshTokenFactory(digest_key=REFRESH_KEY),
            license_signer=signer,
            now=lambda: self.now,
        )
        self.identity = IdentityProtector(
            encryption_key=b"e" * 32, lookup_hmac_key=b"h" * 32, key_version="identity/1"
        )
        self.data = InMemoryPlatformRepository(access_repository=self.access)
        app = create_app(
            ServiceContainer(
                subjects=SubjectConsentService(self.data, self.identity),
                tenant_access=self.tenant_access,
                tenant_tokens=tenant_tokens,
                terminal_access=terminal_access,
                terminal_tokens=terminal_tokens,
                subject_sync=SubjectSyncService(
                    InMemorySubjectSyncRepository(self.data), terminal_access, self.identity,
                    now=lambda: self.now,
                ),
            )
        )
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")
        self.tenant_id, self.account_name, self.license_id = await self.provision("Gait Clinic")
        self.terminal = await self.activate(self.account_name, self.tenant_id)
        self.installation_id = UUID(self.terminal["client_installation_id"])

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def provision(self, name: str) -> tuple[UUID, str, UUID]:
        provisioned = await self.platform.provision_tenant(
            self.operator,
            ProvisionTenantRequest(
                tenant_name=name,
                account_name=name.lower().replace(" ", "-"),
                hardware_id=f"usb-serial-{uuid4().hex[:20]}",
                license_period_months=12,
            ),
        )
        await self.tenant_access.activate(
            ActivateAccountRequest(
                account_name=provisioned.account_name,
                activation_code=provisioned.activation_code,
                password=PASSWORD,
                password_confirmation=PASSWORD,
                hardware_id=provisioned.hardware_id,
                client_installation_id=uuid4(),
            ),
            source_fingerprint=b"subject-sync-test",
        )
        await self.access.set_terminal_seats(
            license_id=provisioned.license_id, seats=3, changed_at=self.now
        )
        return provisioned.tenant_id, provisioned.account_name, provisioned.license_id

    async def activate(self, account_name: str, tenant_id: UUID) -> dict:
        installation_id = uuid4()
        response = await self.client.post(
            "/v1/access/terminal-activate",
            json={
                "account_name": account_name,
                "password": PASSWORD,
                "terminal_name": "Gait lab",
                "client_installation_id": str(installation_id),
                "platform": "android",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        # Activation projects the terminal into device.terminals (RAY-728 D3).
        self.data.add_terminal(tenant_id, None, installation_id)
        return response.json()["data"]

    @staticmethod
    def headers(credentials: dict, key: str | None = None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {credentials['access_token']}"}
        if key is not None:
            headers["Idempotency-Key"] = key
        return headers

    @staticmethod
    def error_code(response) -> str:
        return response.json()["error"]["code"]

    async def create_subject(
        self,
        *,
        credentials: dict | None = None,
        name: str | None = NAME,
        number: str | None = "GAIT-001",
        contact: str | None = None,
    ) -> UUID:
        subject_uuid = uuid4()
        body: dict = {"subject_uuid": str(subject_uuid), "analysis_profile": {
            "height_cm": {"state": "PROVIDED", "value": 168.0}}}
        if number is not None:
            body["external_identifier"] = {**NUMBER, "external_id": number}
        if name is not None or contact is not None:
            body["identity_profile"] = {
                key: value for key, value in (("display_name", name), ("contact", contact))
                if value is not None
            }
        response = await self.client.post(
            "/v1/subjects",
            headers=self.headers(credentials or self.terminal, str(uuid4())),
            json=body,
        )
        self.assertEqual(response.status_code, 201, response.text)
        return subject_uuid

    async def download(self, credentials: dict | None = None, **params) -> dict:
        response = await self.client.get(
            "/v1/subjects", headers=self.headers(credentials or self.terminal), params=params
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["data"]

    async def record(self, subject_uuid: UUID) -> dict:
        items = (await self.download(limit=500))["items"]
        return next(item for item in items if item["subject_uuid"] == str(subject_uuid))

    async def patch(self, subject_uuid: UUID, body: dict, *, key: str | None = None,
                    credentials: dict | None = None):
        return await self.client.patch(
            f"/v1/subjects/{subject_uuid}",
            headers=self.headers(credentials or self.terminal, key or str(uuid4())),
            json=body,
        )

    async def search(self, name: str, credentials: dict | None = None):
        return await self.client.post(
            "/v1/subjects/search-by-name",
            headers=self.headers(credentials or self.terminal),
            json={"display_name": name},
        )

    async def create_tag(self, name: str, *, tag_id: UUID | None = None,
                         key: str | None = None, credentials: dict | None = None):
        return await self.client.post(
            "/v1/subject-tags",
            headers=self.headers(credentials or self.terminal, key or str(uuid4())),
            json={"tag_id": str(tag_id or uuid4()), "name": name},
        )

    async def suspend_license(self) -> None:
        await self.platform.control_license(
            self.operator,
            self.license_id,
            LicenseControlRequest(
                action=LicenseControlAction.SUSPEND, reason_code="CUSTOMER_REQUEST"
            ),
        )

    async def revoke_self(self) -> None:
        response = await self.client.post(
            f"/v1/access/terminals/{self.installation_id}/revoke",
            headers=self.headers(self.terminal),
        )
        self.assertEqual(response.status_code, 200, response.text)

    async def consent(self, subject_uuid: UUID) -> UUID:
        consent_id = uuid4()
        response = await self.client.post(
            "/v1/consents",
            headers=self.headers(self.terminal, str(uuid4())),
            json={
                "consent_record_id": str(consent_id),
                "subject_uuid": str(subject_uuid),
                "policy_version": "privacy-policy/1.0",
                "purpose_codes": ["SCREENING_SERVICE"],
                "data_categories": ["PRESSURE_RAW"],
                "granted_at": self.now.isoformat(),
                "evidence_type": "OPERATOR_CONFIRMED",
                "terminal_signature": "signed-client-evidence",
            },
        )
        self.assertEqual(response.status_code, 201, response.text)
        return consent_id

    # --- download -------------------------------------------------------

    async def test_download_pages_are_complete_ordered_and_end_with_a_stable_cursor(self) -> None:
        created = [await self.create_subject(number=f"GAIT-{index:03d}") for index in range(5)]
        seen: list[dict] = []
        cursor = None
        while True:
            params = {"limit": 2} | ({} if cursor is None else {"cursor": cursor})
            page = await self.download(**params)
            seen.extend(page["items"])
            cursor = page["next_cursor"]
            if not page["has_more"]:
                break
        self.assertEqual([item["subject_uuid"] for item in seen], [str(uuid) for uuid in created])
        revisions = [item["revision"] for item in seen]
        self.assertEqual(revisions, sorted(set(revisions)))
        last = await self.download(cursor=cursor)
        self.assertEqual((last["items"], last["next_cursor"], last["has_more"]),
                         ([], cursor, False))
        for item in seen:
            SubjectRecord.model_validate(item)

    async def test_record_carries_display_name_and_masked_number_but_never_contact(self) -> None:
        subject_uuid = await self.create_subject(contact=CONTACT)
        response = await self.client.get("/v1/subjects", headers=self.headers(self.terminal))
        self.assertNotIn(CONTACT, response.text)
        self.assertNotIn("contact", response.text)
        self.assertNotIn("GAIT-001", response.text.upper())
        record = response.json()["data"]["items"][0]
        self.assertEqual(record["subject_uuid"], str(subject_uuid))
        self.assertEqual(record["identity_profile"], {"display_name": NAME})
        self.assertEqual(record["external_identifier"]["external_id_masked"], "****-001")
        self.assertEqual(record["status"], "ACTIVE")
        self.assertEqual(record["tag_ids"], [])

    async def test_consent_create_and_revoke_and_archive_reappear_in_the_download(self) -> None:
        subject_uuid = await self.create_subject()
        cursor = (await self.download())["next_cursor"]
        consent_id = await self.consent(subject_uuid)
        page = await self.download(cursor=cursor)
        self.assertEqual([item["subject_uuid"] for item in page["items"]], [str(subject_uuid)])
        self.assertEqual(page["items"][0]["consents"][0]["consent_record_id"], str(consent_id))
        self.assertIsNone(page["items"][0]["consents"][0]["revoked_at"])

        cursor = page["next_cursor"]
        revoked = await self.client.post(
            f"/v1/consents/{consent_id}/revoke",
            headers=self.headers(self.terminal, str(uuid4())),
            json={"revoked_at": self.now.isoformat(), "reason_code": "SUBJECT_REQUEST"},
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        page = await self.download(cursor=cursor)
        consent = page["items"][0]["consents"][0]
        self.assertIsNotNone(consent["revoked_at"])
        self.assertEqual(consent["revocation_reason_code"], "SUBJECT_REQUEST")

        cursor = page["next_cursor"]
        archived = await self.patch(
            subject_uuid, {"base_revision": page["items"][0]["revision"], "status": "ARCHIVED"}
        )
        self.assertEqual(archived.status_code, 200, archived.text)
        page = await self.download(cursor=cursor)
        self.assertEqual(page["items"][0]["status"], "ARCHIVED")
        self.assertEqual(page["items"][0]["revision"], archived.json()["data"]["revision"])

    async def test_invalid_cursors_are_rejected(self) -> None:
        for cursor in (
            "not base64!",
            "bm90LWEtY3Vyc29y",
            encode_cursor("subject-tag-cursor/1", 1),
            base64.urlsafe_b64encode(b"subject-cursor/1:99999999999999999999").decode(),
            base64.urlsafe_b64encode(b"subject-cursor/1:-1").decode(),
        ):
            response = await self.client.get(
                "/v1/subjects", headers=self.headers(self.terminal), params={"cursor": cursor}
            )
            self.assertEqual(response.status_code, 400, cursor)
            self.assertEqual(self.error_code(response), "E-SUB-400-CURSOR-INVALID")
        self.assertEqual(decode_cursor(SUBJECT_CURSOR_SCHEMA, encode_cursor(
            SUBJECT_CURSOR_SCHEMA, 42)), 42)
        response = await self.client.get(
            "/v1/subjects", headers=self.headers(self.terminal), params={"limit": 501}
        )
        self.assertEqual(response.status_code, 422)

    # --- isolation ------------------------------------------------------

    async def test_other_institution_sees_nothing_and_gets_404(self) -> None:
        subject_uuid = await self.create_subject()
        tag = (await self.create_tag("Follow-up")).json()["data"]["tag"]
        other_tenant, other_account, _ = await self.provision("Other Clinic")
        other = await self.activate(other_account, other_tenant)
        self.assertEqual((await self.download(other))["items"], [])
        self.assertEqual((await self.search(NAME, other)).json()["data"]["items"], [])
        tags = await self.client.get("/v1/subject-tags", headers=self.headers(other))
        self.assertEqual(tags.json()["data"]["items"], [])
        response = await self.patch(
            subject_uuid, {"base_revision": 1, "status": "ARCHIVED"}, credentials=other
        )
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(self.error_code(response), "E-API-404")
        # Another institution's tag is unknown here.
        own = await self.create_subject(credentials=other, number="OTHER-1")
        revision = (await self.download(other))["items"][0]["revision"]
        response = await self.patch(
            own, {"base_revision": revision, "tag_ids": [tag["tag_id"]]}, credentials=other
        )
        self.assertEqual(self.error_code(response), "E-SUB-422-UNKNOWN-TAG")
        # The same number is free in the other institution.
        response = await self.patch(
            own, {"base_revision": revision,
                  "external_identifier": {**NUMBER, "external_id": "GAIT-001"}},
            credentials=other,
        )
        self.assertEqual(response.status_code, 200, response.text)

    # --- PATCH ----------------------------------------------------------

    async def test_patch_merges_profile_replaces_identity_and_tags_and_supersedes_number(self) -> None:
        subject_uuid = await self.create_subject(contact=CONTACT)
        first = (await self.create_tag("Follow-up")).json()["data"]["tag"]["tag_id"]
        second = (await self.create_tag("Diabetes")).json()["data"]["tag"]["tag_id"]
        record = await self.record(subject_uuid)
        response = await self.patch(subject_uuid, {
            "base_revision": record["revision"],
            "analysis_profile": {"weight_kg": {"state": "PROVIDED", "value": 61.5}},
            "identity_profile": {"display_name": "Li Si"},
            "tag_ids": [second, first],
            "external_identifier": {**NUMBER, "external_id": "GAIT-777"},
        })
        self.assertEqual(response.status_code, 200, response.text)
        updated = response.json()["data"]
        self.assertGreater(updated["revision"], record["revision"])
        self.assertEqual(set(updated["analysis_profile"]), {"height_cm", "weight_kg"})
        self.assertEqual(updated["identity_profile"], {"display_name": "Li Si"})
        self.assertEqual(updated["tag_ids"], sorted([first, second]))
        self.assertEqual(updated["external_identifier"]["external_id_masked"], "****-777")
        self.assertEqual(updated, await self.record(subject_uuid))
        # identity_profile replaced whole: the earlier contact is gone too.
        self.assertFalse(self.data.identity_storage_contains(CONTACT))

        old = await self.client.post(
            "/v1/subjects/resolve", headers=self.headers(self.terminal),
            json={**NUMBER, "external_id": "GAIT-001"},
        )
        self.assertEqual(old.status_code, 404, old.text)
        new = await self.client.post(
            "/v1/subjects/resolve", headers=self.headers(self.terminal),
            json={**NUMBER, "external_id": "gait-777"},
        )
        self.assertEqual(new.json()["data"]["subject_uuid"], str(subject_uuid))
        self.assertEqual((await self.search("li si")).json()["data"]["items"][0]["subject_uuid"],
                         str(subject_uuid))
        self.assertEqual((await self.search(NAME)).json()["data"]["items"], [])

        cleared = await self.patch(subject_uuid, {"base_revision": updated["revision"],
                                                  "tag_ids": []})
        self.assertEqual(cleared.json()["data"]["tag_ids"], [])
        # Setting the subject's own number again changes nothing but the revision.
        same = await self.patch(subject_uuid, {
            "base_revision": cleared.json()["data"]["revision"],
            "external_identifier": {**NUMBER, "external_id": "GAIT-777"}})
        self.assertEqual(same.status_code, 200, same.text)
        self.assertEqual(same.json()["data"]["external_identifier"],
                         updated["external_identifier"])

    async def test_patch_replay_returns_the_record_and_other_body_is_rejected(self) -> None:
        subject_uuid = await self.create_subject()
        revision = (await self.record(subject_uuid))["revision"]
        body = {"base_revision": revision, "status": "ARCHIVED"}
        first = await self.patch(subject_uuid, body, key="patch-key")
        replay = await self.patch(subject_uuid, body, key="patch-key")
        self.assertEqual(first.status_code, 200, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        self.assertEqual(replay.json()["data"], first.json()["data"])
        self.assertEqual((await self.record(subject_uuid))["revision"],
                         first.json()["data"]["revision"])
        for other_body, other_subject in (
            ({"base_revision": revision, "status": "ACTIVE"}, subject_uuid),
            (body, await self.create_subject(number="GAIT-002")),
        ):
            response = await self.patch(other_subject, other_body, key="patch-key")
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(self.error_code(response), "E-API-409")

    async def test_stale_revision_conflicts_with_the_current_record(self) -> None:
        subject_uuid = await self.create_subject()
        revision = (await self.record(subject_uuid))["revision"]
        winner = await self.patch(subject_uuid, {
            "base_revision": revision,
            "analysis_profile": {"weight_kg": {"state": "PROVIDED", "value": 60.0}}})
        self.assertEqual(winner.status_code, 200, winner.text)
        loser = await self.patch(subject_uuid, {
            "base_revision": revision,
            "analysis_profile": {"weight_kg": {"state": "PROVIDED", "value": 70.0}}})
        self.assertEqual(loser.status_code, 409, loser.text)
        error = loser.json()["error"]
        self.assertEqual(error["code"], "E-SUB-409-REVISION-CONFLICT")
        self.assertEqual(error["details"]["current"], winner.json()["data"])
        # Nothing was merged.
        self.assertEqual((await self.record(subject_uuid)), winner.json()["data"])

    async def test_number_of_another_subject_is_taken(self) -> None:
        owner = await self.create_subject(number="GAIT-001")
        subject_uuid = await self.create_subject(number="GAIT-002", name="Li Si")
        revision = (await self.record(subject_uuid))["revision"]
        response = await self.patch(subject_uuid, {
            "base_revision": revision,
            "external_identifier": {**NUMBER, "external_id": " gait-001 "}})
        self.assertEqual(response.status_code, 409, response.text)
        error = response.json()["error"]
        self.assertEqual(error["code"], "E-SUB-409-NUMBER-TAKEN")
        self.assertEqual(error["details"], {"subject_uuid": str(owner),
                                            "external_id_masked": "****-001"})
        self.assertEqual((await self.record(subject_uuid))["revision"], revision)

    async def test_merged_and_restricted_subjects_are_not_editable_and_hide_identity(self) -> None:
        for status in ("MERGED", "RESTRICTED"):
            subject_uuid = await self.create_subject(number=f"GAIT-{status}")
            self.data.touch_subject(self.tenant_id, subject_uuid, status=status)
            record = await self.record(subject_uuid)
            self.assertEqual(record["status"], status)
            self.assertIsNone(record["identity_profile"])
            response = await self.patch(subject_uuid, {
                "base_revision": record["revision"], "status": "ACTIVE"})
            self.assertEqual(response.status_code, 409, response.text)
            self.assertEqual(self.error_code(response), "E-SUB-409-NOT-EDITABLE")
            self.assertEqual((await self.search(NAME)).json()["data"]["items"], [])

    async def test_unknown_tag_is_rejected(self) -> None:
        subject_uuid = await self.create_subject()
        known = (await self.create_tag("Follow-up")).json()["data"]["tag"]["tag_id"]
        revision = (await self.record(subject_uuid))["revision"]
        response = await self.patch(subject_uuid, {
            "base_revision": revision, "tag_ids": [known, str(uuid4())]})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(self.error_code(response), "E-SUB-422-UNKNOWN-TAG")

    async def test_patch_request_contract(self) -> None:
        subject_uuid = await self.create_subject()
        for body in (
            {"base_revision": 1},
            {"base_revision": 0, "status": "ARCHIVED"},
            {"base_revision": 1, "status": "MERGED"},
            {"base_revision": 1, "tag_ids": [str(UUID(int=1))] * 2},
            {"base_revision": 1, "tag_ids": [str(UUID(int=index)) for index in range(65)]},
            {"base_revision": 1, "identity_profile": {"contact": None}},
        ):
            response = await self.patch(subject_uuid, body)
            self.assertEqual(response.status_code, 422, body)
        response = await self.client.patch(
            f"/v1/subjects/{subject_uuid}", headers=self.headers(self.terminal),
            json={"base_revision": 1, "status": "ARCHIVED"},
        )
        self.assertEqual(response.status_code, 422, response.text)

    # --- name lookup ----------------------------------------------------

    async def test_name_lookup_is_normalized_exact_and_capped(self) -> None:
        subject_uuid = await self.create_subject()
        for spelling in (NAME, "  zhang san  ", "ＺＨＡＮＧ　ＳＡＮ", "ZHANG SAN"):
            response = await self.search(spelling)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual([item["subject_uuid"] for item in response.json()["data"]["items"]],
                             [str(subject_uuid)], spelling)
        for spelling in ("Zhang", "ZhangSan", "Zhang San Feng"):
            self.assertEqual((await self.search(spelling)).json()["data"]["items"], [])
        # Archived subjects are still found.
        revision = (await self.record(subject_uuid))["revision"]
        await self.patch(subject_uuid, {"base_revision": revision, "status": "ARCHIVED"})
        self.assertEqual(len((await self.search(NAME)).json()["data"]["items"]), 1)
        for index in range(SUBJECT_NAME_SEARCH_MAX_RESULTS + 1):
            await self.create_subject(number=f"MANY-{index}")
        items = (await self.search(NAME)).json()["data"]["items"]
        self.assertEqual(len(items), SUBJECT_NAME_SEARCH_MAX_RESULTS)
        revisions = [item["revision"] for item in items]
        self.assertEqual(revisions, sorted(revisions))

    async def test_name_never_reaches_audit_or_error_details(self) -> None:
        await self.create_subject()
        await self.search(NAME)
        await self.search("Nobody Here")
        audits = self.data.subject_audits
        self.assertEqual([audit["safe_context"] for audit in audits],
                         [{"result_count": 1}, {"result_count": 0}])
        self.assertTrue(all(audit["actor_id"] == self.installation_id for audit in audits))
        self.assertNotIn("zhang", repr(audits).lower())
        too_long = "Zhang" * 60
        response = await self.search(too_long)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn("Zhang", response.text)
        self.assertEqual(len(audits), 2)

    async def test_blank_names_are_never_searchable(self) -> None:
        await self.create_subject(name="   ", number="BLANK-1")
        await self.create_subject(name="\u3000", number="BLANK-2")
        for spelling in ("   ", " ", "\u3000"):
            response = await self.search(spelling)
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["data"]["items"], [], repr(spelling))

    async def test_subject_without_name_key_is_found_after_its_identity_is_edited(self) -> None:
        subject_uuid = await self.create_subject()
        # D6: a row from before migration 0017 has no name key.
        self.data._name_lookup_hmacs.pop((self.tenant_id, subject_uuid))
        self.assertEqual((await self.search(NAME)).json()["data"]["items"], [])
        self.assertIn(str(subject_uuid), str((await self.download())["items"]))
        revision = (await self.record(subject_uuid))["revision"]
        await self.patch(subject_uuid, {"base_revision": revision,
                                        "identity_profile": {"display_name": NAME}})
        self.assertEqual(len((await self.search(NAME)).json()["data"]["items"]), 1)

    # --- tags -----------------------------------------------------------

    async def test_tag_create_replay_name_conflict_and_download(self) -> None:
        tag_id = uuid4()
        created = await self.create_tag(" Follow-up ", tag_id=tag_id, key="tag-key")
        self.assertEqual(created.status_code, 201, created.text)
        tag = created.json()["data"]["tag"]
        self.assertEqual((tag["tag_id"], tag["name"], tag["revision"]),
                         (str(tag_id), "Follow-up", 1))
        self.assertFalse(created.json()["data"]["conflict"])
        replay = await self.create_tag(" Follow-up ", tag_id=tag_id, key="tag-key")
        self.assertEqual((replay.status_code, replay.json()["data"]),
                         (201, created.json()["data"]))
        other = await self.create_tag("Other", tag_id=tag_id, key="tag-key")
        self.assertEqual(self.error_code(other), "E-API-409")
        reused_id = await self.create_tag("Another name", tag_id=tag_id)
        self.assertEqual(self.error_code(reused_id), "E-API-409")

        conflict = await self.create_tag("ＦＯＬＬＯＷ-ＵＰ")
        self.assertEqual(conflict.status_code, 200, conflict.text)
        self.assertEqual(conflict.json()["data"], {"tag": tag, "conflict": True})

        second = (await self.create_tag("Diabetes")).json()["data"]["tag"]
        page = (await self.client.get("/v1/subject-tags", headers=self.headers(self.terminal),
                                      params={"limit": 1})).json()["data"]
        self.assertEqual((page["items"], page["has_more"]), ([tag], True))
        page = (await self.client.get(
            "/v1/subject-tags", headers=self.headers(self.terminal),
            params={"cursor": page["next_cursor"]})).json()["data"]
        self.assertEqual((page["items"], page["has_more"]), ([second], False))
        wrong = await self.client.get(
            "/v1/subject-tags", headers=self.headers(self.terminal),
            params={"cursor": encode_cursor(SUBJECT_CURSOR_SCHEMA, 1)})
        self.assertEqual(self.error_code(wrong), "E-SUB-400-CURSOR-INVALID")
        for name in ("", "   ", "x" * 33):
            self.assertEqual((await self.create_tag(name)).status_code, 422, name)

    # --- terminal and License -------------------------------------------

    async def route_calls(self, subject_uuid: UUID):
        return {
            "download": lambda: self.client.get("/v1/subjects", headers=self.headers(self.terminal)),
            "search": lambda: self.search(NAME),
            "tags": lambda: self.client.get("/v1/subject-tags",
                                            headers=self.headers(self.terminal)),
            "patch": lambda: self.patch(subject_uuid, {"base_revision": 1, "status": "ARCHIVED"}),
            "tag_create": lambda: self.create_tag("Follow-up"),
        }

    async def test_inactive_license_keeps_reads_and_rejects_writes(self) -> None:
        subject_uuid = await self.create_subject()
        await self.suspend_license()
        calls = await self.route_calls(subject_uuid)
        for name in ("download", "search", "tags"):
            self.assertEqual((await calls[name]()).status_code, 200, name)
        for name in ("patch", "tag_create"):
            response = await calls[name]()
            self.assertEqual(response.status_code, 403, name)
            self.assertEqual(self.error_code(response), "E-TRM-403-LICENSE-INACTIVE")
        # RAY-728 D6: subject creation is unchanged and still allowed.
        await self.create_subject(number="GAIT-NEW")

    async def test_revoked_terminal_is_rejected_on_every_route(self) -> None:
        subject_uuid = await self.create_subject()
        await self.revoke_self()
        for name, call in (await self.route_calls(subject_uuid)).items():
            response = await call()
            self.assertEqual(response.status_code, 401, name)
            self.assertEqual(self.error_code(response), "E-TRM-401-REVOKED", name)

    async def test_tenant_hardware_token_is_not_a_terminal_credential(self) -> None:
        response = await self.client.get(
            "/v1/subjects", headers={"Authorization": "Bearer not-a-terminal-token"}
        )
        self.assertEqual(response.status_code, 401, response.text)

    # --- contract -------------------------------------------------------

    async def test_contract_lists_the_routes_and_their_codes(self) -> None:
        paths = build_openapi()["paths"]
        expected = {
            ("/v1/subjects", "get"): {"E-SUB-400-CURSOR-INVALID", "E-TRM-401-REVOKED"},
            ("/v1/subjects/{subject_uuid}", "patch"): {
                "E-SUB-409-REVISION-CONFLICT", "E-SUB-409-NUMBER-TAKEN",
                "E-SUB-409-NOT-EDITABLE", "E-SUB-422-UNKNOWN-TAG", "E-API-404", "E-API-409",
                "E-TRM-403-LICENSE-INACTIVE"},
            ("/v1/subjects/search-by-name", "post"): {"E-TRM-401-REVOKED"},
            ("/v1/subject-tags", "get"): {"E-SUB-400-CURSOR-INVALID"},
            ("/v1/subject-tags", "post"): {"E-API-409", "E-TRM-403-LICENSE-INACTIVE"},
        }
        for (path, method), codes in expected.items():
            operation = paths[path][method]
            self.assertLessEqual(codes, {item["code"] for item in operation["x-ffp-error-codes"]})
        self.assertEqual(set(paths["/v1/subject-tags"]["post"]["responses"]) & {"200", "201"},
                         {"200", "201"})
        params = {item["name"] for item in paths["/v1/subjects/{subject_uuid}"]["patch"]["parameters"]}
        self.assertIn("Idempotency-Key", params)

    async def test_vector_name_examples_hold(self) -> None:
        vectors = build_vectors()["subject_sync"]["name_search"]
        for left, right in vectors["equal_examples"]:
            self.assertEqual(IdentityProtector.normalize(left), IdentityProtector.normalize(right))
        for left, right in vectors["unequal_examples"]:
            self.assertNotEqual(IdentityProtector.normalize(left),
                                IdentityProtector.normalize(right))
        vectors = build_vectors()["subject_sync"]
        SubjectRecord.model_validate(vectors["record"])
        SubjectRecord.model_validate(vectors["errors"]["revision_conflict"]["body"]["error"]
                                     ["details"]["current"])

    async def test_every_vector_scenario_is_replayed(self) -> None:
        vectors = build_vectors()["subject_sync"]
        subject_uuid = await self.create_subject()
        other_uuid = await self.create_subject(number="GAIT-002", name="Li Si")
        restricted = await self.create_subject(number="GAIT-003", name="Wang Wu")
        self.data.touch_subject(self.tenant_id, restricted, status="RESTRICTED")
        state: dict = {}

        async def revision(uuid=subject_uuid):
            return (await self.record(uuid))["revision"]

        async def patch_current():
            state["body"] = {**vectors["patch"]["request"], "base_revision": await revision()}
            state["first"] = await self.patch(subject_uuid, state["body"], key="vector-key")
            return state["first"]

        async def patch_replay():
            response = await self.patch(subject_uuid, state["body"], key="vector-key")
            self.assertEqual(response.json()["data"]["revision"],
                             state["first"].json()["data"]["revision"])
            return response

        async def tag_conflict():
            response = await self.create_tag(vectors["tags"]["request"]["name"].upper())
            self.assertTrue(response.json()["data"]["conflict"])
            return response

        actions = {
            "download_from_start": lambda: self.client.get(
                "/v1/subjects", headers=self.headers(self.terminal)),
            "invalid_cursor": lambda: self.client.get(
                "/v1/subjects", headers=self.headers(self.terminal),
                params={"cursor": vectors["download"]["invalid_cursor_example"]}),
            "name_search_normalized": lambda: self.search(
                vectors["name_search"]["request"]["display_name"]),
            "tag_create": lambda: self.client.post(
                "/v1/subject-tags",
                headers={**self.headers(self.terminal), **vectors["tags"]["request_headers"]},
                json=vectors["tags"]["request"]),
            "tag_name_conflict": tag_conflict,
            "patch_current_revision": patch_current,
            "patch_replay": patch_replay,
            "patch_same_key_other_body": lambda: self.patch(
                subject_uuid, {**state["body"], "status": "ARCHIVED"}, key="vector-key"),
            "patch_stale_revision": lambda: self.patch(
                subject_uuid, {"base_revision": 1, "status": "ARCHIVED"}),
            "patch_unknown_tag": self._patch_with(other_uuid, {"tag_ids": [str(uuid4())]}),
            "patch_number_taken": self._patch_with(other_uuid, {
                "external_identifier": {**NUMBER, "external_id": "GAIT-001"}}),
            "patch_unknown_subject": lambda: self.patch(
                uuid4(), {"base_revision": 1, "status": "ARCHIVED"}),
            "patch_restricted_subject": self._patch_with(restricted, {"status": "ACTIVE"}),
            "license_inactive_read": self._suspended_read,
            "license_inactive_write": self._patch_with(other_uuid, {"status": "ARCHIVED"}),
            "revoked_terminal": self._revoked_download,
        }
        scenarios = {scenario["name"]: scenario for scenario in vectors["scenarios"]}
        self.assertEqual(list(scenarios), list(actions))
        for name, action in actions.items():
            expect = scenarios[name]["expect"]
            response = await action()
            self.assertEqual(response.status_code, expect["http_status"], f"{name}: {response.text}")
            if "code" in expect:
                self.assertEqual(self.error_code(response), expect["code"], name)
            if "count" in expect:
                self.assertEqual(len(response.json()["data"]["items"]), expect["count"], name)
            if "conflict" in expect:
                self.assertEqual(response.json()["data"]["conflict"], expect["conflict"], name)

    def _patch_with(self, subject_uuid: UUID, changes: dict):
        async def call():
            revision = (await self.record(subject_uuid))["revision"]
            return await self.patch(subject_uuid, {"base_revision": revision, **changes})
        return call

    async def _suspended_read(self):
        await self.suspend_license()
        return await self.client.get("/v1/subjects", headers=self.headers(self.terminal))

    async def _revoked_download(self):
        await self.revoke_self()
        return await self.client.get("/v1/subjects", headers=self.headers(self.terminal))


if __name__ == "__main__":
    unittest.main()
