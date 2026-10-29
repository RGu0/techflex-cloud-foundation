from __future__ import annotations

from datetime import UTC, datetime, timedelta
import unittest
from uuid import uuid4

from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ConsentRevokeRequest,
    ExternalIdentifierInput,
    IdentityProfileInput,
    MissingValueState,
    ProfileValue,
    SubjectCreateRequest,
    SubjectResolveRequest,
)
from techflex_cloud_foundation.platform_errors import IdempotencyConflict, TenantAccessDenied
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.subject_service import (
    IdentityProtector,
    SubjectConsentService,
)


class SubjectConsentTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tenant_id = uuid4()
        self.other_tenant_id = uuid4()
        self.terminal_id = uuid4()
        self.other_terminal_id = uuid4()
        self.context = TerminalContext(
            self.tenant_id,
            self.terminal_id,
            datetime.now(UTC) + timedelta(minutes=10),
        )
        self.other_context = TerminalContext(
            self.other_tenant_id,
            self.other_terminal_id,
            datetime.now(UTC) + timedelta(minutes=10),
        )
        self.repository = InMemoryPlatformRepository()
        self.repository.add_terminal(self.tenant_id, uuid4(), self.terminal_id)
        self.repository.add_terminal(self.other_tenant_id, uuid4(), self.other_terminal_id)
        self.protector = IdentityProtector(
            encryption_key=b"e" * 32,
            lookup_hmac_key=b"h" * 32,
            key_version="identity/1",
        )
        self.service = SubjectConsentService(self.repository, self.protector)
        self.external = ExternalIdentifierInput(
            issuer="site-main",
            id_type="medical_record_number",
            external_id=" A-123456 ",
        )

    def subject_request(self, subject_uuid=None) -> SubjectCreateRequest:
        return SubjectCreateRequest(
            subject_uuid=subject_uuid or uuid4(),
            external_identifier=self.external,
            analysis_profile={
                "height_cm": ProfileValue(state=MissingValueState.PROVIDED, value=168.0),
                "condition_tags": ProfileValue(state=MissingValueState.UNKNOWN, value=None),
            },
        )

    async def test_same_external_identifier_is_isolated_by_tenant(self) -> None:
        left = await self.service.create_subject(
            self.context, self.subject_request(), "left-subject"
        )
        right = await self.service.create_subject(
            self.other_context, self.subject_request(), "right-subject"
        )

        self.assertNotEqual(left.subject_uuid, right.subject_uuid)
        self.assertFalse(left.conflict)
        self.assertFalse(right.conflict)

    def test_lookup_hmac_is_scoped_by_tenant_issuer_and_type(self) -> None:
        left = self.protector.lookup_digest(
            self.external.external_id,
            tenant_id=str(self.tenant_id),
            issuer=self.external.issuer,
            id_type=self.external.id_type,
        )
        right = self.protector.lookup_digest(
            self.external.external_id,
            tenant_id=str(self.other_tenant_id),
            issuer=self.external.issuer,
            id_type=self.external.id_type,
        )

        self.assertNotEqual(left, right)

    async def test_normalized_identifier_resolves_without_storing_plaintext(self) -> None:
        created = await self.service.create_subject(
            self.context, self.subject_request(), "create-subject"
        )

        resolved = await self.service.resolve(
            self.context,
            SubjectResolveRequest(
                issuer="site-main",
                id_type="medical_record_number",
                external_id="a-123456",
            ),
        )

        self.assertEqual(resolved.subject_uuid, created.subject_uuid)
        self.assertEqual(resolved.external_id_masked, "****3456")
        self.assertFalse(self.repository.identity_storage_contains("A-123456"))

    async def test_duplicate_identifier_returns_conflict_without_auto_merge(self) -> None:
        first = await self.service.create_subject(
            self.context, self.subject_request(), "first-subject"
        )
        second = await self.service.create_subject(
            self.context, self.subject_request(), "second-subject"
        )

        self.assertEqual(second.subject_uuid, first.subject_uuid)
        self.assertTrue(second.conflict)
        self.assertEqual(self.repository.subject_count(self.tenant_id), 1)

    async def test_profile_missing_state_is_preserved(self) -> None:
        created = await self.service.create_subject(
            self.context, self.subject_request(), "profile-subject"
        )

        self.assertEqual(
            created.analysis_profile["condition_tags"].state,
            MissingValueState.UNKNOWN,
        )
        self.assertIsNone(created.analysis_profile["condition_tags"].value)

    async def test_optional_identity_profile_is_encrypted_in_separate_store(self) -> None:
        request = self.subject_request().model_copy(
            update={
                "identity_profile": IdentityProfileInput(
                    display_name="测试姓名",
                    contact="masked-contact@example.invalid",
                )
            }
        )

        await self.service.create_subject(self.context, request, "identity-subject")

        self.assertFalse(self.repository.identity_storage_contains("测试姓名"))
        self.assertFalse(
            self.repository.identity_storage_contains("masked-contact@example.invalid")
        )
        self.assertTrue(
            self.repository.has_identity_profile(self.tenant_id, request.subject_uuid)
        )

    async def test_consent_replay_is_idempotent_and_revocation_blocks_new_use(self) -> None:
        subject = await self.service.create_subject(
            self.context, self.subject_request(), "subject"
        )
        request = ConsentCreateRequest(
            consent_record_id=uuid4(),
            subject_uuid=subject.subject_uuid,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW", "ANALYSIS_PROFILE"),
            granted_at=datetime.now(UTC),
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-terminal-evidence",
        )

        first = await self.service.create_consent(self.context, request, "consent")
        replay = await self.service.create_consent(self.context, request, "consent")
        self.assertEqual(first, replay)

        await self.service.revoke_consent(
            self.context,
            request.consent_record_id,
            ConsentRevokeRequest(
                revoked_at=datetime.now(UTC), reason_code="SUBJECT_WITHDRAWN"
            ),
            "revoke",
        )
        self.assertFalse(
            await self.repository.is_consent_active(
                self.tenant_id, request.consent_record_id
            )
        )

    async def test_same_consent_id_with_changed_content_conflicts(self) -> None:
        subject = await self.service.create_subject(
            self.context, self.subject_request(), "subject"
        )
        request = ConsentCreateRequest(
            consent_record_id=uuid4(),
            subject_uuid=subject.subject_uuid,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW",),
            granted_at=datetime.now(UTC),
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-terminal-evidence",
        )
        await self.service.create_consent(self.context, request, "consent")

        with self.assertRaises(IdempotencyConflict):
            await self.service.create_consent(
                self.context,
                request.model_copy(update={"policy_version": "privacy-policy/2.0"}),
                "consent-changed",
            )

    async def test_cross_tenant_consent_reference_is_denied(self) -> None:
        subject = await self.service.create_subject(
            self.context, self.subject_request(), "subject"
        )
        request = ConsentCreateRequest(
            consent_record_id=uuid4(),
            subject_uuid=subject.subject_uuid,
            policy_version="privacy-policy/1.0",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW",),
            granted_at=datetime.now(UTC),
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="signed-terminal-evidence",
        )

        with self.assertRaises(TenantAccessDenied):
            await self.service.create_consent(self.other_context, request, "cross-tenant")


if __name__ == "__main__":
    unittest.main()
