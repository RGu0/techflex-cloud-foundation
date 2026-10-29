from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
from pydantic import ValidationError

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    IdentityProfileInput,
    SessionCreateRequest,
    SessionVersions,
    TestProtocol,
)
from techflex_cloud_foundation.contracts.identity_recovery import (
    RecoveryCaseCreateRequest,
    RecoveryRegistrationRequest,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    ResourceNotFound,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.access_auth import PlatformAccessContext
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.identity_recovery.repository import (
    InMemoryRecoveryCaseRepository,
)
from techflex_cloud_foundation.server.identity_recovery.service import IdentityRecoveryService
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.repository import (
    CaptureGrantRecord,
    InMemoryPlatformRepository,
)
from techflex_cloud_foundation.server.subject_service import IdentityProtector


class RecoveryCaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tenant, self.terminal, self.cloud_subject = uuid4(), uuid4(), uuid4()
        self.principal = IngestionPrincipal(
            tenant_id=self.tenant, terminal_id=self.terminal,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            allow_new_test=False, allow_upload=True,
        )
        self.repository = InMemoryRecoveryCaseRepository()
        self.identifier_id = self.repository.add_subject(
            self.tenant, self.cloud_subject, masked_clue="***0731"
        )
        self.service = IdentityRecoveryService(self.repository)
        self.request = RecoveryCaseCreateRequest(
            session_id=uuid4(), original_subject_uuid=uuid4(),
            cloud_subject_uuid=self.cloud_subject, envelope_sha256="a" * 64,
            identifier_issuer="institution", identifier_type="record-number",
            external_identifier_id=self.identifier_id,
            terminal_id=self.terminal,
        )

    async def test_immutable_retry_and_changed_key_conflict(self) -> None:
        first = await self.service.create_case(self.principal, self.request, "case-1")
        self.assertEqual(first, await self.service.create_case(self.principal, self.request, "case-1"))
        self.assertEqual(first, await self.service.get_case(self.principal, first.case_id))
        self.assertEqual(first.status, "PENDING")
        self.assertEqual(first.masked_clue, "***0731")
        self.assertNotIn("display_name", first.model_dump())
        with self.assertRaises(IdempotencyConflict):
            await self.service.create_case(
                self.principal, self.request.model_copy(update={"envelope_sha256": "b" * 64}), "case-1"
            )
        with self.assertRaises(IdempotencyConflict):
            await self.service.create_case(
                self.principal, self.request.model_copy(update={"envelope_sha256": "b" * 64}), "case-2"
            )

    async def test_context_and_subject_binding(self) -> None:
        with self.assertRaises(TenantAccessDenied):
            await self.service.create_case(
                self.principal, self.request.model_copy(update={"terminal_id": uuid4()}), "different-terminal"
            )
        with self.assertRaises(ResourceNotFound):
            await self.service.create_case(
                self.principal, self.request.model_copy(update={"cloud_subject_uuid": uuid4()}), "missing-subject"
            )
        with self.assertRaises(ResourceNotFound):
            await self.service.create_case(
                self.principal, self.request.model_copy(update={"external_identifier_id": uuid4()}),
                "different-identifier",
            )
        other = self.principal.__class__(
            tenant_id=uuid4(), terminal_id=self.terminal, expires_at=self.principal.expires_at,
            allow_new_test=False, allow_upload=True,
        )
        created = await self.service.create_case(self.principal, self.request, "case-1")
        with self.assertRaises(ResourceNotFound):
            await self.service.get_case(other, created.case_id)

    def test_rejects_malformed_or_self_mapping(self) -> None:
        with self.assertRaises(ValidationError):
            RecoveryCaseCreateRequest.model_validate(
                {**self.request.model_dump(), "envelope_sha256": "not-a-digest"}
            )
        with self.assertRaises(ValidationError):
            RecoveryCaseCreateRequest.model_validate(
                {**self.request.model_dump(), "original_subject_uuid": self.cloud_subject}
            )

    async def test_terminal_routes_bind_authentication_and_return_safe_summary(self) -> None:
        issuer = TerminalTokenIssuer(
            secret=b"test-only-recovery-token-secret-32-bytes", key_id="test-key",
            token_ttl=timedelta(minutes=10),
        )
        app = create_app(ServiceContainer(token_issuer=issuer, identity_recovery=self.service))
        headers = {
            "Authorization": f"Bearer {issuer.issue(self.tenant, self.terminal)}",
            "X-Terminal-ID": str(self.terminal), "Idempotency-Key": "route-1",
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test") as client:
            response = await client.post(
                "/v1/identity-recovery/cases", json=self.request.model_dump(mode="json"), headers=headers,
            )
            self.assertEqual(response.status_code, 201)
            case = response.json()["data"]
            self.assertEqual(case["status"], "PENDING")
            self.assertNotIn("display_name", str(response.json()))
            read = await client.get(f"/v1/identity-recovery/cases/{case['case_id']}", headers=headers)
            self.assertEqual(read.status_code, 200)
            self.assertEqual(read.json()["data"], case)
            wrong = await client.get(
                f"/v1/identity-recovery/cases/{case['case_id']}",
                headers={**headers, "Authorization": f"Bearer {issuer.issue(uuid4(), self.terminal)}"},
            )
            self.assertEqual(wrong.status_code, 404)


class RecoveryComparisonTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await RecoveryCaseTests.asyncSetUp(self)
        self.case = await self.service.create_case(self.principal, self.request, "compare-case")
        self.platform = PlatformAccessContext(
            platform_identity_id=uuid4(), roles=frozenset({PlatformRole.SUPPORT}),
            token_version=1, expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )

        class Sensitive:
            calls = 0

            async def read_identity(self, context, *, grant_id, tenant_id, subject_id, identity_loader, grant_observer):
                self.calls += 1
                grant_observer(type("Grant", (), {"ticket_reference": "SUP-100"})())
                name, contact = await identity_loader()
                return type("Identity", (), {
                    "display_name": name, "contact": contact,
                })()

        class IdentityReader:
            async def read_identity(self, tenant_id, subject_id):
                return "Ada Wu", "+86 13900001111"

        self.sensitive = Sensitive()
        self.service = IdentityRecoveryService(
            self.repository, sensitive=self.sensitive, identity_reader=IdentityReader(),
        )

    async def test_two_exact_fields_issue_one_short_receipt(self) -> None:
        result = await self.service.compare(
            self.platform, self.case.case_id, uuid4(), "Ａｄａ Wu ", "+86 13900001111",
            tenant_id=self.tenant, ticket_reference="SUP-100",
        )
        self.assertEqual(result.decision, "MATCHED")
        self.assertIsNotNone(result.receipt_id)
        self.assertLessEqual(
            result.receipt_expires_at - datetime.now(UTC), timedelta(minutes=15)
        )
        terminal = await self.service.get_case(self.principal, self.case.case_id)
        self.assertEqual(terminal.receipt_id, result.receipt_id)
        self.assertNotIn("Ada", terminal.model_dump_json())
        with self.assertRaises(IdempotencyConflict):
            await self.service.compare(
                self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
                tenant_id=self.tenant, ticket_reference="SUP-100",
            )
        self.assertEqual(
            (await self.service.get_case(self.principal, self.case.case_id)).receipt_id,
            result.receipt_id,
        )

    async def test_one_field_or_ambiguous_contact_never_issues_receipt(self) -> None:
        for name, contact in (
            ("Ada Wu", "wrong"), ("wrong", "+86 13900001111"),
            ("", "+86 13900001111"), ("Ada Wu", "+86 13900001111, +86 13900002222"),
        ):
            result = await self.service.compare(
                self.platform, self.case.case_id, uuid4(), name, contact,
                tenant_id=self.tenant, ticket_reference="SUP-100",
            )
            self.assertEqual(result.decision, "NOT_VERIFIED")
            self.assertIsNone(result.receipt_id)
            self.assertNotIn("contact", result.model_dump_json())
        self.assertEqual((await self.service.get_case(self.principal, self.case.case_id)).status, "DENIED")
        self.assertEqual(self.sensitive.calls, 3)

    async def test_ticket_must_match_consumed_grant(self) -> None:
        with self.assertRaises(TenantAccessDenied):
            await self.service.compare(
                self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
                tenant_id=self.tenant, ticket_reference="DIFFERENT-TICKET",
            )
        self.assertIsNone((await self.service.get_case(self.principal, self.case.case_id)).receipt_id)

    async def test_platform_route_returns_only_decision_and_opaque_receipt(self) -> None:
        class Identities:
            async def verify_access_token(_self, token):
                return self.platform

        app = create_app(ServiceContainer(
            identity_recovery=self.service, platform_identities=Identities(),
            platform_tokens=object(),
        ))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test") as client:
            response = await client.post(
                f"/v1/platform/identity-recovery/cases/{self.case.case_id}/compare",
                headers={"Authorization": "Bearer test-platform-token"},
                json={
                    "tenant_id": str(self.tenant), "grant_id": str(uuid4()),
                    "original_name": "Ada Wu", "original_contact": "+86 13900001111",
                    "ticket_reference": "SUP-100",
                },
            )
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["data"]["decision"], "MATCHED")
        self.assertNotIn("Ada Wu", str(body))
        self.assertNotIn("13900001111", str(body))
        self.assertNotIn("SUP-100", str(body))

    async def test_wrong_role_and_subject_binding_fail_closed(self) -> None:
        engineer = PlatformAccessContext(
            platform_identity_id=uuid4(), roles=frozenset({PlatformRole.ENGINEER}),
            token_version=1, expires_at=datetime.now(UTC) + timedelta(minutes=10),
        )
        with self.assertRaises(TenantAccessDenied):
            await self.service.compare(
                engineer, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
                tenant_id=self.tenant, ticket_reference="SUP-100",
            )
        self.assertEqual(self.sensitive.calls, 0)

    async def test_expired_receipt_requires_fresh_comparison(self) -> None:
        first = await self.service.compare(
            self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
            tenant_id=self.tenant, ticket_reference="SUP-100",
        )
        stored = self.repository._by_id[(self.tenant, self.case.case_id)]
        expired = replace(stored, receipt_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        self.repository._by_id[(self.tenant, self.case.case_id)] = expired
        self.repository._cases[(self.tenant, self.request.session_id)] = expired
        self.repository._keys[(self.tenant, stored.key_sha256)] = expired
        self.assertEqual((await self.service.get_case(self.principal, self.case.case_id)).status, "EXPIRED")
        self.assertIsNone((await self.service.get_case(self.principal, self.case.case_id)).receipt_id)
        second = await self.service.compare(
            self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
            tenant_id=self.tenant, ticket_reference="SUP-100",
        )
        self.assertNotEqual(first.receipt_id, second.receipt_id)
        self.assertEqual(self.sensitive.calls, 2)

    async def test_deactivated_cloud_subject_cannot_issue_receipt(self) -> None:
        self.repository.deactivate_subject(self.tenant, self.cloud_subject)
        with self.assertRaises(ResourceNotFound):
            await self.service.compare(
                self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
                tenant_id=self.tenant, ticket_reference="SUP-100",
            )
        self.assertIsNone((await self.service.get_case(self.principal, self.case.case_id)).receipt_id)

    async def test_replaced_identifier_cannot_issue_receipt(self) -> None:
        self.repository.replace_identifier(self.tenant, self.cloud_subject)
        with self.assertRaises(ResourceNotFound):
            await self.service.compare(
                self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
                tenant_id=self.tenant, ticket_reference="SUP-100",
            )
        self.assertIsNone((await self.service.get_case(self.principal, self.case.case_id)).receipt_id)


class RecoveryIdentityProtectionTests(unittest.TestCase):
    def test_identity_decrypt_is_bound_to_subject_and_tenant(self) -> None:
        tenant, subject = uuid4(), uuid4()
        protector = IdentityProtector(
            encryption_key=b"e" * 32, lookup_hmac_key=b"h" * 32,
            key_version="identity/1",
        )
        profile = IdentityProfileInput(display_name="Ada Wu", contact="+86 13900001111")
        protected = protector.protect_identity_profile(
            profile, tenant_id=str(tenant), subject_uuid=str(subject),
        )
        self.assertEqual(
            protector.unprotect_identity_profile(
                protected.ciphertext, protected.nonce, protected.key_version,
                tenant_id=str(tenant), subject_uuid=str(subject),
            ),
            profile,
        )
        with self.assertRaises(Exception):
            protector.unprotect_identity_profile(
                protected.ciphertext, protected.nonce, protected.key_version,
                tenant_id=str(tenant), subject_uuid=str(uuid4()),
            )


class RecoveryRegistrationTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        await RecoveryComparisonTests.asyncSetUp(self)
        self.principal = replace(
            self.principal, allow_new_test=True, account_id=uuid4(),
            license_id=uuid4(), hardware_id="usb-serial-recovery-test",
        )
        self.data = InMemoryPlatformRepository()
        self.site, self.device = uuid4(), uuid4()
        self.data.add_terminal(self.tenant, self.site, self.terminal)
        self.data.add_device(self.tenant, self.device, "DO-P4864")
        self.data.add_subject(self.tenant, self.cloud_subject)
        self.repository.attach_data_repository(self.data)
        self.data.recovery_case_guard = self.repository
        compared = await self.service.compare(
            self.platform, self.case.case_id, uuid4(), "Ada Wu", "+86 13900001111",
            tenant_id=self.tenant, ticket_reference="SUP-100",
        )
        self.receipt_id = compared.receipt_id
        self.consent = ConsentCreateRequest(
            consent_record_id=uuid4(), subject_uuid=self.cloud_subject,
            policy_version="consent/1", purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW",), granted_at=datetime.now(UTC),
            evidence_type="SUBJECT_CONFIRMED", terminal_signature="test-signature-123456",
        )
        self.session = SessionCreateRequest(
            session_id=self.request.session_id, subject_uuid=self.cloud_subject,
            consent_record_id=self.consent.consent_record_id, site_id=self.site,
            terminal_id=self.terminal, client_installation_id=self.terminal,
            device_id=self.device,
            test_protocol=TestProtocol(id="standard-screening", version="1"),
            versions=SessionVersions(
                app="0.1", protocol_profile="do-p4864/1",
                payload_schema="raw-segment/1", calibration="calibration/1",
            ),
            started_at=datetime.now(UTC),
        )
        self.registration = RecoveryRegistrationRequest(
            receipt_id=self.receipt_id,
            original_subject_uuid=self.request.original_subject_uuid,
            original_envelope_sha256=self.request.envelope_sha256,
            consent=self.consent, session=self.session,
        )

    async def test_paused_recovery_registration_without_authorization_is_denied(self) -> None:
        paused = replace(self.principal, allow_new_test=False)
        with self.assertRaises(TenantAccessDenied):
            await self.service.register(
                paused, self.case.case_id, self.registration, "paused-register"
            )
        self.assertEqual(len(self.data._consents), 0)
        self.assertEqual(len(self.data._sessions), 0)

    def _authorization(self, *, kind: str) -> SessionAuthorization:
        token = f"recovery-{kind}-authorization-token-12345"
        self.data_row = CaptureGrantRecord(
            tenant_id=self.tenant,
            session_id=self.session.session_id,
            installation_id=self.terminal,
            account_id=self.principal.account_id,
            license_id=self.principal.license_id,
            hardware_id=self.device,
            token_sha256=hashlib.sha256(token.encode()).digest(),
            issued_at=datetime.now(UTC),
            consumed_request_sha256=(
                canonical_sha256(self.session) if kind == "migration_permit" else None
            ),
            expected_manifest_sha256=("a" * 64 if kind == "migration_permit" else None),
            final_subject_uuid=(self.cloud_subject if kind == "migration_permit" else None),
            consent_record_id=(self.consent.consent_record_id if kind == "migration_permit" else None),
            consent_sha256=(canonical_sha256(self.consent) if kind == "migration_permit" else None),
            reconciliation_case_id=(self.case.case_id if kind == "migration_permit" else None),
            original_envelope_sha256=(self.request.envelope_sha256 if kind == "migration_permit" else None),
            original_subject_uuid=(self.request.original_subject_uuid if kind == "migration_permit" else None),
        )
        rows = self.data._capture_grants if kind == "grant" else self.data._migration_permits
        rows[(self.tenant, self.session.session_id)] = self.data_row
        return SessionAuthorization(
            session_id=self.session.session_id, kind=kind, token=token,
            manifest_sha256="a" * 64,
        )

    async def test_paused_recovery_with_preissued_grant_consumes_grant_atomically(self) -> None:
        paused = replace(self.principal, allow_new_test=False)
        authorization = self._authorization(kind="grant")
        result = await self.service.register(
            paused, self.case.case_id, self.registration, "paused-grant",
            authorization,
        )
        self.assertEqual(result.session_id, self.session.session_id)
        stored = self.data._capture_grants[(self.tenant, self.session.session_id)]
        self.assertEqual(stored.state, "CONSUMED")
        self.assertEqual(stored.consumed_request_sha256, canonical_sha256(self.session))
        self.assertEqual(stored.expected_manifest_sha256, authorization.manifest_sha256)
        self.assertEqual(len(self.data._consents), 1)
        self.assertEqual(len(self.data._sessions), 1)

    async def test_paused_recovery_with_bound_permit_checks_final_consent_and_case(self) -> None:
        paused = replace(self.principal, allow_new_test=False)
        authorization = self._authorization(kind="migration_permit")
        result = await self.service.register(
            paused, self.case.case_id, self.registration, "paused-permit",
            authorization,
        )
        self.assertEqual(result.session_id, self.session.session_id)
        stored = self.data._migration_permits[(self.tenant, self.session.session_id)]
        self.assertEqual(stored.state, "CONSUMED")
        self.assertEqual(stored.reconciliation_case_id, self.case.case_id)
        self.assertEqual(len(self.data._consents), 1)
        self.assertEqual(len(self.data._sessions), 1)

    async def test_atomic_registration_and_lost_response_retry(self) -> None:
        first = await self.service.register(
            self.principal, self.case.case_id, self.registration, "register-1"
        )
        self.assertEqual(first.session_id, self.request.session_id)
        self.assertEqual(first.consent_record_id, self.consent.consent_record_id)
        self.assertEqual(
            await self.service.register(self.principal, self.case.case_id, self.registration, "register-1"),
            first,
        )
        self.assertEqual(len(self.data._consents), 1)
        self.assertEqual(len(self.data._sessions), 1)
        with self.assertRaises(IdempotencyConflict):
            await self.service.register(
                self.principal, self.case.case_id,
                self.registration.model_copy(update={"consent": self.consent.model_copy(update={"consent_record_id": uuid4()})}),
                "register-1",
            )

    async def test_old_operator_attestation_and_wrong_binding_fail_closed(self) -> None:
        old = self.consent.model_copy(update={"evidence_type": "OPERATOR_CONFIRMED"})
        for changed in (
            self.registration.model_copy(update={"consent": old}),
            self.registration.model_copy(update={"original_envelope_sha256": "b" * 64}),
            self.registration.model_copy(update={"original_subject_uuid": uuid4()}),
            self.registration.model_copy(update={"receipt_id": uuid4()}),
        ):
            with self.assertRaises((RequestContractError, IdempotencyConflict)):
                await self.service.register(self.principal, self.case.case_id, changed, "bad-binding")
        self.assertEqual(len(self.data._consents), 0)
        self.assertEqual(len(self.data._sessions), 0)

    async def test_generic_session_creation_cannot_bypass_open_case(self) -> None:
        await self.data.create_consent(
            self.principal, self.consent, canonical_sha256(self.consent), "generic-consent"
        )
        with self.assertRaises(TenantAccessDenied):
            await self.data.create_session(self.principal, self.session, "generic-session")
        self.assertEqual(len(self.data._sessions), 0)

    async def test_expired_receipt_and_old_consent_do_not_register(self) -> None:
        stale_consent = self.consent.model_copy(update={
            "granted_at": datetime.now(UTC) - timedelta(days=1),
        })
        with self.assertRaises(RequestContractError):
            await self.service.register(
                self.principal, self.case.case_id,
                self.registration.model_copy(update={"consent": stale_consent}), "old-consent",
            )
        stored = self.repository._by_id[(self.tenant, self.case.case_id)]
        expired = replace(stored, receipt_expires_at=datetime.now(UTC) - timedelta(seconds=1))
        self.repository._by_id[(self.tenant, self.case.case_id)] = expired
        with self.assertRaises(IdempotencyConflict):
            await self.service.register(
                self.principal, self.case.case_id, self.registration, "expired-receipt",
            )
        self.assertEqual(len(self.data._sessions), 0)

    async def test_identifier_replacement_after_match_blocks_registration(self) -> None:
        self.repository.replace_identifier(self.tenant, self.cloud_subject)
        with self.assertRaises(ResourceNotFound):
            await self.service.register(
                self.principal, self.case.case_id, self.registration, "stale-identifier",
            )
        self.assertEqual(len(self.data._consents), 0)
        self.assertEqual(len(self.data._sessions), 0)

    async def test_failure_after_consent_insert_rolls_back_all_local_state(self) -> None:
        async def fail_session(*args, **kwargs):
            raise RuntimeError("injected session insert failure")

        self.data.create_session = fail_session
        with self.assertRaisesRegex(RuntimeError, "injected"):
            await self.service.register(
                self.principal, self.case.case_id, self.registration, "register-fail",
            )
        self.assertEqual(len(self.data._consents), 0)
        self.assertEqual(len(self.data._sessions), 0)
        self.assertIsNone(
            self.repository._by_id[(self.tenant, self.case.case_id)].receipt_consumed_at
        )

    async def test_concurrent_double_spend_has_one_winner(self) -> None:
        outcomes = await asyncio.gather(
            self.service.register(self.principal, self.case.case_id, self.registration, "register-a"),
            self.service.register(self.principal, self.case.case_id, self.registration, "register-b"),
            return_exceptions=True,
        )
        self.assertEqual(sum(isinstance(item, Exception) for item in outcomes), 1)
        self.assertEqual(len(self.data._consents), 1)
        self.assertEqual(len(self.data._sessions), 1)

    async def test_registration_route_is_terminal_authenticated(self) -> None:
        issuer = TerminalTokenIssuer(
            secret=b"test-only-recovery-token-secret-32-bytes", key_id="test-key",
            token_ttl=timedelta(minutes=10),
        )
        app = create_app(ServiceContainer(token_issuer=issuer, identity_recovery=self.service))
        headers = {
            "Authorization": f"Bearer {issuer.issue(self.tenant, self.terminal)}",
            "X-Terminal-ID": str(self.terminal), "Idempotency-Key": "route-register",
        }
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test") as client:
            url = f"/v1/identity-recovery/cases/{self.case.case_id}/register"
            response = await client.post(
                url, json=self.registration.model_dump(mode="json"), headers=headers,
            )
            self.assertEqual(response.status_code, 201)
            replay = await client.post(
                url, json=self.registration.model_dump(mode="json"), headers=headers,
            )
            self.assertEqual(replay.status_code, 201)
            self.assertEqual(response.json()["data"], replay.json()["data"])
            foreign = await client.post(
                url, json=self.registration.model_dump(mode="json"),
                headers={**headers, "Authorization": f"Bearer {issuer.issue(uuid4(), self.terminal)}"},
            )
            self.assertEqual(foreign.status_code, 404)
