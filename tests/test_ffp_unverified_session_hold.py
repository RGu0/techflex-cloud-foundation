from __future__ import annotations

from datetime import UTC, datetime
import unittest
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import PlatformRole
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    ResourceNotFound,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.access_auth import PlatformAccessContext
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.session_hold.models import (
    HoldApplyRequest,
    HoldDispositionRequest,
    HoldReleaseRequest,
)
from techflex_cloud_foundation.server.session_hold.repository import InMemorySessionHoldRepository
from techflex_cloud_foundation.server.session_hold.service import SessionHoldService


class HoldServiceTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tenant, self.session = uuid4(), uuid4()
        self.repository = InMemorySessionHoldRepository()
        self.repository.add_session(self.tenant, self.session, status="INGESTED", raw_object_count=16)
        self.service = SessionHoldService(self.repository)
        self.owner = PlatformAccessContext(uuid4(), frozenset({PlatformRole.OWNER}), 1, datetime.now(UTC))
        self.support = PlatformAccessContext(uuid4(), frozenset({PlatformRole.SUPPORT}), 1, datetime.now(UTC))
        self.engineer = PlatformAccessContext(uuid4(), frozenset({PlatformRole.ENGINEER}), 1, datetime.now(UTC))
        self.request = HoldApplyRequest(
            tenant_id=self.tenant,
            session_id=self.session,
            ticket_reference="INC-99",
            reason_code="IDENTITY_UNVERIFIED",
        )

    async def test_hold_is_idempotent_and_preserves_ingestion_and_raw_objects(self) -> None:
        first = await self.service.apply(self.owner, self.request, "apply-1")
        replay = await self.service.apply(self.owner, self.request, "apply-1")
        self.assertEqual(first, replay)
        self.assertTrue(self.repository.is_held(self.tenant, self.session))
        self.assertEqual(self.repository.session_status(self.tenant, self.session), "INGESTED")
        self.assertEqual(self.repository.raw_object_count(self.tenant, self.session), 16)
        self.assertEqual(self.repository.audit_count("session-hold.apply"), 1)
        self.assertNotIn("INC-99", repr(first))

    async def test_support_can_apply_but_engineer_cannot(self) -> None:
        await self.service.apply(self.support, self.request, "apply-1")
        with self.assertRaises(TenantAccessDenied):
            await self.service.apply(self.engineer, self.request, "apply-2")

    async def test_wrong_tenant_and_absent_session_are_indistinguishable(self) -> None:
        for request in (
            self.request.model_copy(update={"tenant_id": uuid4()}),
            self.request.model_copy(update={"session_id": uuid4()}),
        ):
            with self.assertRaises(ResourceNotFound) as caught:
                await self.service.apply(self.owner, request, "apply-1")
            self.assertEqual(str(caught.exception), "session not found")

    async def test_empty_ticket_and_conflicting_replay_fail_closed(self) -> None:
        with self.assertRaises(RequestContractError):
            await self.service.apply(
                self.owner, self.request.model_copy(update={"ticket_reference": " "}), "apply-1"
            )
        await self.service.apply(self.owner, self.request, "apply-1")
        with self.assertRaises(IdempotencyConflict):
            await self.service.apply(self.owner, self.request, "apply-2")
        with self.assertRaises(IdempotencyConflict):
            await self.service.apply(
                self.owner, self.request.model_copy(update={"ticket_reference": "INC-100"}), "apply-1"
            )
        second_session = uuid4()
        self.repository.add_session(self.tenant, second_session, status="INGESTED", raw_object_count=1)
        with self.assertRaises(IdempotencyConflict):
            await self.service.apply(
                self.owner, self.request.model_copy(update={"session_id": second_session}), "apply-1"
            )

    async def test_platform_route_rejects_terminal_token_and_returns_safe_status(self) -> None:
        class IdentityVerifier:
            async def verify_access_token(self, token):
                if token != "platform-token":
                    raise TenantAccessDenied("invalid platform token")
                return self_owner

        self_owner = self.owner
        app = create_app(ServiceContainer(
            platform_identities=IdentityVerifier(),
            platform_tokens=object(),
            session_holds=self.service,
        ))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test") as client:
            url = f"/v1/platform/tenants/{self.tenant}/sessions/{self.session}/hold"
            body = {"ticket_reference": "INC-99", "reason_code": "IDENTITY_UNVERIFIED"}
            denied = await client.post(url, headers={"Authorization": "Bearer terminal-token", "Idempotency-Key": "key-1"}, json=body)
            self.assertEqual(denied.status_code, 403)
            created = await client.post(url, headers={"Authorization": "Bearer platform-token", "Idempotency-Key": "key-1"}, json=body)
            self.assertEqual(created.status_code, 201, created.text)
            self.assertNotIn("INC-99", created.text)
            status = await client.get(url, headers={"Authorization": "Bearer platform-token"})
            self.assertEqual(status.status_code, 200, status.text)
            self.assertTrue(status.json()["data"]["held"])

    async def test_retain_decision_needs_basis_and_separate_explicit_release(self) -> None:
        await self.service.apply(self.owner, self.request, "apply-1")
        missing_basis = HoldDispositionRequest(
            tenant_id=self.tenant, session_id=self.session,
            ticket_reference="INC-99", decision_code="RETAIN_WITH_VALID_BASIS",
            evidence_reference="EV-99", valid_basis_reference=None,
        )
        with self.assertRaises(RequestContractError):
            await self.service.dispose(self.owner, missing_basis, "disposition-1")
        decision = missing_basis.model_copy(update={"valid_basis_reference": "LEGAL-99"})
        with self.assertRaises(TenantAccessDenied):
            await self.service.dispose(self.engineer, decision, "disposition-1")
        first = await self.service.dispose(self.owner, decision, "disposition-1")
        replay = await self.service.dispose(self.owner, decision, "disposition-1")
        self.assertEqual(first, replay)
        self.assertTrue(self.repository.is_held(self.tenant, self.session))
        self.assertEqual(self.repository.audit_count("session-hold.disposition"), 1)

        release = HoldReleaseRequest(
            tenant_id=self.tenant, session_id=self.session,
            ticket_reference="INC-99", evidence_reference="EV-RELEASE-99",
        )
        released = await self.service.release(self.support, release, "release-1")
        self.assertEqual(released.state, "RELEASED")
        self.assertFalse(self.repository.is_held(self.tenant, self.session))
        self.assertEqual(self.repository.audit_count("session-hold.release"), 1)
        self.assertEqual(self.repository.raw_object_count(self.tenant, self.session), 16)
        self.assertEqual(self.repository.session_status(self.tenant, self.session), "INGESTED")

    async def test_restrict_disposition_stays_held_with_planned_job(self) -> None:
        await self.service.apply(self.owner, self.request, "apply-1")
        policy_id = uuid4()
        self.repository.add_retention_policy(self.tenant, policy_id, approved=True)
        request = HoldDispositionRequest(
            tenant_id=self.tenant, session_id=self.session,
            ticket_reference="INC-99", decision_code="RESTRICT_AND_DISPOSE",
            retention_policy_id=policy_id, evidence_reference="EV-RESTRICT-99",
        )
        first = await self.service.dispose(self.owner, request, "disposition-1")
        replay = await self.service.dispose(self.owner, request, "disposition-1")
        self.assertEqual(first, replay)
        self.assertEqual(first.planned_job_status, "PLANNED")
        self.assertEqual(self.repository.planned_job_count(self.tenant, self.session), 1)
        self.assertEqual(self.repository.audit_count("session-hold.disposition"), 1)
        self.assertTrue(self.repository.is_held(self.tenant, self.session))
        self.assertEqual(self.repository.raw_object_count(self.tenant, self.session), 16)
        with self.assertRaises(IdempotencyConflict):
            await self.service.dispose(
                self.owner, request.model_copy(update={"evidence_reference": "EV-OTHER"}),
                "disposition-1",
            )
        with self.assertRaises(RequestContractError):
            await self.service.release(self.owner, HoldReleaseRequest(
                tenant_id=self.tenant, session_id=self.session,
                ticket_reference="INC-99", evidence_reference="EV-RELEASE-99",
            ), "release-1")

    async def test_unapproved_or_cross_tenant_policy_is_rejected(self) -> None:
        await self.service.apply(self.owner, self.request, "apply-1")
        policy_id = uuid4()
        self.repository.add_retention_policy(uuid4(), policy_id, approved=True)
        request = HoldDispositionRequest(
            tenant_id=self.tenant, session_id=self.session,
            ticket_reference="INC-99", decision_code="RESTRICT_AND_DISPOSE",
            retention_policy_id=policy_id, evidence_reference="EV-99",
        )
        with self.assertRaises(ResourceNotFound):
            await self.service.dispose(self.owner, request, "disposition-1")
        self.repository.add_retention_policy(self.tenant, policy_id, approved=True, data_category="LOGS")
        with self.assertRaises(ResourceNotFound):
            await self.service.dispose(self.owner, request, "disposition-1")
        self.assertTrue(self.repository.is_held(self.tenant, self.session))

    async def test_disposition_and_release_routes_require_platform_identity(self) -> None:
        await self.service.apply(self.owner, self.request, "apply-1")

        class IdentityVerifier:
            async def verify_access_token(self, token):
                if token != "platform-token":
                    raise TenantAccessDenied("invalid platform token")
                return self_owner

        self_owner = self.owner
        app = create_app(ServiceContainer(
            platform_identities=IdentityVerifier(),
            platform_tokens=object(),
            session_holds=self.service,
        ))
        url = f"/v1/platform/tenants/{self.tenant}/sessions/{self.session}/hold"
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test") as client:
            body = {
                "ticket_reference": "INC-99", "decision_code": "RETAIN_WITH_VALID_BASIS",
                "evidence_reference": "EV-99", "valid_basis_reference": "LEGAL-99",
            }
            denied = await client.post(f"{url}/disposition", json=body, headers={
                "Authorization": "Bearer terminal-token", "Idempotency-Key": "d-1",
            })
            self.assertEqual(denied.status_code, 403)
            decided = await client.post(f"{url}/disposition", json=body, headers={
                "Authorization": "Bearer platform-token", "Idempotency-Key": "d-1",
            })
            self.assertEqual(decided.status_code, 201, decided.text)
            self.assertNotIn("LEGAL-99", decided.text)
            released = await client.post(f"{url}/release", json={
                "ticket_reference": "INC-99", "evidence_reference": "EV-RELEASE-99",
            }, headers={"Authorization": "Bearer platform-token", "Idempotency-Key": "r-1"})
            self.assertEqual(released.status_code, 200, released.text)
            self.assertEqual(released.json()["data"]["state"], "RELEASED")


if __name__ == "__main__":
    unittest.main()
