"""RAY-656 R2 institutional multi-terminal activation API behaviour."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
import unittest
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import (
    LicenseState,
    PlatformRole,
    ProvisionTenantRequest,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.terminal_access import SignedTerminalLicense
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

LOGIN_KEY = b"login-lookup-key-must-contain-32-bytes"
ACTIVATION_KEY = b"activation-key-must-contain-at-least-32-bytes"
PASSWORD = "correct-horse-battery-staple"


class _TerminalApiFixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.repository = InMemoryAccessRepository()
        private_key = Ed25519PrivateKey.generate()
        self.public_key = private_key.public_key()
        signer = LicenseDocumentSigner(
            private_key=private_key,
            key_id="license/2-key-1",
            public_keys={
                "license/2-key-1": self.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
            },
        )
        tenant_tokens = TenantAccessTokenIssuer(
            secret=b"tenant-token-secret-must-be-at-least-32-bytes", key_id="tenant/1"
        )
        self.tenant_access = TenantAuthenticationService(
            self.repository,
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
            self.repository,
            login_lookup_hmac_key=LOGIN_KEY,
            activation_hmac_key=ACTIVATION_KEY,
            license_signer=signer,
            now=lambda: self.now,
        )
        terminal_access = TerminalAccessService(
            self.repository,
            login_lookup_hmac_key=LOGIN_KEY,
            terminal_tokens=TerminalAccessTokenIssuer(
                secret=b"tenant-token-secret-must-be-at-least-32-bytes", key_id="tenant/1"
            ),
            refresh_tokens=TerminalRefreshTokenFactory(
                digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
            ),
            license_signer=signer,
            now=lambda: self.now,
        )
        app = create_app(
            ServiceContainer(
                tenant_access=self.tenant_access,
                tenant_tokens=tenant_tokens,
                terminal_access=terminal_access,
                terminal_tokens=TerminalAccessTokenIssuer(
                    secret=b"tenant-token-secret-must-be-at-least-32-bytes", key_id="tenant/1"
                ),
            )
        )
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")
        self.account_name, self.license_id = await self._active_account(
            "Seed Clinic", "seed-clinic", "usb-serial-0123456789abcdef0123"
        )
        await self.repository.set_terminal_seats(
            license_id=self.license_id, seats=2, changed_at=self.now
        )

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def _active_account(self, tenant: str, account: str, hardware: str):
        operator = PlatformAccessContext(
            platform_identity_id=uuid4(),
            roles=frozenset({PlatformRole.OPERATIONS}),
            token_version=1,
            expires_at=self.now + timedelta(minutes=15),
        )
        provisioned = await self.platform.provision_tenant(
            operator,
            ProvisionTenantRequest(
                tenant_name=tenant,
                account_name=account,
                hardware_id=hardware,
                license_period_months=12,
            ),
        )
        activated = await self.client.post(
            "/v1/access/activate",
            json={
                "account_name": provisioned.account_name,
                "activation_code": provisioned.activation_code,
                "password": PASSWORD,
                "password_confirmation": PASSWORD,
                "hardware_id": provisioned.hardware_id,
                "client_installation_id": str(uuid4()),
            },
        )
        assert activated.status_code == 201, activated.text
        return provisioned.account_name, provisioned.license_id

    async def activate(self, name: str = "Front desk", **overrides):
        body = {
            "account_name": self.account_name,
            "password": PASSWORD,
            "terminal_name": name,
            "client_installation_id": str(uuid4()),
            "platform": "ios",
            **overrides,
        }
        return await self.client.post("/v1/access/terminal-activate", json=body)

    async def refresh(self, credentials: dict, token: str | None = None):
        return await self.client.post(
            "/v1/access/terminal-refresh",
            json={
                "refresh_token": token or credentials["refresh_token"],
                "client_installation_id": credentials["client_installation_id"],
            },
        )

    def error_code(self, response) -> str:
        return response.json()["error"]["code"]

    def bearer(self, credentials: dict) -> dict[str, str]:
        return {"Authorization": f"Bearer {credentials['access_token']}"}


class TerminalAccessApiTests(_TerminalApiFixture):
    async def test_one_account_activates_terminals_up_to_signed_seat_limit(self) -> None:
        first = await self.activate("Front desk")
        second = await self.activate("Gait lab", platform="android")
        third = await self.activate("Overflow")

        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(second.status_code, 201, second.text)
        self.assertEqual(third.status_code, 409, third.text)
        self.assertEqual(self.error_code(third), "E-TRM-409-SEAT-LIMIT")
        self.assertEqual(third.json()["error"]["action"], "FREE_TERMINAL_SEAT")
        data = first.json()["data"]
        self.assertEqual(data["refresh_replay_grace_seconds"], 30)
        self.assertNotEqual(data["refresh_token"], second.json()["data"]["refresh_token"])
        signed = SignedTerminalLicense.model_validate(data["signed_license"])
        self.assertEqual(signed.document.seats, 2)
        self.assertEqual(signed.document.schema_version, "terminal-license/1")
        self.public_key.verify(
            base64.b64decode(signed.signature), canonical_json_bytes(signed.document)
        )

    async def test_activation_code_is_not_part_of_the_request(self) -> None:
        response = await self.activate(activation_code="ffp_activation_code_000000")
        self.assertEqual(response.status_code, 422, response.text)

    async def test_wrong_password_has_credentials_code(self) -> None:
        response = await self.activate(password="wrong-horse-battery-staple")
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.error_code(response), "E-TRM-401-CREDENTIALS")

    async def test_refresh_rotation_is_independent_per_installation(self) -> None:
        first = (await self.activate("A")).json()["data"]
        second = (await self.activate("B")).json()["data"]

        rotated = await self.refresh(first)
        self.assertEqual(rotated.status_code, 200, rotated.text)
        self.assertNotEqual(rotated.json()["data"]["refresh_token"], first["refresh_token"])
        untouched = await self.refresh(second)
        self.assertEqual(untouched.status_code, 200, untouched.text)

    async def test_replay_within_grace_returns_identical_successor(self) -> None:
        credentials = (await self.activate()).json()["data"]
        rotated = (await self.refresh(credentials)).json()["data"]

        self.now += timedelta(seconds=30)
        replayed = await self.refresh(credentials)

        self.assertEqual(replayed.status_code, 200, replayed.text)
        self.assertEqual(replayed.json()["data"]["refresh_token"], rotated["refresh_token"])
        onward = await self.refresh(rotated)
        self.assertEqual(onward.status_code, 200, onward.text)

    async def test_replay_after_grace_revokes_whole_family(self) -> None:
        credentials = (await self.activate()).json()["data"]
        rotated = (await self.refresh(credentials)).json()["data"]

        self.now += timedelta(seconds=31)
        replayed = await self.refresh(credentials)
        successor = await self.refresh(rotated)

        self.assertEqual(replayed.status_code, 401)
        self.assertEqual(self.error_code(replayed), "E-TRM-401-REFRESH-REPLAYED")
        self.assertEqual(replayed.json()["error"]["action"], "REACTIVATE_TERMINAL")
        self.assertEqual(self.error_code(successor), "E-TRM-401-REFRESH-REPLAYED")

    async def test_replay_after_successor_was_used_is_a_replay_even_in_grace(self) -> None:
        credentials = (await self.activate()).json()["data"]
        rotated = (await self.refresh(credentials)).json()["data"]
        await self.refresh(rotated)

        replayed = await self.refresh(credentials)

        self.assertEqual(self.error_code(replayed), "E-TRM-401-REFRESH-REPLAYED")

    async def test_expired_and_invalid_refresh_have_distinct_codes(self) -> None:
        credentials = (await self.activate()).json()["data"]
        unknown = await self.refresh(credentials, token="x" * 43)
        wrong_installation = await self.client.post(
            "/v1/access/terminal-refresh",
            json={
                "refresh_token": credentials["refresh_token"],
                "client_installation_id": str(uuid4()),
            },
        )
        self.now += timedelta(days=31)
        expired = await self.refresh(credentials)

        self.assertEqual(self.error_code(unknown), "E-TRM-401-REFRESH-INVALID")
        self.assertEqual(self.error_code(wrong_installation), "E-TRM-401-REFRESH-INVALID")
        self.assertEqual(self.error_code(expired), "E-TRM-401-REFRESH-EXPIRED")

    async def test_list_rename_and_revoke_release_a_seat(self) -> None:
        first = (await self.activate("A")).json()["data"]
        second = (await self.activate("B", platform="android")).json()["data"]

        renamed = await self.client.patch(
            f"/v1/access/terminals/{second['client_installation_id']}",
            headers=self.bearer(first),
            json={"terminal_name": "Gait lab"},
        )
        revoked = await self.client.post(
            f"/v1/access/terminals/{second['client_installation_id']}/revoke",
            headers=self.bearer(first),
        )
        listed = await self.client.get("/v1/access/terminals", headers=self.bearer(first))
        revoked_refresh = await self.refresh(second)
        revoked_manage = await self.client.get(
            "/v1/access/terminals", headers=self.bearer(second)
        )
        third = await self.activate("C")

        self.assertEqual(renamed.json()["data"]["terminal_name"], "Gait lab")
        self.assertEqual(revoked.json()["data"]["status"], "REVOKED")
        listing = listed.json()["data"]
        self.assertEqual((listing["seats"], listing["seats_used"]), (2, 1))
        self.assertEqual(
            {row["terminal_name"]: row["status"] for row in listing["terminals"]},
            {"A": "ACTIVE", "Gait lab": "REVOKED"},
        )
        self.assertEqual(revoked_refresh.status_code, 401)
        self.assertEqual(self.error_code(revoked_refresh), "E-TRM-401-REVOKED")
        self.assertEqual(self.error_code(revoked_manage), "E-TRM-401-REVOKED")
        self.assertEqual(third.status_code, 201, third.text)

    async def test_unknown_terminal_management_is_not_found(self) -> None:
        first = (await self.activate("A")).json()["data"]
        response = await self.client.post(
            f"/v1/access/terminals/{uuid4()}/revoke", headers=self.bearer(first)
        )
        self.assertEqual(response.status_code, 404)

    async def test_reactivating_the_same_installation_keeps_one_seat(self) -> None:
        installation = str(uuid4())
        first = (await self.activate("A", client_installation_id=installation)).json()["data"]
        again = await self.activate("A2", client_installation_id=installation)
        other = await self.activate("B")
        stale = await self.refresh(first)

        self.assertEqual(again.status_code, 201, again.text)
        self.assertEqual(other.status_code, 201, other.text)
        self.assertEqual(self.error_code(stale), "E-TRM-401-REFRESH-INVALID")

    async def test_installation_owned_by_another_account_conflicts(self) -> None:
        installation = str(uuid4())
        await self.activate(client_installation_id=installation)
        other_account, other_license = await self._active_account(
            "Other Clinic", "other-clinic", "usb-serial-0123456789abcdef0124"
        )
        await self.repository.set_terminal_seats(
            license_id=other_license, seats=1, changed_at=self.now
        )

        response = await self.activate(
            account_name=other_account, client_installation_id=installation
        )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(self.error_code(response), "E-TRM-409-INSTALLATION-CONFLICT")

    async def test_inactive_license_rejects_activation(self) -> None:
        current = await self.repository.license(self.license_id)
        await self.repository.replace_license(
            license_id=self.license_id,
            expected_version=current.version,
            status=LicenseState.SUSPENDED,
            issued_at=self.now,
            valid_until=current.valid_until,
            key_id=current.key_id,
            document_json=current.document_json,
            signature=current.signature,
        )
        response = await self.activate()
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.error_code(response), "E-TRM-403-LICENSE-INACTIVE")

    async def test_zero_seats_rejects_activation(self) -> None:
        await self.repository.set_terminal_seats(
            license_id=self.license_id, seats=0, changed_at=self.now
        )
        response = await self.activate()
        self.assertEqual(self.error_code(response), "E-TRM-409-SEAT-LIMIT")

    async def test_platform_seat_change_requires_write_role_and_is_audited(self) -> None:
        from techflex_cloud_foundation.server.access_control.platform_service import (
            PlatformAuthorizationDenied,
        )

        def operator(role):
            return PlatformAccessContext(
                platform_identity_id=uuid4(), roles=frozenset({role}), token_version=1,
                expires_at=self.now + timedelta(minutes=15),
            )

        with self.assertRaises(PlatformAuthorizationDenied):
            await self.platform.set_terminal_seats(
                operator(PlatformRole.SUPPORT), self.license_id, 5
            )
        updated = await self.platform.set_terminal_seats(
            operator(PlatformRole.OPERATIONS), self.license_id, 5
        )
        events = await self.repository.audit_events()

        self.assertEqual(updated.terminal_seats, 5)
        self.assertEqual(events[-1].action, "license.terminal_seats")
        self.assertIn(("previous_seats", "2"), events[-1].details)

    async def test_operations_revoke_frees_a_seat_held_by_a_dead_terminal(self) -> None:
        from techflex_cloud_foundation.server.access_control.platform_service import (
            PlatformAuthorizationDenied,
        )

        def operator(role):
            return PlatformAccessContext(
                platform_identity_id=uuid4(), roles=frozenset({role}), token_version=1,
                expires_at=self.now + timedelta(minutes=15),
            )

        lost = (await self.activate("Lost phone")).json()["data"]
        await self.activate("Desk")
        # Refresh family dies after 30 idle days; the terminal still holds its seat.
        self.now += timedelta(days=31)
        self.assertEqual(self.error_code(await self.refresh(lost)), "E-TRM-401-REFRESH-EXPIRED")
        self.assertEqual(self.error_code(await self.activate("New")), "E-TRM-409-SEAT-LIMIT")

        with self.assertRaises(PlatformAuthorizationDenied):
            await self.platform.revoke_terminal(
                operator(PlatformRole.SUPPORT), UUID(lost["client_installation_id"]),
                reason_code="DEVICE_LOST",
            )
        listed = await self.platform.list_terminals(
            operator(PlatformRole.OPERATIONS), self.license_id
        )
        revoked = await self.platform.revoke_terminal(
            operator(PlatformRole.OPERATIONS), UUID(lost["client_installation_id"]),
            reason_code="DEVICE_LOST",
        )
        events = await self.repository.audit_events()

        self.assertEqual({row.terminal_name for row in listed}, {"Lost phone", "Desk"})
        self.assertEqual(revoked.status, "REVOKED")
        self.assertEqual(events[-1].action, "terminal.revoke")
        self.assertIn(("reason_code", "DEVICE_LOST"), events[-1].details)
        self.assertEqual((await self.activate("New")).status_code, 201)

    async def test_terminal_token_is_not_a_tenant_token(self) -> None:
        credentials = (await self.activate()).json()["data"]
        response = await self.client.get("/v1/access/license", headers=self.bearer(credentials))
        self.assertEqual(response.status_code, 401)


if __name__ == "__main__":
    unittest.main()


class TerminalContractVectorReplayTests(_TerminalApiFixture):
    """Every published RAY-656 vector scenario holds against the implementation."""

    async def test_refresh_rotation_vectors(self) -> None:
        from techflex_cloud_foundation.server.contract_export import build_vectors

        start = self.now
        for scenario in build_vectors()["terminal"]["refresh_rotation"]["scenarios"]:
            with self.subTest(scenario["name"]):
                self.now = start
                credentials = (await self.activate(scenario["name"][:60])).json()["data"]
                successor = (await self.refresh(credentials)).json()["data"]
                if scenario["successor_used"]:
                    await self.refresh(successor)
                if scenario.get("revoke_first"):
                    await self.client.post(
                        f"/v1/access/terminals/{credentials['client_installation_id']}/revoke",
                        headers=self.bearer(successor),
                    )
                self.now = start + timedelta(seconds=scenario["elapsed_seconds"])
                token = {
                    "original": credentials["refresh_token"],
                    "successor": successor["refresh_token"],
                    "unknown": "u" * 43,
                }[scenario["replay"]]
                response = await self.refresh(credentials, token=token)
                expect = scenario["expect"]
                self.assertEqual(response.status_code, expect["http_status"], response.text)
                if "code" in expect:
                    self.assertEqual(self.error_code(response), expect["code"])
                if expect.get("refresh_token") == "same_as_successor":
                    self.assertEqual(
                        response.json()["data"]["refresh_token"], successor["refresh_token"]
                    )
                if "successor_code" in expect:
                    self.assertEqual(
                        self.error_code(await self.refresh(successor)), expect["successor_code"]
                    )
                # Free the seat for the next scenario.
                await self.repository.revoke_terminal(
                    tenant_id=UUID(credentials["tenant_id"]),
                    account_id=UUID(credentials["account_id"]),
                    client_installation_id=UUID(credentials["client_installation_id"]),
                    revoked_at=self.now,
                )

    async def test_seat_vectors(self) -> None:
        from techflex_cloud_foundation.server.contract_export import build_vectors

        for scenario in build_vectors()["terminal"]["seats"]["scenarios"]:
            with self.subTest(scenario["name"]):
                for row in await self.repository.terminals_for_account(
                    tenant_id=self._tenant_id, account_id=self._account_id
                ):
                    await self.repository.revoke_terminal(
                        tenant_id=row.tenant_id, account_id=row.account_id,
                        client_installation_id=row.client_installation_id,
                        revoked_at=self.now,
                    )
                await self.repository.set_terminal_seats(
                    license_id=self.license_id, seats=scenario["seats"], changed_at=self.now
                )
                active = [
                    (await self.activate(f"seat-{index}")).json()["data"]
                    for index in range(scenario["active"])
                ]
                if scenario.get("revoke_first"):
                    await self.client.post(
                        f"/v1/access/terminals/{active[0]['client_installation_id']}/revoke",
                        headers=self.bearer(active[-1]),
                    )
                overrides = (
                    {"client_installation_id": active[0]["client_installation_id"]}
                    if scenario.get("same_installation") else {}
                )
                response = await self.activate("seat-next", **overrides)
                self.assertEqual(response.status_code, scenario["expect"]["http_status"], response.text)
                if "code" in scenario["expect"]:
                    self.assertEqual(self.error_code(response), scenario["expect"]["code"])

    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        probe = (await self.activate("probe")).json()["data"]
        self._tenant_id = UUID(probe["tenant_id"])
        self._account_id = UUID(probe["account_id"])
        await self.repository.revoke_terminal(
            tenant_id=self._tenant_id, account_id=self._account_id,
            client_installation_id=UUID(probe["client_installation_id"]),
            revoked_at=self.now,
        )
