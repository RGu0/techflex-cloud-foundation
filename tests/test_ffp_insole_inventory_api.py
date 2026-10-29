"""RAY-778 R1 institutional insole inventory API behaviour and vector replay."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta, timezone
import random
import unittest
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import PlatformRole, ProvisionTenantRequest
from techflex_cloud_foundation.contracts.insole_inventory import InsoleRecord
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
from techflex_cloud_foundation.server.contract_export import build_vectors
from techflex_cloud_foundation.server.insole_inventory.repository import (
    InMemoryInsoleInventoryRepository,
)
from techflex_cloud_foundation.server.insole_inventory.service import (
    InsoleInventoryService,
    encode_cursor,
)

LOGIN_KEY = b"login-lookup-key-must-contain-32-bytes"
ACTIVATION_KEY = b"activation-key-must-contain-at-least-32-bytes"
TOKEN_SECRET = b"tenant-token-secret-must-be-at-least-32-bytes"
PASSWORD = "correct-horse-battery-staple"
VECTORS = build_vectors()["insole_inventory"]


def _iso(moment: datetime) -> str:
    return moment.isoformat().replace("+00:00", "Z")


class _InsoleApiFixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # Tokens are issued with this clock but verified against the real one,
        # so it must track the wall clock; readings sit an hour before it.
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.reading_base = self.now - timedelta(hours=1)
        self.repository = InMemoryAccessRepository()
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
        self.platform = PlatformProvisioningService(
            self.repository,
            login_lookup_hmac_key=LOGIN_KEY,
            activation_hmac_key=ACTIVATION_KEY,
            license_signer=signer,
            now=lambda: self.now,
        )
        self.terminal_access = TerminalAccessService(
            self.repository,
            login_lookup_hmac_key=LOGIN_KEY,
            terminal_tokens=terminal_tokens,
            refresh_tokens=TerminalRefreshTokenFactory(
                digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
            ),
            license_signer=signer,
            now=lambda: self.now,
        )
        self.inventory = InMemoryInsoleInventoryRepository()
        app = create_app(
            ServiceContainer(
                tenant_access=TenantAuthenticationService(
                    self.repository,
                    login_lookup_hmac_key=LOGIN_KEY,
                    activation_hmac_key=ACTIVATION_KEY,
                    tenant_tokens=tenant_tokens,
                    refresh_tokens=RefreshTokenFactory(
                        digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
                    ),
                    license_signer=signer,
                    now=lambda: self.now,
                ),
                tenant_tokens=tenant_tokens,
                terminal_access=self.terminal_access,
                terminal_tokens=terminal_tokens,
                insole_inventory=InsoleInventoryService(
                    self.inventory, self.repository, now=lambda: self.now
                ),
            )
        )
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")
        clinic = await self._account("Seed Clinic", "seed-clinic", "usb-serial-0123456789abcdef0123")
        other = await self._account("Other Clinic", "other-clinic", "usb-serial-fedcba98765432100123")
        self.terminal_a = await self._terminal(clinic, "Front desk")
        self.terminal_b = await self._terminal(clinic, "Gait lab")
        self.foreign = await self._terminal(other, "Elsewhere")

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def _account(self, tenant: str, account: str, hardware: str) -> str:
        operator = PlatformAccessContext(
            platform_identity_id=uuid4(),
            roles=frozenset({PlatformRole.OPERATIONS}),
            token_version=1,
            expires_at=self.now + timedelta(minutes=15),
        )
        provisioned = await self.platform.provision_tenant(
            operator,
            ProvisionTenantRequest(
                tenant_name=tenant, account_name=account, hardware_id=hardware,
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
        await self.repository.set_terminal_seats(
            license_id=provisioned.license_id, seats=5, changed_at=self.now
        )
        return provisioned.account_name

    async def _terminal(self, account_name: str, name: str) -> dict:
        response = await self.client.post(
            "/v1/access/terminal-activate",
            json={
                "account_name": account_name, "password": PASSWORD, "terminal_name": name,
                "client_installation_id": str(uuid4()), "platform": "android",
            },
        )
        assert response.status_code == 201, response.text
        return response.json()["data"]

    @staticmethod
    def bearer(terminal: dict) -> dict[str, str]:
        return {"Authorization": f"Bearer {terminal['access_token']}"}

    async def register(self, terminal: dict, body: dict, key: str | None = None):
        headers = {**self.bearer(terminal), "Idempotency-Key": key or str(uuid4())}
        return await self.client.post("/v1/inventory/insoles", json=body, headers=headers)

    async def report(self, terminal: dict, insole_id: str, body: dict):
        return await self.client.post(
            f"/v1/inventory/insoles/{insole_id}/reports", json=body, headers=self.bearer(terminal)
        )

    async def retire(self, terminal: dict, insole_id: str):
        return await self.client.post(
            f"/v1/inventory/insoles/{insole_id}/retire", headers=self.bearer(terminal)
        )

    async def download(self, terminal: dict, cursor: str | None = None, limit: int | None = None):
        params = {}
        if cursor is not None:
            params["cursor"] = cursor
        if limit is not None:
            params["limit"] = limit
        return await self.client.get(
            "/v1/inventory/insoles", params=params, headers=self.bearer(terminal)
        )

    async def download_all(self, terminal: dict, cursor: str | None = None) -> tuple[list, str]:
        items: list[dict] = []
        while True:
            response = await self.download(terminal, cursor)
            assert response.status_code == 200, response.text
            data = response.json()["data"]
            items.extend(data["items"])
            cursor = data["next_cursor"]
            if not data["has_more"]:
                return items, cursor

    async def registered(self, terminal: dict | None = None, body: dict | None = None) -> dict:
        response = await self.register(terminal or self.terminal_a,
                                       body or VECTORS["registration_request"])
        assert response.status_code == 201, response.text
        return response.json()["data"]["insole"]

    @staticmethod
    def code(response) -> str:
        return response.json()["error"]["code"]


class InsoleRegistrationTests(_InsoleApiFixture):
    async def test_terminal_a_registers_and_terminal_b_downloads_battery_and_state(self) -> None:
        insole = await self.registered(self.terminal_a)
        reported = await self.report(self.terminal_a, insole["insole_id"], VECTORS["report_request"])
        self.assertEqual(reported.status_code, 200, reported.text)

        items, _ = await self.download_all(self.terminal_b)

        self.assertEqual(len(items), 1)
        pair = items[0]
        InsoleRecord.model_validate(pair)
        self.assertEqual(pair["institution_number"], "A-001")
        self.assertEqual(pair["size"], 38)
        self.assertEqual(pair["state"], "in_use")
        self.assertEqual(pair["left"]["battery"]["millivolts"], 3987)
        self.assertEqual(pair["left"]["battery"]["percent"], 82)
        self.assertEqual(pair["right"]["battery"]["millivolts"], 3712)
        self.assertEqual(pair["right"]["battery"]["percent"], 55)
        self.assertEqual(pair["left"]["battery"]["read_at"], "2026-10-20T08:00:00Z")
        self.assertEqual(pair["left"]["identity"], VECTORS["registration_request"]["left"]["identity"])
        self.assertEqual(pair["right"]["firmware_version"], "1.4.2")
        self.assertEqual(pair["holder"], {
            "client_installation_id": self.terminal_a["client_installation_id"],
            "terminal_name": "Front desk",
        })
        self.assertEqual(pair["registered_by_client_installation_id"],
                         self.terminal_a["client_installation_id"])

    async def test_new_pair_is_available_without_state_time_or_battery(self) -> None:
        insole = await self.registered()
        self.assertEqual(insole["state"], "available")
        self.assertIsNone(insole["state_observed_at"])
        self.assertIsNone(insole["holder"])
        self.assertIsNone(insole["left"]["battery"])
        self.assertIsNone(insole["right"]["battery"])

    async def test_idempotent_replay_vectors(self) -> None:
        vector = VECTORS["registration"]
        key = vector["request_headers"]["Idempotency-Key"]
        body = VECTORS["registration_request"]
        first = await self.register(self.terminal_a, body, key)
        replay = await self.register(self.terminal_a, body, key)

        self.assertEqual(first.status_code, vector["initial_status"], first.text)
        self.assertEqual(replay.status_code, vector["replay_status"], replay.text)
        self.assertIs(first.json()["data"]["idempotent_replay"], vector["initial_idempotent_replay"])
        self.assertIs(replay.json()["data"]["idempotent_replay"], vector["replay_idempotent_replay"])
        self.assertEqual(first.json()["data"]["insole"], replay.json()["data"]["insole"])

        changed = await self.register(self.terminal_a, {**body, "size": 39}, key)
        self.assertEqual(changed.status_code, 409, changed.text)
        self.assertEqual(self.code(changed), vector["same_key_different_request_error"])

    async def test_idempotency_key_is_scoped_to_the_registering_terminal(self) -> None:
        body = VECTORS["registration_request"]
        await self.register(self.terminal_a, body, "shared-key")
        other = await self.register(
            self.terminal_b, {**body, "institution_number": "A-009",
                              "left": {**body["left"], "identity": {
                                  **body["left"]["identity"], "value": "C0:FF:EE:00:00:0A"}},
                              "right": {**body["right"], "identity": {
                                  **body["right"]["identity"], "value": "C0:FF:EE:00:00:0B"}}},
            "shared-key",
        )
        self.assertEqual(other.status_code, 201, other.text)

    async def test_replay_returns_same_pair_at_its_current_revision(self) -> None:
        body = VECTORS["registration_request"]
        first = (await self.register(self.terminal_a, body, "k-1")).json()["data"]["insole"]
        await self.report(self.terminal_b, first["insole_id"], VECTORS["report_request"])
        replay = (await self.register(self.terminal_a, body, "k-1")).json()["data"]["insole"]
        self.assertEqual(replay["insole_id"], first["insole_id"])
        self.assertGreater(replay["revision"], first["revision"])
        self.assertEqual(replay["state"], "in_use")

    async def test_conflict_vectors_have_distinct_codes_and_return_existing(self) -> None:
        for scenario in VECTORS["registration"]["scenarios"]:
            with self.subTest(scenario["name"]):
                self.inventory.__init__()
                original = await self.registered(self.terminal_a)
                response = await self.register(self.terminal_b, scenario["attempt"])
                expect = scenario["expect"]
                self.assertEqual(response.status_code, expect["http_status"], response.text)
                if "code" in expect:
                    error = response.json()["error"]
                    self.assertEqual(error["code"], expect["code"])
                    existing = InsoleRecord.model_validate(error["details"]["existing"])
                    self.assertEqual(existing.institution_number,
                                     expect["existing_institution_number"])
                    self.assertEqual(str(existing.insole_id), original["insole_id"])
                    self.assertEqual(error["action"], "SHOW_EXISTING_INSOLE")
                else:
                    data = response.json()["data"]
                    self.assertIs(data["idempotent_replay"], expect["idempotent_replay"])
                    if expect.get("same_insole_id"):
                        self.assertEqual(data["insole"]["insole_id"], original["insole_id"])
        codes = {VECTORS["errors"][name]["body"]["error"]["code"]
                 for name in ("identity_registered", "number_taken")}
        self.assertEqual(len(codes), 2)

    async def test_conflict_does_not_create_a_pair_or_change_the_cursor(self) -> None:
        await self.registered()
        _, cursor = await self.download_all(self.terminal_b)
        attempt = VECTORS["registration"]["scenarios"][1]["attempt"]
        self.assertEqual((await self.register(self.terminal_b, attempt)).status_code, 409)
        items, after = await self.download_all(self.terminal_b, cursor)
        self.assertEqual((items, after), ([], cursor))

    async def test_left_and_right_must_be_different_devices(self) -> None:
        body = VECTORS["registration_request"]
        response = await self.register(self.terminal_a, {**body, "right": body["left"]})
        self.assertEqual(response.status_code, 422, response.text)

    async def test_mac_must_be_canonical(self) -> None:
        vector = VECTORS["registration"]
        body = VECTORS["registration_request"]
        for value in vector["non_canonical_mac_examples"]:
            with self.subTest(value=value):
                attempt = {**body, "institution_number": "A-100", "left": {
                    **body["left"], "identity": {**body["left"]["identity"], "value": value}}}
                response = await self.register(self.terminal_a, attempt)
                self.assertEqual(response.status_code, vector["non_canonical_mac_status"],
                                 response.text)
        serial = {**body, "left": {**body["left"], "identity": {
            "kind": "serial", "value": "sn-lower-ok", "provenance": "unknown"}}}
        self.assertEqual((await self.register(self.terminal_a, serial)).status_code, 201)

    async def test_idempotency_key_is_required(self) -> None:
        response = await self.client.post(
            "/v1/inventory/insoles", json=VECTORS["registration_request"],
            headers=self.bearer(self.terminal_a),
        )
        self.assertEqual(response.status_code, 422, response.text)


class InsoleReportMergeTests(_InsoleApiFixture):
    def _body(self, group: str, moment: datetime, value: int) -> dict:
        if group == "state":
            return {"state": {"state": "in_use" if value % 2 else "available",
                              "observed_at": _iso(moment)}}
        return {group: {"millivolts": 3000 + value, "percent": value, "read_at": _iso(moment)}}

    async def test_merge_vectors_for_every_group(self) -> None:
        base = self.reading_base
        for group in VECTORS["merge"]["granularity"]:
            for scenario in VECTORS["merge"]["scenarios"]:
                with self.subTest(group=group, scenario=scenario["name"]):
                    self.inventory.__init__()
                    insole = await self.registered()
                    if scenario["stored_offset_seconds"] is not None:
                        stored = base + timedelta(seconds=scenario["stored_offset_seconds"])
                        first = await self.report(self.terminal_a, insole["insole_id"],
                                                  self._body(group, stored, 11))
                        self.assertTrue(first.json()["data"]["applied"][group], first.text)
                    incoming = base + timedelta(seconds=scenario["incoming_offset_seconds"])
                    response = await self.report(self.terminal_b, insole["insole_id"],
                                                 self._body(group, incoming, 20))
                    self.assertEqual(response.status_code, 200, response.text)
                    data = response.json()["data"]
                    self.assertIs(data["applied"][group], scenario["expect_applied"])
                    others = {name for name in ("state", "left", "right") if name != group}
                    self.assertFalse(any(data["applied"][name] for name in others))
                    winner = 20 if scenario["expect_applied"] else 11
                    if group == "state":
                        self.assertEqual(data["insole"]["state"],
                                         "in_use" if winner % 2 else "available")
                    else:
                        self.assertEqual(data["insole"][group]["battery"]["percent"], winner)

    async def test_late_stale_offline_report_never_overwrites_newer_one(self) -> None:
        insole = await self.registered()
        newer = self.reading_base + timedelta(minutes=30)
        older = newer - timedelta(minutes=20)
        fresh = await self.report(self.terminal_a, insole["insole_id"], {
            "state": {"state": "in_use", "observed_at": _iso(newer)},
            "left": {"millivolts": 3900, "percent": 75, "read_at": _iso(newer)},
        })
        self.assertEqual(fresh.status_code, 200, fresh.text)
        stale = await self.report(self.terminal_b, insole["insole_id"], {
            "state": {"state": "available", "observed_at": _iso(older)},
            "left": {"millivolts": 4100, "percent": 96, "read_at": _iso(older)},
            "right": {"millivolts": 4050, "percent": 92, "read_at": _iso(older)},
        })
        data = stale.json()["data"]
        self.assertEqual(data["applied"], {"state": False, "left": False, "right": True})
        self.assertEqual(data["insole"]["state"], "in_use")
        self.assertEqual(data["insole"]["holder"]["client_installation_id"],
                         self.terminal_a["client_installation_id"])
        self.assertEqual(data["insole"]["left"]["battery"]["millivolts"], 3900)
        self.assertEqual(data["insole"]["right"]["battery"]["millivolts"], 4050)
        self.assertEqual(data["insole"]["right"]["battery"]["reported_by_client_installation_id"],
                         self.terminal_b["client_installation_id"])

    async def test_concurrent_reports_converge_on_the_newest_reading(self) -> None:
        insole = await self.registered()
        base = self.reading_base
        offsets = list(range(40))
        random.Random(778).shuffle(offsets)
        terminals = (self.terminal_a, self.terminal_b)
        await asyncio.gather(*(
            self.report(terminals[index % 2], insole["insole_id"], {
                "left": {"millivolts": 3000 + offset, "percent": offset,
                         "read_at": _iso(base + timedelta(seconds=offset))},
                "state": {"state": "in_use", "observed_at": _iso(base + timedelta(seconds=offset))},
            })
            for index, offset in enumerate(offsets)
        ))
        items, _ = await self.download_all(self.terminal_b)
        self.assertEqual(items[0]["left"]["battery"]["millivolts"], 3039)
        self.assertEqual(items[0]["state_observed_at"], _iso(base + timedelta(seconds=39)))

    async def test_holder_is_set_only_while_in_use(self) -> None:
        insole = await self.registered()
        base = self.reading_base
        taken = await self.report(self.terminal_b, insole["insole_id"],
                                  {"state": {"state": "in_use", "observed_at": _iso(base)}})
        self.assertEqual(taken.json()["data"]["insole"]["holder"]["terminal_name"], "Gait lab")
        for offset, state in ((1, "unreturned_data"), (2, "available")):
            released = await self.report(self.terminal_b, insole["insole_id"], {"state": {
                "state": state, "observed_at": _iso(base + timedelta(seconds=offset))}})
            self.assertEqual(released.json()["data"]["insole"]["state"], state)
            self.assertIsNone(released.json()["data"]["insole"]["holder"])

    async def test_not_applied_report_keeps_the_revision(self) -> None:
        insole = await self.registered()
        moment = self.reading_base
        body = {"left": {"millivolts": 3900, "percent": 75, "read_at": _iso(moment)}}
        first = (await self.report(self.terminal_a, insole["insole_id"], body)).json()["data"]
        again = (await self.report(self.terminal_a, insole["insole_id"], body)).json()["data"]
        self.assertEqual(again["insole"]["revision"], first["insole"]["revision"])
        self.assertFalse(again["applied"]["left"])

    async def test_offsets_are_compared_as_instants_and_returned_in_utc(self) -> None:
        insole = await self.registered()
        offset = self.reading_base.astimezone(timezone(timedelta(hours=8))).isoformat()
        first = await self.report(self.terminal_a, insole["insole_id"], {
            "left": {"millivolts": 3900, "percent": 75, "read_at": offset}})
        self.assertEqual(first.json()["data"]["insole"]["left"]["battery"]["read_at"],
                         _iso(self.reading_base))
        same = await self.report(self.terminal_b, insole["insole_id"], {
            "left": {"millivolts": 3000, "percent": 10, "read_at": _iso(self.reading_base)}})
        self.assertFalse(same.json()["data"]["applied"]["left"])

    async def test_reading_too_far_in_the_future_is_rejected(self) -> None:
        insole = await self.registered()
        skew = VECTORS["merge"]["max_future_skew_seconds"]
        allowed = self.now + timedelta(seconds=skew)
        ok = await self.report(self.terminal_a, insole["insole_id"], {
            "left": {"millivolts": 3900, "percent": 75, "read_at": _iso(allowed)}})
        self.assertEqual(ok.status_code, 200, ok.text)
        ahead = await self.report(self.terminal_a, insole["insole_id"], {
            "right": {"millivolts": 3900, "percent": 75,
                      "read_at": _iso(allowed + timedelta(seconds=1))}})
        self.assertEqual(ahead.status_code, 422, ahead.text)
        self.assertEqual(self.code(ahead), VECTORS["errors"]["reading_in_future"]["body"]["error"]["code"])

    async def test_report_contract_validation(self) -> None:
        insole = await self.registered()
        moment = _iso(self.reading_base)
        for body in (
            {},
            {"state": {"state": "retired", "observed_at": moment}},
            {"left": {"millivolts": 3900, "read_at": moment}},
            {"left": {"millivolts": 3900, "percent": 101, "read_at": moment}},
            {"left": {"millivolts": 3900, "percent": 50, "read_at": "2026-10-20T08:00:00"}},
        ):
            with self.subTest(body=body):
                response = await self.report(self.terminal_a, insole["insole_id"], body)
                self.assertEqual(response.status_code, 422, response.text)

    async def test_unknown_insole_is_not_found(self) -> None:
        response = await self.report(self.terminal_a, str(uuid4()), VECTORS["report_request"])
        self.assertEqual(response.status_code, 404, response.text)
        self.assertEqual(self.code(response), "E-API-404")


class InsoleRetireAndDownloadTests(_InsoleApiFixture):
    async def test_any_terminal_retires_and_retirement_is_downloaded_not_deleted(self) -> None:
        insole = await self.registered(self.terminal_a)
        _, cursor = await self.download_all(self.terminal_a)

        retired = await self.retire(self.terminal_b, insole["insole_id"])
        self.assertEqual(retired.status_code, 200, retired.text)
        data = retired.json()["data"]
        self.assertFalse(data["idempotent_replay"])
        self.assertEqual(data["insole"]["state"], "retired")
        self.assertEqual(data["insole"]["retired_by_client_installation_id"],
                         self.terminal_b["client_installation_id"])

        changed, _ = await self.download_all(self.terminal_a, cursor)
        self.assertEqual([(row["insole_id"], row["state"]) for row in changed],
                         [(insole["insole_id"], "retired")])
        everything, _ = await self.download_all(self.terminal_a)
        self.assertEqual(len(everything), 1)
        self.assertEqual(everything[0]["institution_number"], "A-001")

    async def test_retire_is_idempotent_and_final(self) -> None:
        insole = await self.registered()
        first = (await self.retire(self.terminal_a, insole["insole_id"])).json()["data"]
        again = await self.retire(self.terminal_b, insole["insole_id"])
        self.assertEqual(again.status_code, 200)
        self.assertTrue(again.json()["data"]["idempotent_replay"])
        self.assertEqual(again.json()["data"]["insole"], first["insole"])

        report = await self.report(self.terminal_a, insole["insole_id"], VECTORS["report_request"])
        self.assertEqual(report.status_code, 409, report.text)
        self.assertEqual(self.code(report), VECTORS["merge"]["retired_reports_error"])

        attempt = {**VECTORS["registration_request"], "institution_number": "A-777"}
        reuse = await self.register(self.terminal_b, attempt)
        self.assertEqual(self.code(reuse), "E-INV-409-IDENTITY-REGISTERED")
        self.assertEqual(reuse.json()["error"]["details"]["existing"]["state"], "retired")

    async def test_cursor_pages_in_revision_order_and_moves_changed_pairs_forward(self) -> None:
        body = VECTORS["registration_request"]
        ids = []
        for index in range(5):
            pair = await self.registered(body={
                **body, "institution_number": f"B-{index}",
                "left": {**body["left"], "identity": {**body["left"]["identity"], "kind": "serial",
                                                      "value": f"L-{index}"}},
                "right": {**body["right"], "identity": {**body["right"]["identity"], "kind": "serial",
                                                        "value": f"R-{index}"}}})
            ids.append(pair["insole_id"])
        first = (await self.download(self.terminal_b, limit=2)).json()["data"]
        self.assertTrue(first["has_more"])
        self.assertEqual([row["insole_id"] for row in first["items"]], ids[:2])
        await self.report(self.terminal_a, ids[0], VECTORS["report_request"])
        rest, cursor = await self.download_all(self.terminal_b, first["next_cursor"])
        self.assertEqual([row["insole_id"] for row in rest], ids[2:] + ids[:1])
        revisions = [row["revision"] for row in first["items"] + rest]
        self.assertEqual(revisions, sorted(revisions))
        empty = (await self.download(self.terminal_b, cursor)).json()["data"]
        self.assertEqual(empty, {"items": [], "next_cursor": cursor, "has_more": False})

    async def test_download_vectors(self) -> None:
        vector = VECTORS["download"]
        invalid = await self.download(self.terminal_a, vector["invalid_cursor_example"])
        self.assertEqual(invalid.status_code, 400, invalid.text)
        self.assertEqual(self.code(invalid), vector["invalid_cursor_error"])
        overflow = await self.download(self.terminal_a, vector["out_of_range_cursor_example"])
        self.assertEqual(overflow.status_code, 400, overflow.text)
        self.assertEqual(self.code(overflow), vector["invalid_cursor_error"])
        for limit in (0, vector["max_limit"] + 1):
            response = await self.download(self.terminal_a, limit=limit)
            self.assertEqual(response.status_code, 422, response.text)
        empty = (await self.download(self.terminal_a)).json()["data"]
        self.assertEqual(empty["next_cursor"], encode_cursor(0))
        self.assertEqual((await self.download(self.terminal_a, "")).status_code, 200)

    async def test_default_page_limit(self) -> None:
        body = VECTORS["registration_request"]
        for index in range(VECTORS["download"]["default_limit"] + 1):
            await self.registered(body={
                **body, "institution_number": f"C-{index}",
                "left": {**body["left"], "identity": {**body["left"]["identity"], "kind": "serial",
                                                      "value": f"L-{index}"}},
                "right": {**body["right"], "identity": {**body["right"]["identity"], "kind": "serial",
                                                        "value": f"R-{index}"}}})
        page = (await self.download(self.terminal_a)).json()["data"]
        self.assertEqual(len(page["items"]), VECTORS["download"]["default_limit"])
        self.assertTrue(page["has_more"])


class InsoleTenantIsolationTests(_InsoleApiFixture):
    async def test_other_institution_cannot_see_or_change_the_pair(self) -> None:
        insole = await self.registered(self.terminal_a)
        items, _ = await self.download_all(self.foreign)
        self.assertEqual(items, [])
        expect = VECTORS["authentication"]["other_tenant_insole"]
        for response in (
            await self.report(self.foreign, insole["insole_id"], VECTORS["report_request"]),
            await self.retire(self.foreign, insole["insole_id"]),
        ):
            self.assertEqual(response.status_code, expect["http_status"], response.text)
            self.assertEqual(self.code(response), expect["code"])
        unchanged, _ = await self.download_all(self.terminal_b)
        self.assertEqual(unchanged[0]["state"], "available")
        self.assertEqual(unchanged[0]["revision"], insole["revision"])

    async def test_identities_and_numbers_are_unique_per_institution_only(self) -> None:
        mine = await self.registered(self.terminal_a)
        theirs = await self.register(self.foreign, VECTORS["registration_request"])
        self.assertEqual(theirs.status_code, 201, theirs.text)
        self.assertNotEqual(theirs.json()["data"]["insole"]["insole_id"], mine["insole_id"])
        self.assertEqual(theirs.json()["data"]["insole"]["revision"], 1)

    async def test_revoked_terminal_is_rejected(self) -> None:
        insole = await self.registered(self.terminal_a)
        revoked = await self.client.post(
            f"/v1/access/terminals/{self.terminal_b['client_installation_id']}/revoke",
            headers=self.bearer(self.terminal_a),
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        expect = VECTORS["authentication"]["revoked_terminal"]
        for response in (
            await self.download(self.terminal_b),
            await self.register(self.terminal_b, VECTORS["registration_request"]),
            await self.report(self.terminal_b, insole["insole_id"], VECTORS["report_request"]),
            await self.retire(self.terminal_b, insole["insole_id"]),
        ):
            self.assertEqual(response.status_code, expect["http_status"], response.text)
            self.assertEqual(self.code(response), expect["code"])

    async def test_tenant_token_and_missing_token_are_rejected(self) -> None:
        missing = await self.client.get("/v1/inventory/insoles")
        self.assertEqual(missing.status_code, 422)
        forged = await self.client.get(
            "/v1/inventory/insoles", headers={"Authorization": "Bearer not-a-token"}
        )
        self.assertEqual(forged.status_code, 401, forged.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
