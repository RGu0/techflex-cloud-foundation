"""RAY-802 R1 terminal diagnostic upload, support access, purge and vector replay."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path
import unittest
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import PlatformRole, ProvisionTenantRequest
from techflex_cloud_foundation.contracts.terminal_diagnostics import (
    DIAGNOSTICS_MAX_BYTES,
    DiagnosticSummary,
    DiagnosticUploadResponse,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.platform_iam import PlatformIdentityService
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
from techflex_cloud_foundation.server.terminal_diagnostics.object_store import (
    DiagnosticPackageStore,
)
from techflex_cloud_foundation.server.terminal_diagnostics.repository import (
    InMemoryDiagnosticRepository,
)
from techflex_cloud_foundation.server.terminal_diagnostics.service import TerminalDiagnosticsService

LOGIN_KEY = b"login-lookup-key-must-contain-32-bytes"
ACTIVATION_KEY = b"activation-key-must-contain-at-least-32-bytes"
TOKEN_SECRET = b"tenant-token-secret-must-be-at-least-32-bytes"
PASSWORD = "correct-horse-battery-staple"
VECTORS = build_vectors()["terminal_diagnostics"]
FIXTURE = Path(__file__).parent / "fixtures" / "ffp_terminal_diagnostics" / "ray910_export.ndjson"
FIXTURE_IDS = ("5a1f0c3e-7b2d-4e8a-9c6f-2d4b8e1a0f37", "c3d9e2f1-6a4b-4f0c-8e7d-9b2a1c0d3e5f")


def package(lines: list[str], terminal: dict) -> bytes:
    return "".join(
        line.replace("{tenant_id}", terminal["tenant_id"]).replace(
            "{terminal_id}", terminal["client_installation_id"]) + "\n"
        for line in lines
    ).encode("utf-8")


def fixture_for(terminal: dict) -> bytes:
    tenant_id, terminal_id = FIXTURE_IDS
    return FIXTURE.read_bytes().replace(
        tenant_id.encode(), terminal["tenant_id"].encode()
    ).replace(terminal_id.encode(), terminal["client_installation_id"].encode())


class _DiagnosticsApiFixture(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        # Tokens are verified against the wall clock; the service clock is
        # moved separately to reach expiry.
        self.now = datetime.now(UTC).replace(microsecond=0)
        self.repository = InMemoryAccessRepository()
        private_key = Ed25519PrivateKey.generate()
        signer = LicenseDocumentSigner(
            private_key=private_key,
            key_id="license/2-key-1",
            public_keys={"license/2-key-1": private_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw)},
        )
        tenant_tokens = TenantAccessTokenIssuer(secret=TOKEN_SECRET, key_id="tenant/1")
        terminal_tokens = TerminalAccessTokenIssuer(secret=TOKEN_SECRET, key_id="tenant/1")
        self.terminal_tokens = terminal_tokens
        platform_tokens = PlatformAccessTokenIssuer(
            secret=b"platform-token-secret-must-be-at-least-32-bytes", key_id="platform/1")
        self.identities = PlatformIdentityService(
            self.repository,
            login_lookup_hmac_key=b"platform-login-lookup-key-at-least-32-bytes",
            token_issuer=platform_tokens,
            refresh_tokens=RefreshTokenFactory(
                digest_key=b"platform-refresh-key-must-be-at-least-32-bytes"),
            now=lambda: self.now,
        )
        self.platform = PlatformProvisioningService(
            self.repository, login_lookup_hmac_key=LOGIN_KEY,
            activation_hmac_key=ACTIVATION_KEY, license_signer=signer,
            now=lambda: self.now,
        )
        self.terminal_access = TerminalAccessService(
            self.repository, login_lookup_hmac_key=LOGIN_KEY, terminal_tokens=terminal_tokens,
            refresh_tokens=TerminalRefreshTokenFactory(
                digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"),
            license_signer=signer, now=lambda: self.now,
        )
        self.objects = InMemoryObjectStore()
        self.diagnostics = InMemoryDiagnosticRepository()
        self.service = TerminalDiagnosticsService(
            self.diagnostics, DiagnosticPackageStore(self.objects), self.repository,
            now=lambda: self.now)
        app = create_app(ServiceContainer(
            tenant_access=TenantAuthenticationService(
                self.repository, login_lookup_hmac_key=LOGIN_KEY,
                activation_hmac_key=ACTIVATION_KEY, tenant_tokens=tenant_tokens,
                refresh_tokens=RefreshTokenFactory(
                    digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"),
                license_signer=signer, now=lambda: self.now,
            ),
            tenant_tokens=tenant_tokens,
            terminal_access=self.terminal_access,
            terminal_tokens=terminal_tokens,
            platform_identities=self.identities,
            platform_tokens=platform_tokens,
            terminal_diagnostics=self.service,
        ))
        self.client = AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test")
        owner = await self.identities.bootstrap_owner(
            login_name="platform-owner", display_name="Owner", password=PASSWORD)
        owner_context = await self.identities.verify_access_token(owner.access_token)
        self.platform_tokens = {"owner": owner.access_token}
        for name, role in (("support", PlatformRole.SUPPORT),
                           ("engineer", PlatformRole.ENGINEER),
                           ("operations", PlatformRole.OPERATIONS)):
            login = await self.identities.create_identity(
                owner_context, login_name=f"platform-{name}", display_name=name,
                password=PASSWORD, roles=(role,))
            self.platform_tokens[name] = login.access_token
        clinic, self.clinic_tenant_token = await self._account(
            "Seed Clinic", "seed-clinic", "usb-serial-0123456789abcdef0123")
        other, _ = await self._account(
            "Other Clinic", "other-clinic", "usb-serial-fedcba98765432100123")
        self.terminal_a = await self._terminal(clinic, "Front desk")
        self.terminal_b = await self._terminal(clinic, "Gait lab")
        self.foreign = await self._terminal(other, "Elsewhere")
        self.tenant_id = self.terminal_a["tenant_id"]

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

    async def _account(self, tenant: str, account: str, hardware: str) -> tuple[str, str]:
        operator = await self.identities.verify_access_token(self.platform_tokens["owner"])
        provisioned = await self.platform.provision_tenant(operator, ProvisionTenantRequest(
            tenant_name=tenant, account_name=account, hardware_id=hardware,
            license_period_months=12))
        activated = await self.client.post("/v1/access/activate", json={
            "account_name": provisioned.account_name,
            "activation_code": provisioned.activation_code,
            "password": PASSWORD, "password_confirmation": PASSWORD,
            "hardware_id": provisioned.hardware_id,
            "client_installation_id": str(uuid4()),
        })
        assert activated.status_code == 201, activated.text
        await self.repository.set_terminal_seats(
            license_id=provisioned.license_id, seats=5, changed_at=self.now)
        return provisioned.account_name, activated.json()["data"]["access_token"]

    async def _terminal(self, account_name: str, name: str) -> dict:
        response = await self.client.post("/v1/access/terminal-activate", json={
            "account_name": account_name, "password": PASSWORD, "terminal_name": name,
            "client_installation_id": str(uuid4()), "platform": "android",
        })
        assert response.status_code == 201, response.text
        data = response.json()["data"]
        context = self.terminal_tokens.verify(data["access_token"])
        return {**data, "tenant_id": str(context.tenant_id),
                "client_installation_id": str(context.client_installation_id)}

    @staticmethod
    def bearer(token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    async def upload(self, terminal: dict, body: bytes, *, key: str | None = None,
                     sha256: str | None = None, headers: dict | None = None):
        return await self.client.post("/v1/diagnostics", content=body, headers={
            **self.bearer(terminal["access_token"]),
            "Content-Type": "application/x-ndjson",
            "Idempotency-Key": key or str(uuid4()),
            "X-Content-SHA256": sha256 or hashlib.sha256(body).hexdigest(),
            **(headers or {}),
        })

    async def uploaded(self, terminal: dict | None = None) -> dict:
        terminal = terminal or self.terminal_a
        response = await self.upload(terminal, package(VECTORS["package"]["lines"], terminal))
        assert response.status_code == 201, response.text
        return response.json()["data"]

    async def support_get(self, path: str, *, role: str = "support",
                          ticket: str | None = "SUP-1042", token: str | None = None):
        params = {} if ticket is None else {"ticket_reference": ticket}
        return await self.client.get(
            path, params=params, headers=self.bearer(token or self.platform_tokens[role]))

    def list_path(self, tenant_id: str | None = None) -> str:
        return f"/v1/platform/tenants/{tenant_id or self.tenant_id}/diagnostics"

    def content_path(self, diagnostic_id: str, tenant_id: str | None = None) -> str:
        return f"{self.list_path(tenant_id)}/{diagnostic_id}/content"

    async def audit(self, tenant_id: str | None = None) -> list:
        return [event for event in await self.repository.audit_events(
            tenant_id=None if tenant_id is None else UUID(tenant_id))
            if event.action.startswith("diagnostics.")]

    def age(self, diagnostic_id: str, delta: timedelta) -> None:
        """Move a stored package into the past; the platform tokens stay valid."""

        record = self.diagnostics._records[UUID(diagnostic_id)]
        self.diagnostics._records[record.diagnostic_id] = replace(
            record, received_at=record.received_at - delta,
            expires_at=record.expires_at - delta)

    @staticmethod
    def code(response) -> str:
        return response.json()["error"]["code"]


class DiagnosticsVectorReplayTests(_DiagnosticsApiFixture):
    async def test_every_published_scenario(self) -> None:
        created_key = "fixture:diagnostics:replay"
        created_body = None
        revoked = await self._terminal("seed-clinic", "Revoked")
        revoke = await self.client.post(
            f"/v1/access/terminals/{revoked['client_installation_id']}/revoke",
            headers=self.bearer(self.terminal_a["access_token"]))
        self.assertEqual(revoke.status_code, 200, revoke.text)
        for scenario in VECTORS["scenarios"]:
            with self.subTest(scenario["name"]):
                terminal = revoked if scenario.get("revoke_first") else self.terminal_a
                if "size_bytes" in scenario:
                    body = b"x" * scenario["size_bytes"]
                else:
                    body = package(scenario["lines"], terminal)
                key = created_key if scenario["name"] == "created" or scenario.get(
                    "same_key") else None
                response = await self.upload(
                    terminal, body, key=key, sha256=scenario.get("declared_sha256"))
                expect = scenario["expect"]
                self.assertEqual(response.status_code, expect["http_status"], response.text)
                if "code" in expect:
                    self.assertEqual(self.code(response), expect["code"])
                if "details" in expect:
                    self.assertEqual(response.json()["error"]["details"], expect["details"])
                if scenario["name"] == "created":
                    created_body = response.json()["data"]
                    DiagnosticUploadResponse.model_validate(created_body)
                if scenario["name"] == "replay":
                    self.assertEqual(response.json()["data"], created_body)

    async def test_error_envelopes_match_the_raised_errors(self) -> None:
        too_large = await self.upload(self.terminal_a, b"x" * (DIAGNOSTICS_MAX_BYTES + 1))
        mismatch = await self.upload(
            self.terminal_a, b"{}\n", sha256="0" * 64)
        rejected = await self.upload(self.terminal_a, package(
            VECTORS["scenarios"][-1]["lines"], self.terminal_a))
        for name, response in (("too_large", too_large), ("digest_mismatch", mismatch),
                               ("content_rejected", rejected)):
            published = VECTORS["errors"][name]
            error = response.json()["error"]
            self.assertEqual(response.status_code, published["http_status"])
            for field in ("code", "retryable", "action"):
                self.assertEqual(error[field], published["body"]["error"][field])
            self.assertEqual(set(error["details"]), set(published["body"]["error"]["details"]))

    async def test_example_digest_is_reproducible(self) -> None:
        ids = VECTORS["package"]["example_ids"]
        body = package(VECTORS["package"]["lines"], {
            "tenant_id": ids["tenant_id"], "client_installation_id": ids["terminal_id"]})
        self.assertEqual(hashlib.sha256(body).hexdigest(), VECTORS["package"]["example_sha256"])
        self.assertEqual(len(body), VECTORS["package"]["example_size_bytes"])


class DiagnosticsUploadTests(_DiagnosticsApiFixture):
    async def test_created_response_and_identical_replay(self) -> None:
        body = package(VECTORS["package"]["lines"], self.terminal_a)
        first = await self.upload(self.terminal_a, body, key="k-1")
        replay = await self.upload(self.terminal_a, body, key="k-1")
        self.assertEqual(first.status_code, 201, first.text)
        self.assertEqual(replay.status_code, 200, replay.text)
        data = first.json()["data"]
        self.assertEqual(replay.json()["data"], data)
        self.assertEqual(data["format"], "gait-insole-diagnostics/1")
        self.assertEqual(data["size_bytes"], len(body))
        self.assertEqual(data["sha256"], hashlib.sha256(body).hexdigest())
        received = datetime.fromisoformat(data["received_at"])
        self.assertEqual(datetime.fromisoformat(data["expires_at"]) - received, timedelta(days=30))
        stored = self.objects._objects[f"diagnostics/{self.tenant_id}/{data['diagnostic_id']}.ndjson"]
        self.assertEqual(stored, body)
        self.assertEqual(self.objects.object_count, 1)

    async def test_same_key_other_body_conflicts_and_stores_nothing(self) -> None:
        body = package(VECTORS["package"]["lines"], self.terminal_a)
        await self.upload(self.terminal_a, body, key="k-1")
        conflict = await self.upload(self.terminal_a, body + body[-80:], key="k-1")
        self.assertEqual(conflict.status_code, 409, conflict.text)
        self.assertEqual(self.code(conflict), "E-API-409")
        self.assertEqual(self.objects.object_count, 1)

    async def test_idempotency_key_is_scoped_to_the_uploading_terminal(self) -> None:
        a = await self.upload(self.terminal_a, package(
            VECTORS["package"]["lines"], self.terminal_a), key="shared")
        b = await self.upload(self.terminal_b, package(
            VECTORS["package"]["lines"], self.terminal_b), key="shared")
        self.assertEqual((a.status_code, b.status_code), (201, 201))
        self.assertNotEqual(a.json()["data"]["diagnostic_id"], b.json()["data"]["diagnostic_id"])

    async def test_real_ray910_export_passes_and_planted_identity_is_rejected(self) -> None:
        export = fixture_for(self.terminal_a)
        accepted = await self.upload(self.terminal_a, export)
        self.assertEqual(accepted.status_code, 201, accepted.text)
        lines = export.decode("utf-8").splitlines(keepends=True)
        planted = {
            "phone_in_msg": lines[5].replace("notify timeout", "notify timeout 13912345678"),
            "name_key": lines[1].replace('"telemetry":true', '"patientName":"Wang Fang"'),
        }
        for name, replacement in planted.items():
            with self.subTest(name):
                copy = "".join(lines[:5] + [replacement] + lines[6:]) if name == "phone_in_msg" \
                    else "".join(lines[:1] + [replacement] + lines[2:])
                response = await self.upload(self.terminal_a, copy.encode("utf-8"))
                self.assertEqual(response.status_code, 422, response.text)
                self.assertEqual(response.json()["error"], {
                    "code": "E-DIA-422-CONTENT-REJECTED",
                    "message": "diagnostic package rejected",
                    "retryable": False, "action": "UPDATE_CLIENT",
                    "details": {"line": 6 if name == "phone_in_msg" else 2,
                                "reason": "identity_detected"},
                })
                self.assertNotIn("13912345678", response.text)
                self.assertNotIn("Wang", response.text)
        self.assertEqual(self.objects.object_count, 1)

    async def test_declared_length_over_limit_is_refused_before_reading(self) -> None:
        context = self.terminal_tokens.verify(self.terminal_a["access_token"])

        async def body():
            raise AssertionError("the body must not be read")
            yield b""  # pragma: no cover

        from techflex_cloud_foundation.platform_errors import DiagnosticTooLarge

        with self.assertRaises(DiagnosticTooLarge) as raised:
            await self.service.upload(
                context, body(), declared_length=DIAGNOSTICS_MAX_BYTES + 1,
                content_sha256="0" * 64, idempotency_key="k")
        self.assertEqual(raised.exception.details, {"max_bytes": DIAGNOSTICS_MAX_BYTES})

    async def test_exactly_the_limit_is_read_and_then_validated(self) -> None:
        body = b"x" * DIAGNOSTICS_MAX_BYTES
        response = await self.upload(self.terminal_a, body)
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["error"]["details"], {"line": 1, "reason": "not_json"})

    async def test_media_type_encoding_and_digest_header_are_enforced(self) -> None:
        body = package(VECTORS["package"]["lines"], self.terminal_a)
        for headers, status in (
            ({"Content-Type": "application/json"}, 400),
            ({"Content-Type": "application/x-ndjson; charset=utf-8"}, 201),
            ({"Content-Encoding": "gzip"}, 400),
            ({"X-Content-SHA256": "A" * 64}, 422),
        ):
            with self.subTest(headers):
                response = await self.upload(self.terminal_a, body, headers=headers)
                self.assertEqual(response.status_code, status, response.text)
        self.assertEqual(self.objects.object_count, 1)


class DiagnosticsIsolationTests(_DiagnosticsApiFixture):
    async def test_other_institution_terminal_cannot_upload_as_this_institution(self) -> None:
        # The foreign terminal declares this institution's ids in its header.
        response = await self.upload(self.foreign, package(
            VECTORS["package"]["lines"], self.terminal_a))
        self.assertEqual(response.status_code, 422, response.text)
        self.assertEqual(response.json()["error"]["details"],
                         {"line": 1, "reason": "header_mismatch"})
        # Another terminal of the same institution cannot either.
        sibling = await self.upload(self.terminal_b, package(
            VECTORS["package"]["lines"], self.terminal_a))
        self.assertEqual(sibling.json()["error"]["details"]["reason"], "header_mismatch")
        own = await self.uploaded(self.foreign)
        listed = await self.support_get(self.list_path())
        self.assertEqual(listed.json()["data"]["items"], [])
        theirs = await self.support_get(self.content_path(own["diagnostic_id"]))
        self.assertEqual(theirs.status_code, 404, theirs.text)
        foreign_list = await self.support_get(self.list_path(self.foreign["tenant_id"]))
        self.assertEqual([row["diagnostic_id"] for row in foreign_list.json()["data"]["items"]],
                         [own["diagnostic_id"]])

    async def test_terminal_and_tenant_credentials_have_no_read_path(self) -> None:
        uploaded = await self.uploaded()
        self.assertIn((await self.client.get(
            "/v1/diagnostics", headers=self.bearer(self.terminal_a["access_token"]))
        ).status_code, (404, 405))
        for kind, token in (("terminal", self.terminal_a["access_token"]),
                            ("tenant", self.clinic_tenant_token)):
            for path in (self.list_path(), self.content_path(uploaded["diagnostic_id"])):
                with self.subTest(kind=kind, path=path):
                    response = await self.support_get(path, token=token)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(self.code(response), "E-PLT-403")
                    self.assertNotIn("connected", response.text)
        denials = [dict(event.details) for event in await self.audit(self.tenant_id)]
        self.assertEqual([(d["actor_kind"], d["reason"]) for d in denials], [
            ("terminal", "terminal_credential")] * 2 + [("tenant", "tenant_credential")] * 2)

    async def test_garbage_credential_is_a_plain_authentication_failure(self) -> None:
        response = await self.support_get(self.list_path(), token="not-a-token")
        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(await self.audit(), [])


class DiagnosticsSupportAccessTests(_DiagnosticsApiFixture):
    async def test_support_lists_and_engineer_reads_with_audit(self) -> None:
        uploaded = await self.uploaded()
        listed = await self.support_get(self.list_path(), role="support")
        self.assertEqual(listed.status_code, 200, listed.text)
        self.assertEqual(listed.headers["cache-control"], "no-store")
        [row] = listed.json()["data"]["items"]
        DiagnosticSummary.model_validate(row)
        self.assertEqual(row["client_installation_id"], self.terminal_a["client_installation_id"])
        self.assertIsNone(row["deleted_at"])
        read = await self.support_get(self.content_path(uploaded["diagnostic_id"]),
                                      role="engineer")
        self.assertEqual(read.status_code, 200, read.text)
        self.assertEqual(read.content, package(VECTORS["package"]["lines"], self.terminal_a))
        self.assertEqual(read.headers["cache-control"], "no-store")
        self.assertEqual(read.headers["content-type"], "application/x-ndjson")
        self.assertEqual(read.headers["x-content-sha256"], uploaded["sha256"])
        events = await self.audit(self.tenant_id)
        self.assertEqual([event.action for event in events],
                         ["diagnostics.list", "diagnostics.read"])
        self.assertEqual(dict(events[0].details), {
            "actor_kind": "platform", "count": "1", "roles": "PLATFORM_SUPPORT",
            "ticket_reference": "SUP-1042"})
        self.assertEqual(events[1].resource_id, UUID(uploaded["diagnostic_id"]))
        self.assertEqual(dict(events[1].details)["roles"], "PLATFORM_ENGINEER")

    async def test_wrong_roles_and_missing_ticket_are_denied_and_audited(self) -> None:
        uploaded = await self.uploaded()
        cases = (("owner", "SUP-1"), ("operations", "SUP-1"), ("support", None),
                 ("engineer", "   "))
        for role, ticket in cases:
            for path in (self.list_path(), self.content_path(uploaded["diagnostic_id"])):
                with self.subTest(role=role, path=path):
                    response = await self.support_get(path, role=role, ticket=ticket)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(self.code(response), "E-PLT-403")
        reasons = [dict(event.details)["reason"] for event in await self.audit(self.tenant_id)]
        self.assertEqual(reasons, ["role_unauthorized"] * 4 + ["ticket_missing"] * 4)
        self.assertTrue(all(event.action == "diagnostics.deny"
                            for event in await self.audit(self.tenant_id)))

    async def test_expired_unknown_and_foreign_packages_are_404_and_audited(self) -> None:
        uploaded = await self.uploaded()
        missing = await self.support_get(self.content_path(str(uuid4())))
        self.age(uploaded["diagnostic_id"], timedelta(days=30))
        expired = await self.support_get(self.content_path(uploaded["diagnostic_id"]))
        unknown_tenant = await self.support_get(
            self.content_path(uploaded["diagnostic_id"], str(uuid4())))
        for response in (missing, expired, unknown_tenant):
            self.assertEqual(response.status_code, 404, response.text)
            self.assertEqual(self.code(response), "E-API-404")
        reasons = [dict(event.details)["reason"] for event in await self.audit(self.tenant_id)]
        self.assertEqual(reasons, ["not_found", "expired"])
        [orphan] = [event for event in await self.audit() if event.tenant_id is None]
        self.assertEqual(dict(orphan.details)["reason"], "tenant_unknown")


class DiagnosticsFailureTests(_DiagnosticsApiFixture):
    async def test_a_failed_content_read_is_audited(self) -> None:
        uploaded = await self.uploaded()
        key = f"diagnostics/{self.tenant_id}/{uploaded['diagnostic_id']}.ndjson"
        self.objects._objects[key] = b"tampered\n"
        response = await self.support_get(self.content_path(uploaded["diagnostic_id"]))
        self.assertEqual(response.status_code, 500, response.text)
        self.assertNotIn("tampered", response.text)
        [event] = await self.audit(self.tenant_id)
        self.assertEqual(event.action, "diagnostics.read_failed")
        self.assertEqual(event.resource_id, UUID(uploaded["diagnostic_id"]))

    async def test_failed_insert_deletes_content_only_when_no_record_names_it(self) -> None:
        context = self.terminal_tokens.verify(self.terminal_a["access_token"])
        body = package(VECTORS["package"]["lines"], self.terminal_a)
        repository = self.diagnostics

        class Failing:
            def __init__(self, commit_first: bool) -> None:
                self.commit_first = commit_first

            async def by_key(self, *args):
                return await repository.by_key(*args)

            async def insert(self, record):
                if self.commit_first:
                    await repository.insert(record)
                raise ConnectionError("connection dropped")

        async def stream():
            yield body

        for commit_first, kept in ((False, 0), (True, 1)):
            with self.subTest(commit_first=commit_first):
                service = TerminalDiagnosticsService(
                    Failing(commit_first), DiagnosticPackageStore(self.objects), self.repository,
                    now=lambda: self.now)
                with self.assertRaises(ConnectionError):
                    await service.upload(
                        context, stream(), declared_length=len(body),
                        content_sha256=hashlib.sha256(body).hexdigest(),
                        idempotency_key=f"k-{commit_first}")
                self.assertEqual(self.objects.object_count, kept)


class DiagnosticsPurgeTests(_DiagnosticsApiFixture):
    async def test_purge_deletes_expired_content_and_keeps_the_tombstone(self) -> None:
        old = await self.uploaded()
        recent = await self.uploaded()
        self.age(old["diagnostic_id"], timedelta(days=30, seconds=1))
        self.age(recent["diagnostic_id"], timedelta(days=29, hours=23))
        old = {**old, **{field: getattr(
            self.diagnostics._records[UUID(old["diagnostic_id"])], field).isoformat().replace(
                "+00:00", "Z") for field in ("received_at", "expires_at")}}

        self.assertEqual(await self.service.purge(), 1)
        self.assertEqual(await self.service.purge(), 0)

        self.assertEqual(sorted(self.objects._objects), [
            f"diagnostics/{self.tenant_id}/{recent['diagnostic_id']}.ndjson"])
        listed = await self.support_get(self.list_path())
        rows = {row["diagnostic_id"]: row for row in listed.json()["data"]["items"]}
        tombstone = rows[old["diagnostic_id"]]
        self.assertIsNotNone(tombstone["deleted_at"])
        for field in ("size_bytes", "sha256", "received_at", "expires_at", "format"):
            self.assertEqual(tombstone[field], old[field])
        self.assertIsNone(rows[recent["diagnostic_id"]]["deleted_at"])
        gone = await self.support_get(self.content_path(old["diagnostic_id"]))
        self.assertEqual(gone.status_code, 404, gone.text)
        self.assertEqual(dict((await self.audit(self.tenant_id))[-1].details)["reason"], "deleted")
        kept = await self.support_get(self.content_path(recent["diagnostic_id"]))
        self.assertEqual(kept.status_code, 200, kept.text)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
