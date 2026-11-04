"""RAY-927 diagnostics smoke script replayed against the in-process API."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from scripts import run_ray802_diagnostics_smoke as smoke
from tests import test_ffp_terminal_diagnostics_api as diagnostics

STEPS = [
    "readiness", "terminal_activate", "diagnostic_upload", "diagnostic_upload_replay",
    "diagnostic_upload_key_reused", "diagnostic_upload_identity_planted", "support_login",
    "support_list", "support_read", "owner_login", "owner_list_refused",
    "terminal_list_refused", "cleanup_terminal_self_revoke",
]


class _BridgedClient:
    """Sync smoke calls forwarded to the in-process app.

    Every secret and identity value the smoke sends or receives is kept so the
    test can require that none of it reaches the evidence.
    """

    def __init__(self, test: DiagnosticsSmokeTest, loop: asyncio.AbstractEventLoop) -> None:
        self._test = test
        self._loop = loop
        test.secrets_seen = []

    def _request(self, method, path, *, token=None, body=None, headers=None, content=None):
        merged = dict(headers or {})
        if token is not None:
            merged["Authorization"] = f"Bearer {token}"
        return asyncio.run_coroutine_threadsafe(
            self._test.client.request(method, path, json=body, content=content, headers=merged),
            self._loop,
        ).result()

    def call(self, method, path, *, token=None, body=None, headers=None, content=None):
        if path == "/health/ready":
            return 200, {"status": "ready"}
        response = self._request(
            method, path, token=token, body=body, headers=headers, content=content)
        payload = response.json()
        if response.status_code in (200, 201) and path in (
                "/v1/access/terminal-activate", "/v1/platform/login"):
            data = payload["data"]
            self._test.secrets_seen += [data["access_token"], data["refresh_token"]]
            if "tenant_id" in data:
                self._test.secrets_seen.append(data["tenant_id"])
        if content is not None:
            self._test.uploads.append(content)
        return response.status_code, payload

    def fetch(self, path, *, token):
        response = self._request("GET", path, token=token)
        return response.status_code, dict(response.headers), response.content


class DiagnosticsSmokeTest(diagnostics._DiagnosticsApiFixture):
    async def asyncSetUp(self) -> None:
        await super().asyncSetUp()
        self.uploads: list[bytes] = []

    async def _run(self, *, owner_login: str = "platform-owner") -> dict:
        loop = asyncio.get_running_loop()
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory, "ca.pem")
            ca_file.write_text("not used by the bridged client\n")
            args = argparse.Namespace(
                base_url="https://cloud.test", ca_file=str(ca_file),
                account_name="seed-clinic", support_login="platform-support",
                owner_login=owner_login,
            )
            with patch.object(smoke, "Client", lambda *_: _BridgedClient(self, loop)):
                return await asyncio.to_thread(
                    smoke.run, args, diagnostics.PASSWORD, diagnostics.PASSWORD,
                    diagnostics.PASSWORD)

    async def smoke_terminal_statuses(self) -> list[str]:
        listing = await self.client.get(
            "/v1/access/terminals", headers=self.bearer(self.terminal_a["access_token"]))
        return [
            t["status"] for t in listing.json()["data"]["terminals"]
            if t["terminal_name"].startswith("ray802-smoke-")
        ]

    def assert_redacted(self, summary: dict) -> None:
        rendered = json.dumps(summary, ensure_ascii=False)
        self.assertTrue(self.secrets_seen)
        for secret in (diagnostics.PASSWORD, "seed-clinic", "platform-support",
                       "platform-owner", *self.secrets_seen):
            self.assertNotIn(secret, rendered)
        # The planted number is the only 11-digit run in the rejected package.
        planted = self.uploads[3].decode("utf-8").split(" call ")[1].split(" ")[0]
        self.assertRegex(planted, r"^139[0-9]{8}$")
        self.assertNotIn(planted, rendered)

    async def test_full_flow_passes_and_redacts(self) -> None:
        summary = await self._run()

        self.assertEqual(summary["result"], "passed", summary.get("failed_step"))
        self.assertEqual([step["step"] for step in summary["steps"]], STEPS)
        steps = {step["step"]: step for step in summary["steps"]}
        upload = steps["diagnostic_upload"]
        self.assertEqual((upload["status"], upload["retention_days"]), (201, 30))
        self.assertEqual(steps["diagnostic_upload_replay"]["status"], 200)
        self.assertTrue(steps["diagnostic_upload_replay"]["identical"])
        reused = steps["diagnostic_upload_key_reused"]
        self.assertEqual((reused["status"], reused["error_code"]), (409, "E-API-409"))
        planted = steps["diagnostic_upload_identity_planted"]
        self.assertEqual((planted["status"], planted["reason"], planted["line"]),
                         (422, "identity_detected", 2))
        self.assertEqual(steps["support_login"]["roles"], ["PLATFORM_SUPPORT"])
        self.assertTrue(steps["support_list"]["found"])
        read = steps["support_read"]
        self.assertTrue(read["content_matches"])
        self.assertEqual(read["sha256"], upload["sha256"])
        self.assertEqual(steps["owner_login"]["roles"], ["PLATFORM_OWNER"])
        for name in ("owner_list_refused", "terminal_list_refused"):
            self.assertEqual((steps[name]["status"], steps[name]["error_code"]),
                             (403, "E-PLT-403"))
        self.assertEqual(steps["cleanup_terminal_self_revoke"]["terminal_status"], "REVOKED")
        self.assertEqual(summary["ticket_reference"][:len(smoke.LABEL)], smoke.LABEL)
        self.assert_redacted(summary)
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])

        # Only the accepted package was stored, and the support access was audited.
        self.assertEqual(self.objects.object_count, 1)
        events = await self.audit(self.tenant_id)
        self.assertEqual([event.action for event in events],
                         ["diagnostics.list", "diagnostics.read", "diagnostics.deny",
                          "diagnostics.deny"])
        self.assertEqual({dict(event.details).get("ticket_reference") for event in events},
                         {summary["ticket_reference"]})
        self.assertEqual([dict(event.details)["reason"] for event in events[2:]],
                         ["role_unauthorized", "terminal_credential"])
        self.assertEqual(events[1].resource_id, UUID(upload["diagnostic_id"]))

    async def test_owner_holding_a_support_role_proves_nothing_and_fails(self) -> None:
        # The support identity itself stands in for an "owner" that may read.
        summary = await self._run(owner_login="platform-support")

        self.assertEqual((summary["result"], summary["failed_step"]), ("failed", "owner_login"))
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])
        self.assert_redacted(summary)


class DiagnosticsSmokeTamperTest(DiagnosticsSmokeTest):
    """A wrong server answer fails its own step and still gives the seat back."""

    async def _tampered(self, route: str, number: int, rewrite) -> dict:
        """Rewrite the ``number``-th answer (1-based) from paths starting with ``route``."""
        original = _BridgedClient.call
        seen = [0]

        def call(client, method, path, **kwargs):
            status, payload = original(client, method, path, **kwargs)
            if path.startswith(route):
                seen[0] += 1
                if seen[0] == number:
                    return rewrite(status, payload)
            return status, payload

        with patch.object(_BridgedClient, "call", call):
            return await self._run()

    async def test_each_wrong_answer_fails_its_step(self) -> None:
        platform = "/v1/platform/tenants/"
        cases = {
            "diagnostic_upload": ("/v1/diagnostics", 1, lambda s, p: (
                s, {**p, "data": {**p["data"], "sha256": "0" * 64}})),
            "diagnostic_upload_replay": ("/v1/diagnostics", 2, lambda s, p: (201, p)),
            "diagnostic_upload_key_reused": ("/v1/diagnostics", 3, lambda s, p: (
                200, {"data": {}})),
            "diagnostic_upload_identity_planted": ("/v1/diagnostics", 4, lambda s, p: (
                s, {"error": {**p["error"], "details": {"line": 2, "reason": "not_json"}}})),
            "support_login": ("/v1/platform/login", 1, lambda s, p: (
                s, {"data": {**p["data"], "roles": ["PLATFORM_OPERATIONS"]}})),
            "support_list": (platform, 1, lambda s, p: (s, {"data": {"items": []}})),
            "owner_list_refused": (platform, 2, lambda s, p: (200, {"data": {"items": []}})),
            "terminal_list_refused": (platform, 3, lambda s, p: (
                403, {"error": {"code": "E-API-403"}})),
        }
        for step, (route, number, rewrite) in cases.items():
            with self.subTest(step):
                await self.asyncTearDown()
                await self.asyncSetUp()
                summary = await self._tampered(route, number, rewrite)
                self.assertEqual(
                    (summary["result"], summary["failed_step"]), ("failed", step))
                self.assertEqual(summary["steps"][-1]["step"], "cleanup_terminal_self_revoke")
                self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])
                self.assert_redacted_if_uploaded(summary)

    def assert_redacted_if_uploaded(self, summary: dict) -> None:
        rendered = json.dumps(summary, ensure_ascii=False)
        for secret in (diagnostics.PASSWORD, *self.secrets_seen):
            self.assertNotIn(secret, rendered)

    async def test_tampered_content_fails_the_read(self) -> None:
        original = _BridgedClient.fetch

        def fetch(client, path, *, token):
            status, headers, content = original(client, path, token=token)
            return status, headers, content + b"{}\n"

        with patch.object(_BridgedClient, "fetch", fetch):
            summary = await self._run()
        self.assertEqual((summary["result"], summary["failed_step"]), ("failed", "support_read"))
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])

    async def test_transport_error_is_recorded_and_cleans_up(self) -> None:
        from http.client import IncompleteRead

        original = _BridgedClient.call
        for error in (ConnectionResetError("dropped"), IncompleteRead(b"")):
            with self.subTest(type(error).__name__):
                await self.asyncTearDown()
                await self.asyncSetUp()

                def call(client, method, path, error=error, **kwargs):
                    if path == "/v1/platform/login":
                        raise error
                    return original(client, method, path, **kwargs)

                with patch.object(_BridgedClient, "call", call):
                    summary = await self._run()
                self.assertEqual(summary["failed_step"], f"transport:{type(error).__name__}")
                self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])


class SyntheticPackageTest(unittest.TestCase):
    def test_package_passes_validation_and_nonces_never_look_like_numbers(self) -> None:
        from techflex_cloud_foundation.server.terminal_diagnostics.validation import (
            validate_package,
        )

        tenant, terminal = UUID(int=1), UUID(int=2)
        for _ in range(200):
            body = smoke._package(str(tenant), str(terminal), f"msg {smoke._nonce()}")
            self.assertEqual(
                validate_package(body, tenant_id=tenant, client_installation_id=terminal), 2)
            self.assertNotRegex(smoke._nonce(), r"[0-9]")


class RedactionGuardTest(unittest.TestCase):
    def test_a_leaked_value_drops_every_step(self) -> None:
        summary = {
            "schema_version": smoke.SCHEMA_VERSION, "started_at": "s", "finished_at": "f",
            "endpoint": "https://cloud.test", "script_commit": None, "result": "passed",
            "steps": [{"step": "support_login", "note": 'pass"word'}],
        }
        redacted = smoke._redacted(summary, ['pass"word'])
        self.assertEqual((redacted["result"], redacted["failed_step"], redacted["steps"]),
                         ("failed", "redaction_check", []))
        self.assertIs(smoke._redacted(summary, ["absent"]), summary)
