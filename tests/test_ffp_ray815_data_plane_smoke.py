"""RAY-815 data-plane smoke script replayed against the in-process API."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from httpx import ASGITransport, AsyncClient

from scripts import run_ray815_data_plane_smoke as smoke
from techflex_cloud_foundation.server.access_auth import (
    TerminalAccessTokenIssuer,
    TerminalRefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.terminal_service import TerminalAccessService
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.insole_inventory.repository import (
    InMemoryInsoleInventoryRepository,
)
from techflex_cloud_foundation.server.insole_inventory.service import InsoleInventoryService
from tests import test_ffp_terminal_data_plane as data_plane


class _BridgedClient:
    """Sync smoke calls forwarded to the in-process apps.

    The in-memory data repository has no RAY-728 D3 projections, so the bridge
    stands in for them as the RAY-728 tests do: activation, insole registration
    and revocation are mirrored into the data plane's terminal and device rows.
    """

    def __init__(self, test: DataPlaneSmokeTest, loop: asyncio.AbstractEventLoop) -> None:
        self._test = test
        self._loop = loop
        test.secrets_seen = []

    def call(self, method, path, *, token=None, body=None, headers=None, content=None):
        if path == "/health/ready":
            return 200, {"status": "ready"}
        merged = dict(headers or {})
        if token is not None:
            merged["Authorization"] = f"Bearer {token}"
        client = self._test.inventory_client if path.startswith("/v1/inventory/") else self._test.client
        response = asyncio.run_coroutine_threadsafe(
            client.request(method, path, json=body, content=content, headers=merged), self._loop
        ).result()
        payload = response.json()
        data = self._test.data
        tenant = self._test.tenant_id
        if response.status_code == 201 and path == "/v1/access/terminal-activate":
            data.add_terminal(tenant, None, UUID(payload["data"]["client_installation_id"]))
            self._test.secrets_seen += [
                payload["data"]["access_token"], payload["data"]["refresh_token"]
            ]
        elif response.status_code == 201 and path == "/v1/inventory/insoles":
            data.add_device(tenant, UUID(payload["data"]["insole"]["insole_id"]), "insole-pair")
        elif path == "/v1/subjects" and body is not None:
            self._test.secrets_seen.append(body["external_identifier"]["external_id"])
        elif response.status_code == 200 and path.endswith("/revoke") and "/terminals/" in path:
            data.set_terminal_status(tenant, UUID(path.split("/")[-2]), "REVOKED")
        return response.status_code, payload


class DataPlaneSmokeTest(unittest.IsolatedAsyncioTestCase):
    activate = data_plane.TerminalDataPlaneTests.activate
    headers = staticmethod(data_plane.TerminalDataPlaneTests.headers)

    async def asyncSetUp(self) -> None:
        await data_plane.TerminalDataPlaneTests.asyncSetUp(self)
        terminal_tokens = TerminalAccessTokenIssuer(
            secret=data_plane.TOKEN_SECRET, key_id="tenant/1"
        )
        inventory_app = create_app(
            ServiceContainer(
                terminal_access=TerminalAccessService(
                    self.access,
                    login_lookup_hmac_key=data_plane.LOGIN_KEY,
                    terminal_tokens=terminal_tokens,
                    refresh_tokens=TerminalRefreshTokenFactory(
                        digest_key=b"refresh-digest-key-must-be-at-least-32-bytes"
                    ),
                    license_signer=None,
                    now=lambda: self.now,
                ),
                terminal_tokens=terminal_tokens,
                insole_inventory=InsoleInventoryService(
                    InMemoryInsoleInventoryRepository(), self.access, now=lambda: self.now
                ),
            )
        )
        self.inventory_client = AsyncClient(
            transport=ASGITransport(app=inventory_app), base_url="https://cloud.test"
        )

    async def asyncTearDown(self) -> None:
        await self.inventory_client.aclose()
        await self.client.aclose()

    async def _run(self) -> dict:
        loop = asyncio.get_running_loop()
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory, "ca.pem")
            ca_file.write_text("not used by the bridged client\n")
            args = argparse.Namespace(
                base_url="https://cloud.test",
                ca_file=str(ca_file),
                account_name=self.account_name,
            )
            with patch.object(smoke, "Client", lambda *_: _BridgedClient(self, loop)):
                return await asyncio.to_thread(smoke.run, args, data_plane.PASSWORD)

    async def test_full_flow_passes_and_redacts(self) -> None:
        summary = await self._run()

        self.assertEqual(summary["result"], "passed", summary.get("failed_step"))
        self.assertEqual(
            [step["step"] for step in summary["steps"]],
            [
                "readiness",
                "terminal_activate",
                "insole_register",
                "subject_create",
                "subject_resolve",
                "consent_create",
                "session_create",
                "segment_put",
                "segment_list",
                "session_complete",
                "session_status",
                "cleanup_insole_retire",
                "cleanup_terminal_self_revoke",
                "data_plane_after_revoke",
            ],
        )
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertTrue(steps["subject_resolve"]["matches_created"])
        self.assertEqual(steps["segment_put"]["segment_status"], "ACKNOWLEDGED")
        self.assertEqual(steps["segment_list"]["missing"], [])
        self.assertEqual(steps["session_status"]["ingest_status"], "INGESTED")
        self.assertEqual(steps["cleanup_insole_retire"]["state"], "retired")
        self.assertEqual(steps["cleanup_terminal_self_revoke"]["terminal_status"], "REVOKED")
        self.assertEqual(steps["data_plane_after_revoke"]["error_code"], "E-TRM-401-REVOKED")

        rendered = json.dumps(summary)
        self.assertEqual(len(self.secrets_seen), 3)
        for secret in (
            data_plane.PASSWORD,
            self.account_name,
            "ray815-smoke-synthetic-evidence",
            *self.secrets_seen,
        ):
            self.assertNotIn(secret, rendered)

    async def test_unregistered_insole_fails_at_session_create(self) -> None:
        # Without the D3 projection of the registered pair the session must be refused.
        with patch.object(_BridgedClient, "call", _without_device_projection(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["result"], "failed")
        self.assertEqual(summary["failed_step"], "session_create")
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertEqual(steps["session_create"]["error_code"], "E-AUT-403")


    async def test_failure_after_registration_still_releases_seat_and_insole(self) -> None:
        def failing_complete(call):
            def wrapped(self, method, path, **kwargs):
                if path.endswith("/complete"):
                    return 503, {"error": {"code": "E-SYS-503"}}
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", failing_complete(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["result"], "failed")
        self.assertEqual(summary["failed_step"], "session_complete")
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertTrue(steps["cleanup_insole_retire"]["passed"])
        self.assertTrue(steps["cleanup_terminal_self_revoke"]["passed"])
        installation = steps["terminal_activate"]["client_installation_id"]
        listing = await self.client.get(
            "/v1/access/terminals", headers=self.headers(self.terminal)
        )
        statuses = {
            t["client_installation_id"]: t["status"] for t in listing.json()["data"]["terminals"]
        }
        self.assertEqual(statuses[installation], "REVOKED")

    async def test_transport_error_is_recorded_and_cleans_up(self) -> None:
        def broken_upload(call):
            def wrapped(self, method, path, **kwargs):
                if method == "PUT":
                    raise ConnectionResetError("peer reset")
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", broken_upload(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "transport:ConnectionResetError")
        self.assertEqual(
            [step["step"] for step in summary["steps"]][-2:],
            ["cleanup_insole_retire", "cleanup_terminal_self_revoke"],
        )


class RawBodyClientTest(unittest.TestCase):
    def test_raw_content_is_sent_as_bytes_with_its_content_type(self) -> None:
        from scripts.run_ray785_route_smoke import Client

        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory, "ca.pem")
            ca_file.write_text("")
            with patch("ssl.SSLContext.load_verify_locations"):
                client = Client("https://cloud.test", str(ca_file))
        sent = {}

        class _Response:
            status = 201

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self):
                return b'{"data": {}}'

        def fake_open(request, data=None, timeout=None):
            sent.update(data=data, headers=dict(request.header_items()))
            return _Response()

        payload = b"\x00\x01segment"
        with patch.object(client._opener, "open", fake_open):
            status, _ = client.call("PUT", "/x", content=payload)
            self.assertEqual(status, 201)
            self.assertIs(sent["data"], payload)
            self.assertEqual(sent["headers"]["Content-type"], "application/octet-stream")
            client.call(
                "PUT", "/x", content=payload, headers={"Content-Type": smoke.SEGMENT_CONTENT_TYPE}
            )
            self.assertEqual(sent["headers"]["Content-type"], smoke.SEGMENT_CONTENT_TYPE)


def _without_device_projection(call):
    def wrapped(self, method, path, **kwargs):
        if path == "/v1/inventory/insoles" and method == "POST":
            client = self._test.inventory_client
            merged = dict(kwargs.get("headers") or {})
            merged["Authorization"] = f"Bearer {kwargs['token']}"
            response = asyncio.run_coroutine_threadsafe(
                client.request(method, path, json=kwargs.get("body"), headers=merged), self._loop
            ).result()
            return response.status_code, response.json()
        return call(self, method, path, **kwargs)

    return wrapped
