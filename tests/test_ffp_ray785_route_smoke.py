"""RAY-785 route smoke script replayed against the in-process API."""

from __future__ import annotations

import argparse
import asyncio
import base64
import json
from pathlib import Path
import tempfile
from unittest.mock import patch
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from scripts import run_ray785_route_smoke as smoke
from tests.test_ffp_insole_inventory_api import PASSWORD, _InsoleApiFixture


class _BridgedClient:
    """Sync smoke client calls forwarded to the fixture's async ASGI client."""

    def __init__(self, client, loop: asyncio.AbstractEventLoop) -> None:
        self._client = client
        self._loop = loop

    def call(self, method, path, *, token=None, body=None, headers=None):
        if path == "/health/ready":
            return 200, {"status": "ready"}
        merged = dict(headers or {})
        if token is not None:
            merged["Authorization"] = f"Bearer {token}"
        response = asyncio.run_coroutine_threadsafe(
            self._client.request(method, path, json=body, headers=merged), self._loop
        ).result()
        return response.status_code, response.json()


class RouteSmokeTest(_InsoleApiFixture):
    async def _run(self, public_key: bytes | None = None) -> dict:
        loop = asyncio.get_running_loop()
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory, "ca.pem")
            ca_file.write_text("not used by the bridged client\n")
            key_file = None
            if public_key is not None:
                key_file = Path(directory, "license-public.key")
                key_file.write_text(base64.b64encode(public_key).decode("ascii"))
            args = argparse.Namespace(
                base_url="https://cloud.test",
                ca_file=str(ca_file),
                account_name="seed-clinic",
                license_public_key=str(key_file) if key_file else None,
            )
            with patch.object(
                smoke, "Client", lambda *_: _BridgedClient(self.client, loop)
            ):
                return await asyncio.to_thread(smoke.run, args, PASSWORD)

    async def test_full_flow_passes_and_redacts(self) -> None:
        summary = await self._run()

        self.assertEqual(summary["result"], "passed", summary.get("failed_step"))
        names = [step["step"] for step in summary["steps"]]
        self.assertEqual(
            names,
            [
                "readiness",
                "terminal_a_activate",
                "terminal_a_refresh",
                "terminal_list_before_b",
                "terminal_b_activate",
                "insole_register_by_terminal_a",
                "insole_download_by_terminal_b",
                "insole_report_by_terminal_b",
                "insole_retire_by_terminal_a",
                "terminal_a_revokes_b",
                "terminal_b_refresh_after_revoke",
                "terminal_list_after_revoke",
                "cleanup_terminal_a_revoke",
            ],
        )
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertTrue(steps["terminal_a_refresh"]["refresh_rotated"])
        self.assertTrue(steps["insole_download_by_terminal_b"]["found"])
        self.assertEqual(steps["insole_retire_by_terminal_a"]["state"], "retired")
        self.assertEqual(
            steps["terminal_b_refresh_after_revoke"]["error_code"], "E-TRM-401-REVOKED"
        )
        self.assertEqual(steps["terminal_list_after_revoke"]["b_status"], "REVOKED")
        self.assertEqual(summary["license"]["schema_version"], "terminal-license/1")
        self.assertIsNone(summary["license"]["signature_verified"])

        rendered = json.dumps(summary)
        for secret in (PASSWORD, "seed-clinic", "access_token", "refresh_token", "signature\""):
            self.assertNotIn(secret, rendered)

    async def test_wrong_license_key_is_reported_not_trusted(self) -> None:
        stranger = Ed25519PrivateKey.generate().public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        summary = await self._run(public_key=stranger)

        self.assertEqual(summary["result"], "passed", summary.get("failed_step"))
        self.assertFalse(summary["license"]["signature_verified"])

    async def test_no_free_seat_stops_before_terminal_b(self) -> None:
        listing = (
            await self.client.get("/v1/access/terminals", headers=self.bearer(self.terminal_a))
        ).json()["data"]
        await self.repository.set_terminal_seats(
            license_id=UUID(listing["license_id"]), seats=3, changed_at=self.now
        )

        summary = await self._run()

        self.assertEqual(summary["result"], "failed")
        self.assertEqual(summary["failed_step"], "terminal_list_before_b")
        self.assertNotIn("terminal_b_activate", [s["step"] for s in summary["steps"]])
