"""RAY-825 insole archive smoke script replayed against the in-process API."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import tempfile
from unittest.mock import patch

from scripts import run_ray825_insole_archive_smoke as smoke
from tests import test_ffp_terminal_data_plane as data_plane
from tests.test_ffp_ray815_data_plane_smoke import DataPlaneSmokeTest, _BridgedClient


class InsoleArchiveSmokeTest(DataPlaneSmokeTest):
    async def _run(self) -> dict:
        loop = asyncio.get_running_loop()
        with tempfile.TemporaryDirectory() as directory:
            ca_file = Path(directory, "ca.pem")
            ca_file.write_text("not used by the bridged client\n")
            args = argparse.Namespace(
                base_url="https://cloud.test", ca_file=str(ca_file),
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
                "readiness", "terminal_activate", "insole_register", "subject_create",
                "consent_create",
                "archive_session_create", "archive_segment_put_0", "archive_segment_put_1",
                "archive_segment_list", "archive_crossed_manifest_rejected",
                "archive_session_complete", "archive_session_status",
                "raw_session_create", "raw_segment_put_0", "raw_segment_list",
                "raw_session_complete", "raw_session_status",
                "cleanup_insole_retire", "cleanup_terminal_self_revoke",
                "data_plane_after_revoke",
            ],
        )
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertEqual(steps["archive_session_create"]["payload_schema"],
                         "insole-session-archive/1")
        self.assertEqual(steps["archive_segment_put_0"]["size_bytes"], 4 * 1024 * 1024)
        self.assertEqual(steps["archive_crossed_manifest_rejected"]["action"], "UPDATE_CLIENT")
        self.assertEqual(steps["archive_session_status"]["ingest_status"], "INGESTED")
        self.assertEqual(steps["raw_session_status"]["ingest_status"], "INGESTED")
        self.assertEqual(steps["data_plane_after_revoke"]["error_code"], "E-TRM-401-REVOKED")

        rendered = json.dumps(summary)
        for secret in (
            data_plane.PASSWORD, self.account_name, "ray825-smoke-synthetic-evidence",
            *self.secrets_seen,
        ):
            self.assertNotIn(secret, rendered)

    async def test_unregistered_insole_fails_at_session_create(self) -> None:
        from tests.test_ffp_ray815_data_plane_smoke import _without_device_projection

        with patch.object(_BridgedClient, "call", _without_device_projection(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "archive_session_create")

    async def test_failure_after_registration_still_releases_seat_and_insole(self) -> None:
        def failing_complete(call):
            def wrapped(self, method, path, **kwargs):
                if path.endswith("/complete"):
                    return 503, {"error": {"code": "E-SYS-503"}}
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", failing_complete(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "archive_crossed_manifest_rejected")
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertTrue(steps["cleanup_insole_retire"]["passed"])
        self.assertTrue(steps["cleanup_terminal_self_revoke"]["passed"])

    async def test_unexpected_exception_still_releases_seat_and_insole(self) -> None:
        def broken_list(call):
            def wrapped(self, method, path, **kwargs):
                if path.endswith("/segments") and method == "GET":
                    raise KeyError("unexpected")
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", broken_list(_BridgedClient.call)):
            with self.assertRaises(KeyError):
                await self._run()
        listing = await self.client.get(
            "/v1/access/terminals", headers=self.headers(self.terminal)
        )
        smoke_terminals = [
            t for t in listing.json()["data"]["terminals"]
            if t["terminal_name"].startswith("ray825-smoke-")
        ]
        self.assertEqual([t["status"] for t in smoke_terminals], ["REVOKED"])


del DataPlaneSmokeTest
