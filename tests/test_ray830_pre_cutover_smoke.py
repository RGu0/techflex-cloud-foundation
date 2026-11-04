"""Smoke tools against real in-process routes; these are not TLS acceptance."""
from __future__ import annotations

import argparse
import asyncio
import json
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import run_ray830_pre_cutover_smoke as smoke
from tests.test_ffp_terminal_diagnostics_api import PASSWORD, _DiagnosticsApiFixture


class SmokeTests(_DiagnosticsApiFixture):
    async def run_smoke(self, tmp_path: Path, *, failure: str | None = None):
        loop = asyncio.get_running_loop()
        ca = tmp_path / "ca.pem"
        ca.write_text("in-process test; no TLS")
        tokens = []
        owner = self

        class Bridge:
            def call(self, method, path, *, token=None, body=None, headers=None, content=None):
                if path == "/health/ready":
                    return 200, {}
                if path == failure:
                    raise OSError("sensitive transport text")
                response = asyncio.run_coroutine_threadsafe(owner.client.request(
                    method, path, json=body, content=content,
                    headers={**(headers or {}), **({"Authorization": f"Bearer {token}"}
                                                if token else {})}), loop).result()
                payload = response.json()
                if path.endswith("terminal-activate") and response.status_code == 201:
                    tokens.extend([payload["data"]["access_token"],
                                   payload["data"]["refresh_token"]])
                return response.status_code, payload

        args = argparse.Namespace(mode="diagnostics", base_url="https://cloud.test",
                                  ca_file=str(ca), account_name="seed-clinic",
                                  environment="rehearsal")
        with patch.object(smoke, "Client", lambda *_: Bridge()):
            result = await asyncio.to_thread(smoke.run, args, PASSWORD)
        return result, tokens

    async def test_diagnostics_real_routes_receipt_replay_and_revocation(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            result, tokens = await self.run_smoke(Path(directory))
        self.assertEqual(result["result"], "passed", result)
        steps = {s["step"]: s for s in result["steps"]}
        self.assertTrue(steps["diagnostics_receipt"]["passed"])
        self.assertTrue(steps["diagnostics_replay_identical"]["passed"])
        self.assertTrue(steps["cleanup_terminal_self_revoke"]["passed"])
        rendered = json.dumps(result)
        for secret in [PASSWORD, "seed-clinic", str(self.tenant_id), *tokens]:
            self.assertNotIn(secret, rendered)

    async def test_failure_retains_failure_and_revokes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as directory:
            result, _ = await self.run_smoke(Path(directory), failure="/v1/diagnostics")
        self.assertEqual(result["result"], "failed")
        self.assertNotIn("sensitive transport text", json.dumps(result))
        self.assertTrue(result["steps"][-1]["passed"])
        self.assertEqual(result["steps"][-1]["step"], "cleanup_revoked")


def test_gait_documents_validate_against_registry():
    from uuid import uuid4

    from techflex_cloud_foundation import default_payload_schema_registry
    request, parts, manifest = smoke.gait_documents(uuid4())
    registry = default_payload_schema_registry()
    registry.validate_session(request)
    segments = [registry.validate_segment("gait-session-archive/1", m) for m, _ in parts]
    parsed = registry.validate_manifest("gait-session-archive/1", manifest)
    registry.verify_received(parsed, segments)


def test_target_rejects_credentials_queries_http_and_remote_rehearsal():
    import pytest
    for url in ["http://127.0.0.1:27443", "https://user:secret@127.0.0.1",
                "https://127.0.0.1?token=secret", "https://example.org:7443"]:
        with pytest.raises(ValueError):
            smoke.validate_target(url, "rehearsal", False)
    smoke.validate_target("https://127.0.0.1:27443", "rehearsal", False)
    with pytest.raises(ValueError):
        smoke.validate_target("https://example.org:7443", "production", False)


def test_gait_probe_reaches_ingested_and_rejects_wrong_receipt():
    from types import SimpleNamespace
    from uuid import uuid4

    import pytest

    from scripts.run_ray785_route_smoke import Recorder, SmokeFailure
    terminal = SimpleNamespace(client_installation_id=uuid4(), access_token="test-token")

    class FutureService:
        """Protocol stub, not evidence the current service implements this path."""
        bad_digest = False

        def call(self, method, path, *, body=None, headers=None, **kwargs):
            if path == "/v1/sessions":
                self.sid = body["session_id"]
                self.parts = []
                return 201, {"data": {"session_id": self.sid, "ingest_status": "RECEIVING"}}
            if method == "PUT":
                index = int(path.split("/")[-1])
                record = {"index": index, "sha256": headers["X-Content-SHA256"],
                          "status": "ACKNOWLEDGED"}
                self.parts.append(record)
                return 201, {"data": {**record, "session_id": self.sid, "object_key": "synthetic"}}
            if path.endswith("/segments"):
                return 200, {"data": {"session_id": self.sid,
                                      "received": self.parts, "missing": []}}
            if path.endswith("/complete"):
                return 200, {"data": {"session_id": self.sid, "ingest_status": "INGESTED",
                    "manifest_sha256": "0" * 64 if self.bad_digest else headers["X-Content-SHA256"],
                    "manifest_object_key": "synthetic", "eligibility_reason": "synthetic",
                    "eligibility_policy_version": "1", "completed_at": "2026-11-03T12:00:00Z"}}
            return 200, {"data": {"session_id": self.sid, "ingest_status": "INGESTED",
                "validity_status": "UNKNOWN", "analysis_status": "NOT_REQUESTED"}}

    service = FutureService()
    smoke.gait(service, Recorder(), terminal)
    service.bad_digest = True
    with pytest.raises(SmokeFailure, match="gait_completion_receipt"):
        smoke.gait(service, Recorder(), terminal)


class GaitCurrentServiceTests(unittest.IsolatedAsyncioTestCase):
    async def test_current_http_rejects_registry_valid_gait_core(self):
        import tempfile

        from tests import test_ffp_terminal_data_plane as data_plane
        from tests.test_ffp_ray815_data_plane_smoke import DataPlaneSmokeTest, _BridgedClient
        fixture = DataPlaneSmokeTest()
        await fixture.asyncSetUp()
        try:
            loop = asyncio.get_running_loop()
            with tempfile.TemporaryDirectory() as directory:
                ca = Path(directory) / "ca.pem"
                ca.write_text("ASGI test, no TLS")
                args = argparse.Namespace(mode="gait", environment="rehearsal",
                    base_url="https://cloud.test", ca_file=str(ca),
                    account_name=fixture.account_name)
                with patch.object(smoke, "Client", lambda *_: _BridgedClient(fixture, loop)):
                    result = await asyncio.to_thread(smoke.run, args, data_plane.PASSWORD)
            # Regression evidence of a cutover blocker, not successful gait acceptance.
            self.assertEqual(result["result"], "failed", result)
            self.assertEqual(result["failed_step"], "gait_session_create", result)
            step = next(s for s in result["steps"] if s["step"] == "gait_session_create")
            self.assertEqual(step["status"], 422)
            self.assertTrue(result["steps"][-1]["passed"])
        finally:
            await fixture.asyncTearDown()
