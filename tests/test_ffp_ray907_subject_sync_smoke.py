"""RAY-907 subject sync smoke script replayed against the in-process API."""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from uuid import UUID

from scripts import run_ray907_subject_sync_smoke as smoke
from tests import test_ffp_subject_sync_api as subject_sync


class _BridgedClient:
    """Sync smoke calls forwarded to the in-process app.

    The in-memory data repository has no RAY-728 D3 projections, so activation
    and revocation are mirrored into its terminal rows as the RAY-907 tests do.
    Every secret and synthetic identity the smoke sends or receives is kept so
    the test can require that none of it reaches the evidence.
    """

    def __init__(self, test: SubjectSyncSmokeTest, loop: asyncio.AbstractEventLoop) -> None:
        self._test = test
        self._loop = loop
        test.secrets_seen = []

    def call(self, method, path, *, token=None, body=None, headers=None, content=None):
        if path == "/health/ready":
            return 200, {"status": "ready"}
        merged = dict(headers or {})
        if token is not None:
            merged["Authorization"] = f"Bearer {token}"
        response = asyncio.run_coroutine_threadsafe(
            self._test.client.request(method, path, json=body, content=content, headers=merged),
            self._loop,
        ).result()
        payload = response.json()
        data = self._test.data
        tenant = self._test.tenant_id
        if response.status_code == 201 and path == "/v1/access/terminal-activate":
            data.add_terminal(tenant, None, UUID(payload["data"]["client_installation_id"]))
            self._test.secrets_seen += [
                payload["data"]["access_token"], payload["data"]["refresh_token"],
                payload["data"]["tenant_id"],
            ]
        elif path == "/v1/subjects" and method == "POST":
            self._test.secrets_seen += [
                body["external_identifier"]["external_id"],
                body["identity_profile"]["display_name"],
            ]
        elif response.status_code == 200 and path.endswith("/revoke") and "/terminals/" in path:
            data.set_terminal_status(tenant, UUID(path.split("/")[-2]), "REVOKED")
        return response.status_code, payload


class SubjectSyncSmokeTest(unittest.IsolatedAsyncioTestCase):
    activate = subject_sync.SubjectSyncApiTests.activate
    provision = subject_sync.SubjectSyncApiTests.provision
    create_subject = subject_sync.SubjectSyncApiTests.create_subject
    headers = staticmethod(subject_sync.SubjectSyncApiTests.headers)

    async def asyncSetUp(self) -> None:
        await subject_sync.SubjectSyncApiTests.asyncSetUp(self)

    async def asyncTearDown(self) -> None:
        await self.client.aclose()

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
                return await asyncio.to_thread(smoke.run, args, subject_sync.PASSWORD)

    async def smoke_terminal_statuses(self) -> list[str]:
        listing = await self.client.get(
            "/v1/access/terminals", headers=self.headers(self.terminal)
        )
        return [
            t["status"] for t in listing.json()["data"]["terminals"]
            if t["terminal_name"].startswith("ray907-smoke-")
        ]

    def assert_redacted(self, summary: dict) -> None:
        rendered = json.dumps(summary, ensure_ascii=False)
        self.assertTrue(self.secrets_seen)
        for secret in (subject_sync.PASSWORD, self.account_name, *self.secrets_seen):
            self.assertNotIn(secret, rendered)

    async def test_full_flow_passes_and_redacts(self) -> None:
        summary = await self._run()

        self.assertEqual(summary["result"], "passed", summary.get("failed_step"))
        self.assertEqual(
            [step["step"] for step in summary["steps"]],
            [
                "readiness", "terminal_activate", "subject_create", "subject_download",
                "subject_patch", "subject_patch_replay", "subject_patch_key_reused",
                "subject_patch_stale_revision", "subject_search_by_name",
                "tag_create", "tag_create_name_conflict", "subject_patch_tags",
                "tag_download", "subject_archive", "cleanup_terminal_self_revoke",
                "subject_download_after_revoke",
            ],
        )
        steps = {step["step"]: step for step in summary["steps"]}
        download = steps["subject_download"]
        self.assertEqual(
            (download["found"], download["revisions_ascending"], download["next_cursor_returned"]),
            (True, True, True),
        )
        self.assertGreater(steps["subject_patch"]["revision"], download["revision"])
        self.assertTrue(steps["subject_patch_replay"]["identical"])
        self.assertEqual(steps["subject_patch_key_reused"]["error_code"], "E-API-409")
        stale = steps["subject_patch_stale_revision"]
        self.assertEqual(stale["error_code"], "E-SUB-409-REVISION-CONFLICT")
        self.assertEqual(stale["current_revision"], steps["subject_patch"]["revision"])
        self.assertTrue(steps["subject_search_by_name"]["found"])
        self.assertEqual(steps["tag_create"]["status"], 201)
        conflict = steps["tag_create_name_conflict"]
        self.assertEqual((conflict["status"], conflict["conflict"]), (200, True))
        self.assertEqual(conflict["tag_id"], steps["tag_create"]["tag_id"])
        self.assertEqual(steps["subject_patch_tags"]["tag_ids"], [steps["tag_create"]["tag_id"]])
        self.assertTrue(steps["tag_download"]["found"])
        self.assertEqual(steps["subject_archive"]["subject_status"], "ARCHIVED")
        self.assertEqual(steps["cleanup_terminal_self_revoke"]["terminal_status"], "REVOKED")
        self.assertEqual(
            steps["subject_download_after_revoke"]["error_code"], "E-TRM-401-REVOKED"
        )
        self.assert_redacted(summary)
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])

    async def test_download_pages_with_the_cursor(self) -> None:
        for index in range(3):
            await self.create_subject(number=f"GAIT-{index:03d}")

        with patch.object(smoke, "SUBJECT_PAGE_MAX_LIMIT", 1):
            summary = await self._run()

        self.assertEqual(summary["result"], "passed", summary.get("failed_step"))
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertEqual(steps["subject_download"]["pages"], 4)
        self.assertGreaterEqual(steps["tag_download"]["pages"], 1)
        self.assertEqual(
            [step["step"] for step in summary["steps"]].count("subject_download"), 1
        )

    async def test_out_of_order_download_fails(self) -> None:
        await self.create_subject(number="GAIT-001")

        def reversed_download(call):
            def wrapped(self, method, path, **kwargs):
                status, payload = call(self, method, path, **kwargs)
                if method == "GET" and path.startswith("/v1/subjects?"):
                    payload["data"]["items"].reverse()
                return status, payload

            return wrapped

        with patch.object(_BridgedClient, "call", reversed_download(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "subject_download")
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertFalse(steps["subject_download"]["revisions_ascending"])
        self.assertTrue(steps["cleanup_terminal_self_revoke"]["passed"])
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])

    async def test_missing_name_match_fails_and_still_releases_seat(self) -> None:
        def empty_search(call):
            def wrapped(self, method, path, **kwargs):
                if path == "/v1/subjects/search-by-name":
                    return 200, {"data": {"items": []}}
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", empty_search(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "subject_search_by_name")
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertFalse(steps["subject_search_by_name"]["found"])
        self.assertTrue(steps["cleanup_terminal_self_revoke"]["passed"])
        self.assert_redacted(summary)
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])

    async def test_conflict_without_current_record_fails(self) -> None:
        def bare_conflict(call):
            def wrapped(self, method, path, **kwargs):
                status, payload = call(self, method, path, **kwargs)
                if payload.get("error", {}).get("code") == "E-SUB-409-REVISION-CONFLICT":
                    payload["error"].pop("details", None)
                return status, payload

            return wrapped

        with patch.object(_BridgedClient, "call", bare_conflict(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "subject_patch_stale_revision")
        steps = {step["step"]: step for step in summary["steps"]}
        self.assertFalse(steps["subject_patch_stale_revision"]["current_valid"])

    async def test_transport_error_is_recorded_and_cleans_up(self) -> None:
        def broken_tags(call):
            def wrapped(self, method, path, **kwargs):
                if path == "/v1/subject-tags":
                    raise ConnectionResetError("peer reset")
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", broken_tags(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(summary["failed_step"], "transport:ConnectionResetError")
        self.assertEqual(
            [step["step"] for step in summary["steps"]][-2:],
            ["cleanup_subject_archive", "cleanup_terminal_self_revoke"],
        )
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])

    async def test_unexpected_exception_still_releases_seat(self) -> None:
        def broken_patch(call):
            def wrapped(self, method, path, **kwargs):
                if method == "PATCH":
                    raise KeyError("unexpected")
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", broken_patch(_BridgedClient.call)):
            with self.assertRaises(KeyError):
                await self._run()
        self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])


def _tamper(call, match, mutate):
    """Rewrite the responses ``match`` selects; ``mutate`` returns the new pair."""

    def wrapped(self, method, path, **kwargs):
        status, payload = call(self, method, path, **kwargs)
        key = (kwargs.get("headers") or {}).get("Idempotency-Key", "")
        if match(method, path, key, status, payload):
            return mutate(status, payload)
        return status, payload

    return wrapped


def _set(field, value):
    def mutate(status, payload):
        payload["data"][field] = value
        return status, payload

    return mutate


def _second(match):
    seen = set()

    def matcher(method, path, key, status, payload):
        if not match(method, path, key, status, payload):
            return False
        if key in seen:
            return True
        seen.add(key)
        return False

    return matcher


def _bump_current(status, payload):
    payload["error"]["details"]["current"]["revision"] += 1
    return status, payload


def _key(prefix):
    return lambda method, path, key, status, payload: (
        method == "PATCH" and key.startswith(prefix) and status == 200
    )


TAMPER_CASES = {
    "subject_download": (
        lambda method, path, *_: method == "GET" and path.startswith("/v1/subjects?"),
        lambda status, payload: (status, {**payload, "data": {
            **payload["data"], "items": [], "has_more": False}}),
    ),
    "subject_patch": (_key("ray907-smoke-patch-"), _set("revision", 1)),
    "subject_patch_replay": (_second(_key("ray907-smoke-patch-")), _set("revision", 999)),
    "subject_patch_stale_revision": (
        lambda *args: (args[4].get("error") or {}).get("code") == "E-SUB-409-REVISION-CONFLICT",
        _bump_current,
    ),
    "tag_create": (
        lambda method, path, key, status, payload: path == "/v1/subject-tags" and status == 201,
        _set("conflict", True),
    ),
    "tag_create_name_conflict": (
        lambda method, path, key, status, payload: path == "/v1/subject-tags" and status == 200,
        _set("conflict", False),
    ),
    "subject_patch_tags": (_key("ray907-smoke-tags-"), _set("tag_ids", [])),
    "tag_download": (
        lambda method, path, *_: method == "GET" and path.startswith("/v1/subject-tags?"),
        lambda status, payload: (status, {**payload, "data": {
            **payload["data"], "items": [], "has_more": False}}),
    ),
    "subject_archive": (_key("ray907-smoke-archive-"), _set("status", "ACTIVE")),
    # The cleanup re-revokes, so the seat still ends REVOKED.
    "cleanup_terminal_self_revoke": (
        lambda method, path, key, status, payload: path.endswith("/revoke") and status == 200,
        lambda status, payload: (500, {"error": {"code": "E-SYS-500"}}),
    ),
    "subject_download_after_revoke": (
        lambda method, path, *_: method == "GET" and path == "/v1/subjects",
        lambda status, payload: (401, {"error": {"code": "E-AUT-401"}}),
    ),
}


class SubjectSyncSmokeTamperTest(SubjectSyncSmokeTest):
    """Each check fails its own step when the server's answer is wrong."""

    async def test_each_wrong_answer_fails_its_step_and_still_cleans_up(self) -> None:
        for step, (match, mutate) in TAMPER_CASES.items():
            with self.subTest(step=step):
                await self.asyncTearDown()
                await self.asyncSetUp()
                with patch.object(
                    _BridgedClient, "call", _tamper(_BridgedClient.call, match, mutate)
                ):
                    summary = await self._run()

                self.assertEqual(summary["failed_step"], step)
                self.assertFalse(
                    next(s for s in summary["steps"] if s["step"] == step)["passed"]
                )
                self.assert_redacted(summary)
                self.assertEqual(await self.smoke_terminal_statuses(), ["REVOKED"])
                subjects = (await self.client.get(
                    "/v1/subjects", headers=self.headers(self.terminal)
                )).json()["data"]["items"]
                self.assertEqual([s["status"] for s in subjects], ["ARCHIVED"])

    async def test_only_the_cleanup_archive_runs_on_failure(self) -> None:
        def broken_search(call):
            def wrapped(self, method, path, **kwargs):
                if path == "/v1/subjects/search-by-name":
                    return 503, {"error": {"code": "E-SYS-503"}}
                return call(self, method, path, **kwargs)

            return wrapped

        with patch.object(_BridgedClient, "call", broken_search(_BridgedClient.call)):
            summary = await self._run()

        self.assertEqual(
            [step["step"] for step in summary["steps"]][-2:],
            ["cleanup_subject_archive", "cleanup_terminal_self_revoke"],
        )
        self.assertTrue(summary["steps"][-2]["passed"])

    # Inherited tests already run in SubjectSyncSmokeTest.
    test_full_flow_passes_and_redacts = None
    test_download_pages_with_the_cursor = None
    test_out_of_order_download_fails = None
    test_missing_name_match_fails_and_still_releases_seat = None
    test_conflict_without_current_record_fails = None
    test_transport_error_is_recorded_and_cleans_up = None
    test_unexpected_exception_still_releases_seat = None


class RedactionGuardTest(unittest.TestCase):
    def test_a_leaked_value_drops_every_step(self) -> None:
        summary = {
            "schema_version": smoke.SCHEMA_VERSION, "started_at": "s", "finished_at": "f",
            "endpoint": "https://cloud.test", "script_commit": "c", "result": "passed",
            "secrets_included": False,
            "steps": [{"step": "subject_create", "echo": "RAY907 Smoke 0123"}],
        }

        self.assertIs(smoke._redacted(summary, ["", "absent"]), summary)
        guarded = smoke._redacted(summary, ["RAY907 Smoke 0123"])
        self.assertEqual(
            (guarded["result"], guarded["failed_step"], guarded["steps"]),
            ("failed", "redaction_check", []),
        )
        self.assertNotIn("RAY907 Smoke 0123", json.dumps(guarded))
        quoted = {**summary, "steps": [{"echo": 'pass"word'}]}
        self.assertEqual(smoke._redacted(quoted, ['pass"word'])["failed_step"], "redaction_check")
