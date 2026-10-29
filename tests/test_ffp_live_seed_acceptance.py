from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from uuid import uuid4

import httpx
import pytest

from scripts.verify_seed_live import AcceptanceState, Api, _after, _verify_d10_identity_access

ROOT = Path(__file__).resolve().parents[1]


def _bash_is_usable() -> bool:
    if shutil.which("bash") is None:
        return False
    if os.name != "nt":
        return True
    # Windows resolves a bare "bash" through System32 first, which can be the
    # WSL launcher with no distribution; probe it exactly as the tests call it.
    try:
        return subprocess.run(["bash", "-c", "true"], capture_output=True, timeout=30).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


requires_bash = pytest.mark.skipif(
    not _bash_is_usable(),
    reason="live seed acceptance shell helpers require a working bash",
)


def test_acceptance_evidence_excludes_all_replayable_credentials() -> None:
    state = AcceptanceState(
        tenant_id=uuid4(),
        account_name="acceptance-tenant",
        account_password="secret-password-value",
        hardware_id="usb-serial-0123456789abcdef0123",
        hardware_asset_id=uuid4(),
        installation_id=uuid4(),
        session_id=uuid4(),
        platform_login="seed-owner",
        activation_code="secret-activation-code",
        access_token="secret-access-token",
        refresh_token="secret-refresh-token",
    )

    serialized = json.dumps(state.evidence(), sort_keys=True)

    assert state.evidence() == {
        "tenant_provisioned": True,
        "activation_completed": True,
        "session_metadata_created": True,
        "secrets_included": False,
    }
    for secret in (
        state.account_name,
        state.account_password,
        state.hardware_id,
        str(state.hardware_asset_id),
        str(state.installation_id),
        str(state.session_id),
        state.platform_login,
        state.activation_code,
        state.access_token,
        state.refresh_token,
    ):
        assert secret not in serialized


def test_api_waits_for_auth_rate_limit_and_retries_the_request() -> None:
    attempts = 0
    delays: list[float] = []

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, request=request)
        return httpx.Response(200, request=request, json={"data": {"status": "ok"}})

    api = Api(
        "https://seed.example:7443",
        Path("unused-with-mock-transport.pem"),
        transport=httpx.MockTransport(handler),
        sleep=delays.append,
    )
    try:
        response, payload = api.request("POST", "/v1/access/login", expected=200)
    finally:
        api.close()

    assert response.status_code == 200
    assert payload == {"status": "ok"}
    assert attempts == 2
    assert delays == [13.0]


def test_d10_probe_records_only_redacted_endpoint_outcomes() -> None:
    calls: list[tuple[str, str, object]] = []

    class RecordingApi:
        def request(self, method: str, path: str, **kwargs):
            calls.append((method, path, kwargs.get("expected")))
            if method == "POST" and path == "/v1/platform/sensitive-access-grants":
                return object(), {"grant_id": str(uuid4())}
            if method == "GET" and "grant_id=" in path:
                if len([item for item in calls if item[0] == "GET"]) == 1:
                    return object(), None
                return object(), {
                    "display_name": "synthetic-only-name",
                    "contact": "synthetic-only-contact",
                }
            raise AssertionError(f"unexpected request: {method} {path}")

    result = _verify_d10_identity_access(
        RecordingApi(),
        tenant_id=uuid4(),
        subject_id=uuid4(),
        platform_token="private-platform-token",
        identity_marker="synthetic-only-name",
    )

    assert result == {
        "invalid_grant_denied": True,
        "valid_grant_disclosed": True,
    }
    assert calls[0][2] == 403
    assert calls[1][2] == 201
    assert calls[2][2] == 200
    assert "synthetic-only-name" not in json.dumps(result)
    assert "private-platform-token" not in json.dumps(result)


def test_d10_probe_rejects_denial_response_that_carries_identity_data() -> None:
    class LeakingDenialApi:
        def __init__(self) -> None:
            self.get_calls = 0

        def request(self, method: str, path: str, **_kwargs):
            if method == "GET":
                self.get_calls += 1
                if self.get_calls == 1:
                    return object(), {"display_name": "must-not-disclose"}
                return object(), {"display_name": "synthetic-only-name"}
            if method == "POST":
                assert path == "/v1/platform/sensitive-access-grants"
                return object(), {"grant_id": str(uuid4())}
            raise AssertionError(f"unexpected request: {method} {path}")

    with pytest.raises(RuntimeError, match="identity data"):
        _verify_d10_identity_access(
            LeakingDenialApi(),
            tenant_id=uuid4(),
            subject_id=uuid4(),
            platform_token="private-platform-token",
            identity_marker="must-not-disclose",
        )


@requires_bash
def test_acceptance_cleanup_preserves_failed_state_and_removes_successful_state(
    tmp_path: Path,
) -> None:
    script = ROOT / "deploy/aliyun/seed/run-live-acceptance.sh"
    state = tmp_path / "private-state.json"
    restart_marker = tmp_path / "restart-complete"
    state.write_text("private")
    restart_marker.write_text("")

    failed = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; acceptance_cleanup 1 "$2" "$3"',
            "bash",
            str(script),
            str(state),
            str(restart_marker),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert failed.returncode == 0, failed.stderr
    assert state.read_text() == "private"
    assert restart_marker.exists()
    succeeded = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; acceptance_cleanup 0 "$2" "$3"',
            "bash",
            str(script),
            str(state),
            str(restart_marker),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert succeeded.returncode == 0, succeeded.stderr
    assert not state.exists()
    assert not restart_marker.exists()


@requires_bash
def test_acceptance_resume_phase_is_derived_from_private_state(tmp_path: Path) -> None:
    script = ROOT / "deploy/aliyun/seed/run-live-acceptance.sh"
    state = tmp_path / "private-state.json"
    restart_marker = tmp_path / "restart-complete"

    def phase() -> str:
        result = subprocess.run(
            [
                "bash",
                "-c",
                'source "$1"; acceptance_phase "$2" "$3"',
                "bash",
                str(script),
                str(state),
                str(restart_marker),
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()

    assert phase() == "before-restart"
    state.write_text("private")
    assert phase() == "restart-required"
    restart_marker.write_text("")
    assert phase() == "after-restart"


@requires_bash
def test_acceptance_public_junit_path_is_next_to_redacted_json(tmp_path: Path) -> None:
    script = ROOT / "deploy/aliyun/seed/run-live-acceptance.sh"
    evidence = tmp_path / "aliyun-seed-summary.json"
    result = subprocess.run(
        [
            "bash",
            "-c",
            'source "$1"; acceptance_public_junit_path "$2"',
            "bash",
            str(script),
            str(evidence),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    assert result.stdout.strip() == str(tmp_path / "aliyun-seed-summary-postgres.xml")


def test_after_restart_resume_does_not_reacquire_a_hardware_lease(
    tmp_path: Path,
) -> None:
    state_path = tmp_path / "private-state.json"
    evidence_path = tmp_path / "evidence.json"
    state = AcceptanceState(
        tenant_id=uuid4(),
        account_name="acceptance-tenant",
        account_password="secret-password-value",
        hardware_id="usb-serial-0123456789abcdef0123",
        hardware_asset_id=uuid4(),
        installation_id=uuid4(),
        session_id=uuid4(),
        platform_login="seed-owner",
        activation_code="secret-activation-code",
        access_token="secret-access-token",
        refresh_token="secret-refresh-token",
    )
    state.write_private(state_path)
    evidence_path.write_text(
        json.dumps(
            {
                "restart_persistence_verified": False,
                "postgres_role_parity_verified": False,
            }
        )
    )
    requested_paths: list[str] = []

    class RecordingApi:
        def request(self, method: str, path: str, **kwargs):
            requested_paths.append(path)
            if path == "/v1/access/login":
                return object(), {"access_token": "replacement-access-token"}
            if path.startswith("/v1/access/hardware-lease"):
                raise AssertionError("resume must not reacquire a hardware lease")
            return object(), None

    _after(RecordingApi(), state_path, evidence_path)

    assert requested_paths[0] == "/v1/access/login"
    assert requested_paths[1].startswith("/v1/terminals/")
    assert requested_paths[1].endswith("/heartbeats")
    assert requested_paths[2] == f"/v1/sessions/{state.session_id}/status"
    assert all("hardware-lease" not in path for path in requested_paths)
    evidence = json.loads(evidence_path.read_text())
    assert evidence["restart_persistence_verified"] is True
    assert evidence["replacement_projection_after_restart"] is True


def test_seed_probe_expects_suspended_bare_session_denial_without_persistence() -> None:
    # RAY-513 R5: after suspension a bare POST /v1/sessions is 403 and creates
    # nothing; the 2026-09 probe still expected 201 (the defect RAY-120 found).
    source = (Path(__file__).parents[1] / "scripts" / "verify_seed_live.py").read_text()
    denied = source[source.index('denied_session = session.model_copy'):]
    denied = denied[: denied.index('"action": "RESTORE"')]
    assert "expected=403" in denied
    assert "expected=201" not in denied
    assert '/v1/sessions/{denied_session.session_id}/status' in denied
    assert "expected=404" in denied
