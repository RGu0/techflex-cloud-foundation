#!/usr/bin/env python3
"""Run a redacted seed-pilot lifecycle against the deployed HTTPS API."""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
import getpass
import hashlib
import json
from pathlib import Path
import secrets
import time
from uuid import UUID, uuid4

import httpx

from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    HeartbeatDevice,
    HeartbeatHealth,
    HeartbeatRequest,
    HeartbeatSync,
    IdentityProfileInput,
    ManifestSegment,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    SubjectCreateRequest,
    TestProtocol,
)
from techflex_cloud_foundation.server.seed import SeedSettings, build_seed_app


@dataclass(frozen=True, slots=True)
class AcceptanceState:
    tenant_id: UUID
    account_name: str
    account_password: str
    hardware_id: str
    hardware_asset_id: UUID
    installation_id: UUID
    session_id: UUID
    platform_login: str
    activation_code: str
    access_token: str
    refresh_token: str

    def evidence(self) -> dict[str, bool]:
        return {
            "tenant_provisioned": True,
            "activation_completed": True,
            "session_metadata_created": True,
            "secrets_included": False,
        }

    def write_private(self, path: Path) -> None:
        path.write_text(json.dumps(asdict(self), default=str), encoding="utf-8")
        path.chmod(0o600)

    @classmethod
    def read_private(cls, path: Path) -> AcceptanceState:
        value = json.loads(path.read_text(encoding="utf-8"))
        for field in ("tenant_id", "hardware_asset_id", "installation_id", "session_id"):
            value[field] = UUID(value[field])
        return cls(**value)


class Api:
    def __init__(
        self,
        base_url: str,
        ca_file: Path,
        *,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        trust_env: bool = True,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            verify=str(ca_file),
            timeout=30,
            transport=transport,
            trust_env=trust_env,
        )
        self._sleep = sleep

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        expected: int | tuple[int, ...],
        token: str | None = None,
        headers: dict[str, str] | None = None,
        json_body: dict | None = None,
        content: bytes | None = None,
    ) -> tuple[httpx.Response, object | None]:
        request_headers = dict(headers or {})
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        accepted = (expected,) if isinstance(expected, int) else expected
        for rate_limit_attempt in range(7):
            response = self._client.request(
                method,
                path,
                headers=request_headers,
                json=json_body,
                content=content,
            )
            if (
                response.status_code != 429
                or 429 in accepted
                or rate_limit_attempt == 6
            ):
                break
            retry_after = response.headers.get("Retry-After")
            delay = float(retry_after) if retry_after is not None else 13.0
            self._sleep(max(delay, 1.0))
        if response.status_code not in accepted:
            raise RuntimeError(f"{method} {path} returned HTTP {response.status_code}")
        payload = response.json() if response.content else None
        if isinstance(payload, dict) and "data" in payload:
            return response, payload["data"]
        return response, payload


async def _platform_password(
    login_name: str,
    *,
    settings: SeedSettings | None = None,
    supplied_password: str | None = None,
) -> str:
    app = await build_seed_app(settings or SeedSettings.from_env())
    try:
        async with app.state.seed_pools[2].acquire() as connection:
            count = await connection.fetchval("SELECT count(*) FROM iam.platform_identities")
        password = supplied_password or getpass.getpass(
            "New Platform owner password: " if count == 0 else "Platform owner password: "
        )
        if count == 0:
            if supplied_password is None:
                confirmation = getpass.getpass("Confirm Platform owner password: ")
                if password != confirmation:
                    raise ValueError("password confirmation does not match")
            await app.state.services.platform_identities.bootstrap_owner(
                login_name=login_name,
                display_name="Seed Platform Owner",
                password=password,
            )
        return password
    finally:
        for pool in app.state.seed_pools:
            await pool.close()


def _heartbeat(installation_id: UUID, hardware_asset_id: UUID) -> dict:
    now = datetime.now(UTC)
    return HeartbeatRequest(
        app_version="seed-live-acceptance/1",
        config_version="seed/1",
        protocol_version="do-p4864/1",
        device=HeartbeatDevice(
            device_id=hardware_asset_id,
            model="DO-P4864",
            connection_state="READY",
        ),
        sync=HeartbeatSync(
            last_successful_sync=now,
            pending_sessions=0,
            pending_bytes=0,
        ),
        health=HeartbeatHealth(
            disk_free_bytes=1_000_000,
            clock_skew_seconds=0.0,
        ),
        observed_at=now,
    ).model_dump(mode="json")


def _verify_d10_identity_access(
    api: Api,
    *,
    tenant_id: UUID,
    subject_id: UUID,
    platform_token: str,
    identity_marker: str,
) -> dict[str, bool]:
    """Probe deployed D10 endpoint behavior without serializing identity data."""

    path = f"/v1/platform/tenants/{tenant_id}/subjects/{subject_id}/identity"
    denied_response, denied_payload = api.request(
        "GET",
        f"{path}?grant_id={uuid4()}",
        expected=403,
        token=platform_token,
    )
    denied_text = str(getattr(denied_response, "text", ""))
    denied_json = json.dumps(denied_payload, sort_keys=True)
    if (
        identity_marker in denied_text
        or identity_marker in denied_json
        or (
            isinstance(denied_payload, dict)
            and {"display_name", "contact"}.intersection(denied_payload)
        )
    ):
        raise RuntimeError("D10 denial response contained identity data")
    _, grant = api.request(
        "POST",
        "/v1/platform/sensitive-access-grants",
        expected=201,
        token=platform_token,
        json_body={
            "tenant_id": str(tenant_id),
            "purpose_code": "SUPPORT_DIAGNOSIS",
            "ticket_reference": f"D10-LIVE-{uuid4().hex[:16]}",
            "requested_duration_minutes": 15,
        },
    )
    assert isinstance(grant, dict)
    _, identity = api.request(
        "GET",
        f"{path}?grant_id={grant['grant_id']}",
        expected=200,
        token=platform_token,
    )
    if not isinstance(identity, dict) or not identity.get("display_name"):
        raise RuntimeError("D10 identity disclosure response was incomplete")
    return {
        "invalid_grant_denied": True,
        "valid_grant_disclosed": True,
    }


def _before(
    api: Api,
    state_path: Path,
    evidence_path: Path,
    platform_login: str,
    *,
    settings: SeedSettings | None = None,
    platform_password: str | None = None,
    before_complete: Callable[[UUID], None] | None = None,
) -> None:
    _, ready = api.request("GET", "/health/ready", expected=200)
    resolved_platform_password = asyncio.run(
        _platform_password(
            platform_login,
            settings=settings,
            supplied_password=platform_password,
        )
    )
    _, platform = api.request(
        "POST",
        "/v1/platform/login",
        expected=200,
        json_body={"login_name": platform_login, "password": resolved_platform_password},
    )
    assert isinstance(platform, dict)
    platform_token = str(platform["access_token"])
    unique = uuid4().hex
    account_name = f"accept-{unique[:12]}"
    hardware_id = f"usb-serial-{unique[:20]}"
    account_password = secrets.token_urlsafe(24)
    _, provisioned = api.request(
        "POST",
        "/v1/platform/tenants",
        expected=201,
        token=platform_token,
        json_body={
            "tenant_name": f"Aliyun acceptance {unique[:8]}",
            "account_name": account_name,
            "hardware_id": hardware_id,
            "license_period_months": 6,
        },
    )
    assert isinstance(provisioned, dict)
    first_installation = uuid4()
    _, activated = api.request(
        "POST",
        "/v1/access/activate",
        expected=201,
        json_body={
            "account_name": account_name,
            "activation_code": provisioned["activation_code"],
            "password": account_password,
            "password_confirmation": account_password,
            "hardware_id": hardware_id,
            "client_installation_id": str(first_installation),
        },
    )
    assert isinstance(activated, dict)
    _, first_lease = api.request(
        "POST",
        "/v1/access/hardware-lease",
        expected=201,
        token=str(activated["access_token"]),
        json_body={
            "hardware_id": hardware_id,
            "client_installation_id": str(first_installation),
        },
    )
    assert isinstance(first_lease, dict)
    second_installation = uuid4()
    _, logged_in = api.request(
        "POST",
        "/v1/access/login",
        expected=200,
        json_body={
            "account_name": account_name,
            "password": account_password,
            "client_installation_id": str(second_installation),
        },
    )
    assert isinstance(logged_in, dict)
    identity_marker = f"seed-d10-{unique[:8]}"
    api.request(
        "POST",
        "/v1/access/hardware-lease",
        expected=409,
        token=str(logged_in["access_token"]),
        json_body={
            "hardware_id": hardware_id,
            "client_installation_id": str(second_installation),
        },
    )
    api.request(
        "DELETE",
        f"/v1/access/hardware-lease/{first_lease['lease_id']}",
        expected=200,
        token=str(activated["access_token"]),
    )
    _, second_lease = api.request(
        "POST",
        "/v1/access/hardware-lease",
        expected=201,
        token=str(logged_in["access_token"]),
        json_body={
            "hardware_id": hardware_id,
            "client_installation_id": str(second_installation),
        },
    )
    assert isinstance(second_lease, dict)
    hardware_asset_id = UUID(str(logged_in["hardware_asset_id"]))
    api.request(
        "POST",
        f"/v1/terminals/{second_installation}/heartbeats",
        expected=200,
        token=str(logged_in["access_token"]),
        headers={
            "X-Terminal-ID": str(second_installation),
            "Idempotency-Key": f"heartbeat-{unique}",
        },
        json_body=_heartbeat(second_installation, hardware_asset_id),
    )

    now = datetime.now(UTC)
    subject_id, consent_id, session_id = uuid4(), uuid4(), uuid4()
    api.request(
        "POST",
        "/v1/subjects",
        expected=201,
        token=str(logged_in["access_token"]),
        headers={"Idempotency-Key": f"subject-{unique}"},
        json_body=SubjectCreateRequest(
            subject_uuid=subject_id,
            identity_profile=IdentityProfileInput(
                display_name=identity_marker,
                contact=f"d10-{unique[:8]}@example.invalid",
            ),
        ).model_dump(mode="json"),
    )
    d10_outcomes = _verify_d10_identity_access(
        api,
        tenant_id=UUID(str(provisioned["tenant_id"])),
        subject_id=subject_id,
        platform_token=platform_token,
        identity_marker=identity_marker,
    )
    api.request(
        "POST",
        "/v1/consents",
        expected=201,
        token=str(logged_in["access_token"]),
        headers={"Idempotency-Key": f"consent-{unique}"},
        json_body=ConsentCreateRequest(
            consent_record_id=consent_id,
            subject_uuid=subject_id,
            policy_version="seed-acceptance/1",
            purpose_codes=("SCREENING_SERVICE",),
            data_categories=("PRESSURE_RAW",),
            granted_at=now,
            evidence_type="OPERATOR_CONFIRMED",
            terminal_signature="seed-acceptance-signature",
        ).model_dump(mode="json"),
    )
    session = SessionCreateRequest(
        session_id=session_id,
        subject_uuid=subject_id,
        consent_record_id=consent_id,
        site_id=None,
        terminal_id=second_installation,
        client_installation_id=second_installation,
        device_id=hardware_asset_id,
        test_protocol=TestProtocol(id="seed-acceptance", version="1.0"),
        versions=SessionVersions(
            app="seed-live-acceptance/1",
            protocol_profile="do-p4864/1",
            payload_schema="raw-segment/1",
            calibration="synthetic/1",
        ),
        started_at=now,
    )
    api.request(
        "POST",
        "/v1/sessions",
        expected=201,
        token=str(logged_in["access_token"]),
        headers={"Idempotency-Key": f"session-{unique}"},
        json_body=session.model_dump(mode="json"),
    )
    api.request(
        "PATCH",
        f"/v1/platform/licenses/{provisioned['license_id']}",
        expected=200,
        token=platform_token,
        json_body={"action": "SUSPEND", "reason_code": "LIVE_ACCEPTANCE"},
    )
    _, suspended = api.request(
        "POST",
        "/v1/access/refresh",
        expected=200,
        json_body={
            "refresh_token": logged_in["refresh_token"],
            "client_installation_id": str(second_installation),
        },
    )
    assert isinstance(suspended, dict)
    if suspended["capabilities"]["allow_new_test"]:
        raise RuntimeError("suspended License still allows a new test")

    payload = b"seed-live-acceptance-encrypted-placeholder"
    digest = hashlib.sha256(payload).hexdigest()
    metadata = SegmentMetadata(
        segment_index=0,
        start_frame_index=0,
        frame_count=10,
        start_monotonic_ns=100,
        end_monotonic_ns=200,
        compression="zstd",
        cipher="aes-256-gcm",
        size_bytes=len(payload),
        sha256=digest,
        payload_schema_version="raw-segment/1",
    )
    api.request(
        "PUT",
        f"/v1/sessions/{session_id}/segments/0",
        expected=201,
        token=str(suspended["access_token"]),
        headers={
            "X-Content-SHA256": digest,
            "X-Schema-Version": "raw-segment/1",
            "X-Segment-Metadata": encode_segment_metadata(metadata),
            "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream",
        },
        content=payload,
    )
    manifest = SessionManifest(
        segment_count=1,
        total_frames=10,
        total_bytes=len(payload),
        segments=(
            ManifestSegment(index=0, sha256=digest, size_bytes=len(payload), frame_count=10),
        ),
        ended_at=now + timedelta(seconds=1),
        local_quality_outcome="VALID",
    )
    completion_headers = {
        "Idempotency-Key": f"complete-{unique}",
        "X-Content-SHA256": canonical_sha256(manifest),
        "X-Schema-Version": "session-manifest/1",
    }
    completion_body = manifest.model_dump(mode="json")
    if before_complete is not None:
        before_complete(session_id)
    completion, _ = api.request(
        "POST",
        f"/v1/sessions/{session_id}/complete",
        expected=(200, 503),
        token=str(suspended["access_token"]),
        headers=completion_headers,
        json_body=completion_body,
    )
    completion_retried = completion.status_code == 503
    if completion_retried:
        api.request(
            "POST",
            f"/v1/sessions/{session_id}/complete",
            expected=200,
            token=str(suspended["access_token"]),
            headers=completion_headers,
            json_body=completion_body,
        )
    denied_session = session.model_copy(update={"session_id": uuid4()})
    api.request(
        "POST",
        "/v1/sessions",
        # RAY-513: a suspended License cannot register a new session without a
        # pre-issued capture grant or migration permit, and nothing is persisted.
        expected=403,
        token=str(suspended["access_token"]),
        headers={"Idempotency-Key": f"suspended-{unique}"},
        json_body=denied_session.model_dump(mode="json"),
    )
    api.request(
        "GET",
        f"/v1/sessions/{denied_session.session_id}/status",
        expected=404,
        token=str(suspended["access_token"]),
    )
    api.request(
        "PATCH",
        f"/v1/platform/licenses/{provisioned['license_id']}",
        expected=200,
        token=platform_token,
        json_body={"action": "RESTORE"},
    )
    _, restored = api.request(
        "POST",
        "/v1/access/refresh",
        expected=200,
        json_body={
            "refresh_token": suspended["refresh_token"],
            "client_installation_id": str(second_installation),
        },
    )
    assert isinstance(restored, dict)
    if not restored["capabilities"]["allow_new_test"]:
        raise RuntimeError("restored License does not allow a new test")
    api.request(
        "DELETE",
        f"/v1/access/hardware-lease/{second_lease['lease_id']}",
        expected=200,
        token=str(restored["access_token"]),
    )
    invalid, _ = api.request(
        "POST",
        "/v1/access/login",
        expected=401,
        json_body={
            "account_name": account_name,
            "password": "invalid-password-value",
            "client_installation_id": str(uuid4()),
        },
    )
    if account_name in invalid.text or "token" in invalid.text.lower():
        raise RuntimeError("invalid-login response leaked account or token material")
    api.request(
        "GET",
        "/v1/access/license",
        expected=401,
        token=platform_token,
    )

    state = AcceptanceState(
        tenant_id=UUID(str(provisioned["tenant_id"])),
        account_name=account_name,
        account_password=account_password,
        hardware_id=hardware_id,
        hardware_asset_id=hardware_asset_id,
        installation_id=second_installation,
        session_id=session_id,
        platform_login=platform_login,
        activation_code=str(provisioned["activation_code"]),
        access_token=str(restored["access_token"]),
        refresh_token=str(restored["refresh_token"]),
    )
    state.write_private(state_path)
    evidence = {
        "schema_version": "aliyun-seed-live-evidence/1",
        "generated_at": datetime.now(UTC).isoformat(),
        "mode": "aliyun-seed-integration",
        "readiness": ready,
        **state.evidence(),
        "replacement_installation_login": True,
        "concurrent_hardware_lease_denied": True,
        "heartbeat_recorded": True,
        "suspended_new_test_denied": True,
        "upload_after_suspension_completed": True,
        "completion_response_dropped_then_retried": completion_retried,
        "license_restored": True,
        "invalid_login_safe": True,
        "platform_token_rejected_by_tenant_api": True,
        "d10_identity_probe": d10_outcomes,
        "restart_persistence_verified": False,
        "postgres_role_parity_verified": False,
    }
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def _after(api: Api, state_path: Path, evidence_path: Path) -> None:
    state = AcceptanceState.read_private(state_path)
    installation = uuid4()
    _, session = api.request(
        "POST",
        "/v1/access/login",
        expected=200,
        json_body={
            "account_name": state.account_name,
            "password": state.account_password,
            "client_installation_id": str(installation),
        },
    )
    assert isinstance(session, dict)
    api.request(
        "POST",
        f"/v1/terminals/{installation}/heartbeats",
        expected=200,
        token=str(session["access_token"]),
        headers={
            "X-Terminal-ID": str(installation),
            "Idempotency-Key": f"restart-heartbeat-{uuid4()}",
        },
        json_body=_heartbeat(installation, state.hardware_asset_id),
    )
    api.request(
        "GET",
        f"/v1/sessions/{state.session_id}/status",
        expected=200,
        token=str(session["access_token"]),
    )
    evidence = json.loads(evidence_path.read_text())
    evidence["restart_persistence_verified"] = True
    evidence["replacement_projection_after_restart"] = True
    evidence["generated_at"] = datetime.now(UTC).isoformat()
    evidence_path.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", choices=("before-restart", "after-restart"), required=True)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--ca-file", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--platform-login", default="seed-owner")
    args = parser.parse_args()
    api = Api(args.base_url, args.ca_file)
    try:
        if args.phase == "before-restart":
            _before(api, args.state, args.evidence, args.platform_login)
        else:
            _after(api, args.state, args.evidence)
    finally:
        api.close()


if __name__ == "__main__":
    main()
