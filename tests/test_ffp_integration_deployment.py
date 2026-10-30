from __future__ import annotations

import asyncio
from uuid import uuid4

from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.server.integration import IntegrationSettings, build_integration_app


def _settings() -> IntegrationSettings:
    return IntegrationSettings(
        tenant_id="11111111-1111-4111-8111-111111111111",
        site_id="22222222-2222-4222-8222-222222222222",
        device_id="33333333-3333-4333-8333-333333333333",
        activation_code="FFP-ALIYUN-INTEGRATION-20260731",
        terminal_token_secret="terminal-secret-for-integration-only-32-bytes",
        activation_hmac_key="activation-hmac-for-integration-only-32-bytes",
        identity_encryption_key=b"e" * 32,
        identity_lookup_hmac_key=b"h" * 32,
    )


def test_environment_settings_refuse_missing_server_secrets(monkeypatch) -> None:
    for name in IntegrationSettings.required_environment_names():
        monkeypatch.delenv(name, raising=False)

    with pytest.raises(RuntimeError, match="missing required integration environment"):
        IntegrationSettings.from_environment()


def test_health_declares_ephemeral_integration_boundaries_without_secrets() -> None:
    settings = _settings()

    async def exercise():
        client = AsyncClient(
            transport=ASGITransport(app=build_integration_app(settings)),
            base_url="https://integration.test",
        )
        try:
            return await client.get("/health/live"), await client.get("/health/ready")
        finally:
            await client.aclose()

    live, ready = asyncio.run(exercise())

    assert live.status_code == 200
    assert live.json() == {"status": "ok", "environment": "integration"}
    assert ready.status_code == 200
    assert ready.json() == {
        "status": "ready",
        "environment": "integration",
        "persistence": "ephemeral",
        "object_storage": "in_memory",
    }
    combined = live.text + ready.text
    assert settings.activation_code not in combined
    assert settings.terminal_token_secret not in combined


def test_network_app_enrolls_then_accepts_terminal_bound_heartbeat() -> None:
    settings = _settings()

    async def exercise():
        client = AsyncClient(
            transport=ASGITransport(app=build_integration_app(settings)),
            base_url="https://integration.test",
        )
        try:
            enrolled = await client.post(
                "/v1/terminals/enroll",
                headers={
                    "Idempotency-Key": "aliyun-enrollment-1",
                    "X-Correlation-ID": str(uuid4()),
                },
                json={
                    "activation_code": settings.activation_code,
                    "installation_id": str(uuid4()),
                    "client_public_key": "integration-client-public-key",
                    "system": {
                        "os": "macos",
                        "os_version": "26.5",
                        "app_version": "0.1.0",
                    },
                },
            )
            assert enrolled.status_code == 201, enrolled.text
            identity = enrolled.json()["data"]
            assert identity["tenant_id"] == settings.tenant_id
            assert identity["site_id"] == settings.site_id

            heartbeat = await client.post(
                f"/v1/terminals/{identity['terminal_id']}/heartbeats",
                headers={
                    "Authorization": f"Bearer {identity['access_token']}",
                    "X-Terminal-ID": identity["terminal_id"],
                    "Idempotency-Key": "aliyun-heartbeat-1",
                },
                json={
                    "app_version": "0.1.0",
                    "config_version": "aliyun-integration/1",
                    "protocol_version": "do-p4864/1",
                    "device": {
                        "device_id": settings.device_id,
                        "model": "DO-P4864",
                        "connection_state": "READY",
                    },
                    "sync": {
                        "last_successful_sync": None,
                        "pending_sessions": 0,
                        "pending_bytes": 0,
                    },
                    "health": {
                        "disk_free_bytes": 10_000_000_000,
                        "clock_skew_seconds": 0,
                        "last_error_code": None,
                    },
                    "observed_at": identity["token_expires_at"],
                },
            )
            return identity, heartbeat
        finally:
            await client.aclose()

    identity, heartbeat = asyncio.run(exercise())
    assert heartbeat.status_code == 200, heartbeat.text
    assert heartbeat.json()["data"]["terminal_id"] == identity["terminal_id"]
