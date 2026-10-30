from __future__ import annotations

import asyncio
import base64
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.server.local_lab import (
    FaultController,
    FaultInjectingApp,
    FaultKind,
    FaultRule,
    LocalLabPaths,
    LocalLabSettings,
    build_local_lab_app,
    validate_loopback_host,
)
from techflex_cloud_foundation.server.seed import SeedSettings

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_runtime_root_rejects_repository_path() -> None:
    with pytest.raises(ValueError, match="outside the repository"):
        LocalLabPaths.create(REPOSITORY_ROOT / "unsafe-local-lab")


def test_runtime_root_creates_private_state_directories(tmp_path: Path) -> None:
    paths = LocalLabPaths.create(tmp_path / "local-lab")

    assert paths.root == (tmp_path / "local-lab").resolve()
    assert paths.runtime.is_dir()
    assert paths.audit.is_dir()
    assert paths.objects.is_dir()
    assert paths.secrets.is_dir()


def test_loopback_host_is_required() -> None:
    assert validate_loopback_host("127.0.0.1") == "127.0.0.1"
    assert validate_loopback_host("::1") == "::1"
    with pytest.raises(ValueError, match="loopback"):
        validate_loopback_host("0.0.0.0")


def test_settings_read_private_runtime_root_from_environment(tmp_path: Path) -> None:
    settings = LocalLabSettings.from_environment(
        {"FFP_LOCAL_LAB_RUNTIME_ROOT": str(tmp_path / "local-lab")}
    )

    assert settings.bind_host == "127.0.0.1"
    assert settings.paths.root == (tmp_path / "local-lab").resolve()


def test_fault_rule_returns_503_and_records_redacted_audit(tmp_path: Path) -> None:
    async def exercise() -> tuple[int, str]:
        app = FastAPI()

        @app.post("/v1/ingestion/sessions")
        async def ingest() -> dict[str, str]:
            return {"status": "INGESTED"}

        paths = LocalLabPaths.create(tmp_path / "local-lab")
        controller = FaultController("local-control-token", paths.audit)
        rule = FaultRule.create(
            kind=FaultKind.UNAVAILABLE,
            method="POST",
            path_prefix="/v1/ingestion",
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
        )
        controller.apply("local-control-token", rule)
        async with AsyncClient(
            transport=ASGITransport(app=FaultInjectingApp(app, controller)),
            base_url="https://127.0.0.1:8743",
        ) as client:
            response = await client.post(
                "/v1/ingestion/sessions",
                headers={"X-Correlation-ID": "sensitive-correlation-id"},
            )
        return response.status_code, (paths.audit / "fault-events.jsonl").read_text()

    status, audit = asyncio.run(exercise())

    assert status == 503
    assert "sensitive-correlation-id" not in audit
    assert "unavailable" in audit


def test_drop_after_upstream_executes_once_then_allows_retry(tmp_path: Path) -> None:
    async def exercise() -> tuple[int, int, int]:
        calls = 0
        app = FastAPI()

        @app.post("/v1/ingestion/sessions/session-1/complete")
        async def complete() -> dict[str, str]:
            nonlocal calls
            calls += 1
            return {"status": "INGESTED"}

        paths = LocalLabPaths.create(tmp_path / "local-lab")
        controller = FaultController("local-control-token", paths.audit)
        controller.apply(
            "local-control-token",
            FaultRule.create(
                kind=FaultKind.DROP_AFTER_UPSTREAM,
                method="POST",
                path_prefix="/v1/ingestion/sessions/session-1/complete",
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
            ),
        )
        async with AsyncClient(
            transport=ASGITransport(app=FaultInjectingApp(app, controller)),
            base_url="https://127.0.0.1:8743",
        ) as client:
            dropped = await client.post("/v1/ingestion/sessions/session-1/complete")
            retried = await client.post("/v1/ingestion/sessions/session-1/complete")
        return dropped.status_code, retried.status_code, calls

    dropped_status, retry_status, calls = asyncio.run(exercise())

    assert dropped_status == 503
    assert retry_status == 200
    assert calls == 2


def test_exact_path_rule_does_not_match_a_shared_prefix(tmp_path: Path) -> None:
    async def exercise() -> tuple[int, int]:
        app = FastAPI()

        @app.post("/v1/sessions/one/complete")
        async def complete() -> dict[str, str]:
            return {"status": "INGESTED"}

        @app.post("/v1/sessions/one/segments")
        async def segment() -> dict[str, str]:
            return {"status": "stored"}

        paths = LocalLabPaths.create(tmp_path / "local-lab")
        controller = FaultController("local-control-token", paths.audit)
        controller.apply(
            "local-control-token",
            FaultRule.create(
                kind=FaultKind.UNAVAILABLE,
                method="POST",
                path_prefix="/v1/sessions/one",
                path_exact="/v1/sessions/one/complete",
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
            ),
        )
        async with AsyncClient(
            transport=ASGITransport(app=FaultInjectingApp(app, controller)),
            base_url="https://127.0.0.1:8743",
        ) as client:
            stored = await client.post("/v1/sessions/one/segments")
            faulted = await client.post("/v1/sessions/one/complete")
        return stored.status_code, faulted.status_code

    stored, faulted = asyncio.run(exercise())

    assert stored == 200
    assert faulted == 503


def test_control_route_requires_token_and_enables_a_finite_rule(tmp_path: Path) -> None:
    async def exercise() -> tuple[int, int, int]:
        app = FastAPI()

        @app.get("/healthy")
        async def healthy() -> dict[str, str]:
            return {"status": "ok"}

        paths = LocalLabPaths.create(tmp_path / "local-lab")
        wrapped = FaultInjectingApp(app, FaultController("local-control-token", paths.audit))
        async with AsyncClient(
            transport=ASGITransport(app=wrapped), base_url="https://127.0.0.1:8743"
        ) as client:
            denied = await client.post("/__local_lab/control/rules", json={})
            enabled = await client.post(
                "/__local_lab/control/rules",
                headers={"X-Local-Lab-Control-Token": "local-control-token"},
                json={
                    "kind": "unavailable",
                    "method": "GET",
                    "path_prefix": "/healthy",
                    "applications": 1,
                    "expires_in_seconds": 30,
                },
            )
            faulted = await client.get("/healthy")
        return denied.status_code, enabled.status_code, faulted.status_code

    denied, enabled, faulted = asyncio.run(exercise())

    assert denied == 403
    assert enabled == 201
    assert faulted == 503


def test_throttle_rule_preserves_the_complete_response_body(tmp_path: Path) -> None:
    async def exercise() -> bytes:
        app = FastAPI()

        @app.get("/healthy")
        async def healthy() -> dict[str, str]:
            return {"status": "ok"}

        paths = LocalLabPaths.create(tmp_path / "local-lab")
        controller = FaultController("local-control-token", paths.audit)
        controller.apply(
            "local-control-token",
            FaultRule.create(
                kind=FaultKind.THROTTLE,
                method="GET",
                path_prefix="/healthy",
                expires_at=datetime.now(UTC) + timedelta(minutes=1),
                throttle_bytes_per_second=100,
            ),
        )
        async with AsyncClient(
            transport=ASGITransport(app=FaultInjectingApp(app, controller)),
            base_url="https://127.0.0.1:8743",
        ) as client:
            return (await client.get("/healthy")).content

    assert asyncio.run(exercise()) == b'{"status":"ok"}'


def test_control_restart_requires_token_and_calls_local_supervisor(tmp_path: Path) -> None:
    async def exercise() -> tuple[int, int, bool]:
        restarted = False

        def request_restart() -> None:
            nonlocal restarted
            restarted = True

        paths = LocalLabPaths.create(tmp_path / "local-lab")
        wrapped = FaultInjectingApp(
            FastAPI(),
            FaultController("local-control-token", paths.audit),
            restart_callback=request_restart,
        )
        async with AsyncClient(
            transport=ASGITransport(app=wrapped), base_url="https://127.0.0.1:8743"
        ) as client:
            denied = await client.post("/__local_lab/control/restart")
            accepted = await client.post(
                "/__local_lab/control/restart",
                headers={"X-Local-Lab-Control-Token": "local-control-token"},
            )
        return denied.status_code, accepted.status_code, restarted

    denied, accepted, restarted = asyncio.run(exercise())

    assert denied == 403
    assert accepted == 202
    assert restarted is True


def test_local_lab_wraps_persistent_seed_composition(tmp_path: Path) -> None:
    async def exercise() -> int:
        settings = SeedSettings(
            migration_dsn="postgresql://migration@127.0.0.1/ffp",
            tenant_dsn="postgresql://tenant@127.0.0.1/ffp",
            activation_dsn="postgresql://activation@127.0.0.1/ffp",
            platform_dsn="postgresql://platform@127.0.0.1/ffp",
            tenant_token_secret="t" * 40, platform_token_secret="p" * 40,
            tenant_refresh_hmac_key="r" * 40, platform_refresh_hmac_key="q" * 40,
            tenant_login_hmac_key="l" * 40, platform_login_hmac_key="o" * 40,
            activation_hmac_key="a" * 40,
            identity_lookup_hmac_key="i" * 40,
            identity_encryption_key_b64=base64.b64encode(b"e" * 32).decode(),
            license_private_key_b64=base64.b64encode(b"p" * 32).decode(), license_key_id="local-lab/1",
            object_root=tmp_path / "objects", public_base_url="https://127.0.0.1:8743",
            trusted_proxies=("127.0.0.1",),
        )
        class Pool:
            def acquire(self): return self
            async def __aenter__(self): return self
            async def __aexit__(self, *_): return None
            async def fetchval(self, _): return 1
            async def close(self): return None
        async def pool_factory(**_): return Pool()
        app = await build_local_lab_app(
            settings, "local-control-token", LocalLabPaths.create(tmp_path / "lab").audit,
            pool_factory=pool_factory,
        )
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://127.0.0.1") as client:
            return (await client.get("/health/ready")).status_code
    assert asyncio.run(exercise()) == 200


def test_local_lab_rejects_non_loopback_seed_endpoint(tmp_path: Path) -> None:
    async def exercise() -> None:
        paths = LocalLabPaths.create(tmp_path / "local-lab")
        settings = SeedSettings(
            migration_dsn="postgresql://migration@127.0.0.1/ffp",
            tenant_dsn="postgresql://tenant@127.0.0.1/ffp",
            activation_dsn="postgresql://activation@127.0.0.1/ffp",
            platform_dsn="postgresql://platform@127.0.0.1/ffp",
            tenant_token_secret="t" * 40, platform_token_secret="p" * 40,
            tenant_refresh_hmac_key="r" * 40, platform_refresh_hmac_key="q" * 40,
            tenant_login_hmac_key="l" * 40, platform_login_hmac_key="o" * 40,
            activation_hmac_key="a" * 40, identity_lookup_hmac_key="i" * 40,
            identity_encryption_key_b64=base64.b64encode(b"e" * 32).decode(),
            license_private_key_b64=base64.b64encode(b"p" * 32).decode(), license_key_id="local-lab/1",
            object_root=paths.objects, public_base_url="https://127.0.0.1:8743",
            trusted_proxies=("127.0.0.1",),
        )
        with pytest.raises(ValueError, match="loopback"):
            await build_local_lab_app(
                replace(settings, public_base_url="https://integration.example.test"),
                "local-control-token", paths.audit,
            )

    asyncio.run(exercise())
