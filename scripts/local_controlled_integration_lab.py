#!/usr/bin/env python3
"""Operate the private, loopback-only RAY-428 integration fault lab."""

from __future__ import annotations

import argparse
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
import ipaddress
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
from urllib.parse import quote, urlparse, urlunparse
from uuid import UUID

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import httpx

from scripts.verify_seed_live import Api, _after, _before
from techflex_cloud_foundation.server.local_lab import LocalLabPaths, validate_loopback_host
from techflex_cloud_foundation.server.seed import SeedSettings

SERVICE_ROLES = {
    "migration": "ffp_ray428_lab_migration",
    "tenant": "ffp_ray428_lab_tenant",
    "activation": "ffp_ray428_lab_activation",
    "platform": "ffp_ray428_lab_platform",
}
REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("preflight", "bootstrap", "serve", "exercise"))
    parser.add_argument("--runtime-root", type=Path, required=True)
    parser.add_argument("--bind-host", default="127.0.0.1")
    parser.add_argument("--bind-port", type=int, default=8743)
    parser.add_argument("--administration-dsn", required=True)
    return parser


def validate_postgres_administration_dsn(value: str) -> str:
    endpoint = urlparse(value)
    if endpoint.scheme not in {"postgres", "postgresql"} or endpoint.hostname is None:
        raise ValueError("local lab administration DSN must be PostgreSQL on a loopback host")
    try:
        validate_loopback_host(endpoint.hostname)
    except ValueError as error:
        raise ValueError("local lab administration DSN must use a loopback host") from error
    return value


def service_dsns(administration_dsn: str) -> dict[str, str]:
    """Derive the four distinct local service identities from the admin DSN."""

    validate_postgres_administration_dsn(administration_dsn)
    endpoint = urlparse(administration_dsn)
    assert endpoint.hostname is not None
    host = endpoint.hostname if ":" not in endpoint.hostname else f"[{endpoint.hostname}]"
    port = f":{endpoint.port}" if endpoint.port is not None else ""
    password = f":{quote(endpoint.password, safe='')}" if endpoint.password else ""
    return {
        name: urlunparse(
            (
                endpoint.scheme,
                f"{quote(role, safe='')}{password}@{host}{port}",
                endpoint.path,
                endpoint.params,
                endpoint.query,
                endpoint.fragment,
            )
        )
        for name, role in SERVICE_ROLES.items()
    }


def _psql() -> str:
    executable = shutil.which("psql")
    if executable is None:
        candidate = Path("C:/Program Files/PostgreSQL/16/bin/psql.exe")
        if candidate.is_file():
            return str(candidate)
        raise RuntimeError("psql is required to bootstrap the local fault lab")
    return executable


def _run_psql(administration_dsn: str, *arguments: str) -> None:
    subprocess.run(
        [_psql(), "--dbname", administration_dsn, "--no-password", "--set", "ON_ERROR_STOP=1", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )


def _psql_output(administration_dsn: str, *arguments: str) -> str:
    completed = subprocess.run(
        [_psql(), "--dbname", administration_dsn, "--no-password", "--tuples-only", "--no-align", *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def bootstrap(administration_dsn: str) -> dict[str, str]:
    """Create test-only roles and apply the committed local seed migrations."""

    validate_postgres_administration_dsn(administration_dsn)
    dsns = service_dsns(administration_dsn)
    role_sql = "\n".join(
        f"CREATE ROLE {role} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS;"
        for role in SERVICE_ROLES.values()
    )
    guarded = "DO $$ BEGIN\n" + "\n".join(
        f"IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{role}') THEN {statement} END IF;"
        for role, statement in zip(SERVICE_ROLES.values(), role_sql.splitlines(), strict=True)
    ) + "\nEND $$;"
    _run_psql(administration_dsn, "--command", guarded)
    _run_psql(
        administration_dsn,
        "--command",
        " ".join(f"ALTER ROLE {role} INHERIT;" for role in SERVICE_ROLES.values()),
    )
    _run_psql(
        administration_dsn,
        "--command",
        "CREATE TABLE IF NOT EXISTS public.ffp_local_lab_migrations (name text PRIMARY KEY);",
    )
    for migration in sorted((REPOSITORY_ROOT / "src" / "techflex_cloud_foundation" / "schema" / "sql").glob("*.sql")):
        escaped_name = migration.name.replace("'", "''")
        if _psql_output(
            administration_dsn,
            "--command",
            f"SELECT 1 FROM public.ffp_local_lab_migrations WHERE name = '{escaped_name}';",
        ) == "1":
            continue
        _run_psql(administration_dsn, "--file", str(migration))
        _run_psql(
            administration_dsn,
            "--command",
            f"INSERT INTO public.ffp_local_lab_migrations(name) VALUES ('{escaped_name}');",
        )
    _run_psql(
        administration_dsn,
        "--command",
        "GRANT ffp_tenant_app TO ffp_ray428_lab_tenant WITH INHERIT TRUE; "
        "GRANT ffp_activation_app TO ffp_ray428_lab_activation WITH INHERIT TRUE; "
        "GRANT ffp_platform_app TO ffp_ray428_lab_platform WITH INHERIT TRUE;",
    )
    return dsns


def ensure_tls_material(paths: LocalLabPaths, bind_host: str) -> tuple[Path, Path]:
    """Create a short-lived loopback TLS certificate only in private lab state."""

    host = validate_loopback_host(bind_host)
    certificate = paths.secrets / "loopback-cert.pem"
    private_key = paths.secrets / "loopback-key.pem"
    if certificate.is_file() and private_key.is_file():
        return certificate, private_key
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(host))]), critical=False)
        .sign(key, hashes.SHA256())
    )
    private_key.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return certificate, private_key


def preflight(runtime_root: Path, bind_host: str, administration_dsn: str) -> LocalLabPaths:
    """Validate the non-synchronised local boundary before any service action."""

    validate_loopback_host(bind_host)
    validate_postgres_administration_dsn(administration_dsn)
    return LocalLabPaths.create(runtime_root)


def _seed_settings(paths: LocalLabPaths, dsns: dict[str, str], host: str, port: int) -> tuple[SeedSettings, str]:
    secret_path = paths.secrets / "seed-settings.json"
    if secret_path.is_file():
        values = json.loads(secret_path.read_text(encoding="utf-8"))
        if "platform_owner_password" not in values:
            values["platform_owner_password"] = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
            secret_path.write_text(json.dumps(values), encoding="utf-8")
    else:
        root = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
        values = {
            "control_token": root,
            "tenant_token_secret": root + "t",
            "platform_token_secret": root + "p",
            "tenant_refresh_hmac_key": root + "tr",
            "platform_refresh_hmac_key": root + "pr",
            "tenant_login_hmac_key": root + "tl",
            "platform_login_hmac_key": root + "pl",
            "activation_hmac_key": root + "a",
            "identity_lookup_hmac_key": root + "i",
            "identity_encryption_key_b64": base64.b64encode(os.urandom(32)).decode(),
            "license_private_key_b64": base64.b64encode(os.urandom(32)).decode(),
            "platform_owner_password": base64.urlsafe_b64encode(os.urandom(32)).decode("ascii"),
        }
        secret_path.write_text(json.dumps(values), encoding="utf-8")
    settings = SeedSettings(
        migration_dsn=dsns["migration"],
        tenant_dsn=dsns["tenant"],
        activation_dsn=dsns["activation"],
        platform_dsn=dsns["platform"],
        tenant_token_secret=values["tenant_token_secret"],
        platform_token_secret=values["platform_token_secret"],
        tenant_refresh_hmac_key=values["tenant_refresh_hmac_key"],
        platform_refresh_hmac_key=values["platform_refresh_hmac_key"],
        tenant_login_hmac_key=values["tenant_login_hmac_key"],
        platform_login_hmac_key=values["platform_login_hmac_key"],
        activation_hmac_key=values["activation_hmac_key"],
        identity_lookup_hmac_key=values["identity_lookup_hmac_key"],
        identity_encryption_key_b64=values["identity_encryption_key_b64"],
        license_private_key_b64=values["license_private_key_b64"],
        license_key_id="local-lab/1",
        object_root=paths.objects,
        validation_telemetry_root=paths.runtime / "validation-telemetry",
        public_base_url=f"https://{host}:{port}",
        trusted_proxies=(host,),
    )
    return settings, values["control_token"]


def _control_request(
    base_url: str,
    certificate: Path,
    token: str,
    path: str,
    payload: dict[str, object] | None = None,
) -> httpx.Response:
    with httpx.Client(
        base_url=base_url,
        verify=str(certificate),
        timeout=30,
        trust_env=False,
    ) as client:
        return client.post(
            path,
            headers={"X-Local-Lab-Control-Token": token},
            json=payload,
        )


def _enable_rule(
    base_url: str,
    certificate: Path,
    token: str,
    *,
    kind: str,
    method: str,
    path: str,
    delay_seconds: float = 0.0,
    throttle_bytes_per_second: int | None = None,
) -> None:
    payload: dict[str, object] = {
        "kind": kind,
        "method": method,
        "path_prefix": path,
        "path_exact": path,
        "expires_in_seconds": 60,
        "applications": 1,
        "delay_seconds": delay_seconds,
    }
    if throttle_bytes_per_second is not None:
        payload["throttle_bytes_per_second"] = throttle_bytes_per_second
    response = _control_request(base_url, certificate, token, "/__local_lab/control/rules", payload)
    if response.status_code != 201:
        raise RuntimeError(f"local fault control rejected {kind}: HTTP {response.status_code}")


def _wait_ready(api: Api, *, timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        try:
            api.request("GET", "/health/ready", expected=200)
            return
        except (httpx.HTTPError, RuntimeError):
            time.sleep(0.2)
    raise RuntimeError("local supervisor did not restore readiness after restart")


def _loopback_get(base_url: str, certificate: Path, path: str) -> tuple[int, float]:
    with httpx.Client(
        base_url=base_url,
        verify=str(certificate),
        timeout=30,
        trust_env=False,
    ) as client:
        response = client.get(path)
    return response.status_code, time.monotonic()


def _assert_delayed_ack_reorders_responses(
    base_url: str,
    certificate: Path,
    token: str,
) -> bool:
    """Delay one loopback response and prove a later request is acknowledged first."""

    _enable_rule(
        base_url,
        certificate,
        token,
        kind="latency",
        method="GET",
        path="/health/live",
        delay_seconds=0.2,
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        delayed = executor.submit(_loopback_get, base_url, certificate, "/health/live")
        time.sleep(0.05)
        second_status, second_finished = _loopback_get(base_url, certificate, "/health/live")
        first_status, first_finished = delayed.result(timeout=30)
    return first_status == 200 and second_status == 200 and second_finished < first_finished


def _server_completion_evidence(administration_dsn: str, state_path: Path) -> dict[str, bool]:
    """Read only the redacted completion facts for the private test session."""

    state = json.loads(state_path.read_text(encoding="utf-8"))
    session_id = str(UUID(str(state["session_id"])))
    status = _psql_output(
        administration_dsn,
        "--command",
        "SELECT ingest_status || ':' || validity_status "
        f"FROM screening.sessions WHERE session_id = '{session_id}';",
    )
    idempotency = _psql_output(
        administration_dsn,
        "--command",
        "SELECT EXISTS (SELECT 1 FROM ops.idempotency_keys "
        f"WHERE resource_id = '{session_id}'::uuid);",
    )
    return {
        "server_ingested_valid": status == "INGESTED:VALID",
        "server_idempotency_recorded": idempotency == "t",
    }


def exercise(paths: LocalLabPaths, host: str, port: int, administration_dsn: str) -> Path:
    """Exercise the persistent local data plane through finite fault controls."""

    settings, token = _seed_settings(paths, bootstrap(administration_dsn), host, port)
    certificate, _ = ensure_tls_material(paths, host)
    base_url = f"https://{host}:{port}"
    state_path = paths.secrets / "acceptance-state.json"
    lifecycle_path = paths.audit / "seed-lifecycle.json"
    summary_path = paths.audit / "local-lab-acceptance.json"
    values = json.loads((paths.secrets / "seed-settings.json").read_text(encoding="utf-8"))
    platform_owner_password = str(values["platform_owner_password"])
    api = Api(base_url, certificate, trust_env=False)
    try:
        _enable_rule(
            base_url,
            certificate,
            token,
            kind="unavailable",
            method="GET",
            path="/health/ready",
        )
        unavailable, _ = api.request("GET", "/health/ready", expected=503)
        recovered, _ = api.request("GET", "/health/ready", expected=200)
        _enable_rule(
            base_url,
            certificate,
            token,
            kind="latency",
            method="GET",
            path="/health/live",
            delay_seconds=0.2,
        )
        started = time.monotonic()
        delayed, _ = api.request("GET", "/health/live", expected=200)
        latency_ms = round((time.monotonic() - started) * 1000)
        delayed_out_of_order_ack = _assert_delayed_ack_reorders_responses(
            base_url,
            certificate,
            token,
        )
        api.close()
        api = Api(base_url, certificate, trust_env=False)
        _enable_rule(
            base_url,
            certificate,
            token,
            kind="throttle",
            method="GET",
            path="/health/ready",
            throttle_bytes_per_second=100,
        )
        throttled, _ = api.request("GET", "/health/ready", expected=200)

        def drop_completion(session_id: object) -> None:
            _enable_rule(
                base_url,
                certificate,
                token,
                kind="drop_after_upstream",
                method="POST",
                path=f"/v1/sessions/{session_id}/complete",
            )

        _before(
            api,
            state_path,
            lifecycle_path,
            "local-lab-owner",
            settings=settings,
            platform_password=platform_owner_password,
            before_complete=drop_completion,
        )
        restart = _control_request(base_url, certificate, token, "/__local_lab/control/restart")
        if restart.status_code != 202:
            raise RuntimeError(f"local supervisor rejected restart: HTTP {restart.status_code}")
        api.close()
        api = Api(base_url, certificate, trust_env=False)
        _wait_ready(api)
        _after(api, state_path, lifecycle_path)
    finally:
        api.close()

    lifecycle = json.loads(lifecycle_path.read_text(encoding="utf-8"))
    server = _server_completion_evidence(administration_dsn, state_path)
    fault_audit = paths.audit / "fault-events.jsonl"
    summary = {
        "schema_version": "ray428-local-lab-acceptance/1",
        "generated_at": datetime.now(UTC).isoformat(),
        "loopback_tls": True,
        "private_test_state": True,
        "one_shot_503_observed": unavailable.status_code == 503,
        "recovered_200": recovered.status_code == 200,
        "latency_ms": latency_ms,
        "latency_injected": latency_ms >= 150 and delayed.status_code == 200,
        "delayed_out_of_order_ack_observed": delayed_out_of_order_ack,
        "throttle_observed": throttled.status_code == 200,
        "completion_response_dropped_then_retried": lifecycle[
            "completion_response_dropped_then_retried"
        ],
        **server,
        "idempotent_completion": server["server_idempotency_recorded"],
        "restart_persistence_verified": lifecycle["restart_persistence_verified"],
        "redacted_fault_audit_recorded": fault_audit.is_file()
        and bool(fault_audit.read_text(encoding="utf-8")),
        "secrets_included": False,
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return summary_path


async def serve(paths: LocalLabPaths, host: str, port: int, administration_dsn: str) -> None:
    import uvicorn

    from techflex_cloud_foundation.server.local_lab import build_local_lab_app
    settings, token = _seed_settings(paths, bootstrap(administration_dsn), host, port)
    certificate, private_key = ensure_tls_material(paths, host)
    while True:
        restart_requested = False
        server: uvicorn.Server | None = None

        def request_restart() -> None:
            nonlocal restart_requested
            restart_requested = True
            assert server is not None  # noqa: B023
            server.should_exit = True  # noqa: B023

        app = await build_local_lab_app(
            settings,
            token,
            paths.audit,
            restart_callback=request_restart,
        )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                host=host,
                port=port,
                ssl_certfile=str(certificate),
                ssl_keyfile=str(private_key),
                proxy_headers=False,
                server_header=False,
            )
        )
        await server.serve()
        if not restart_requested:
            return


def main(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    preflight(arguments.runtime_root, arguments.bind_host, arguments.administration_dsn)
    if arguments.phase == "bootstrap":
        bootstrap(arguments.administration_dsn)
    elif arguments.phase == "serve":
        asyncio.run(serve(preflight(arguments.runtime_root, arguments.bind_host, arguments.administration_dsn), arguments.bind_host, arguments.bind_port, arguments.administration_dsn))
    elif arguments.phase == "exercise":
        exercise(
            preflight(arguments.runtime_root, arguments.bind_host, arguments.administration_dsn),
            arguments.bind_host,
            arguments.bind_port,
            arguments.administration_dsn,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
