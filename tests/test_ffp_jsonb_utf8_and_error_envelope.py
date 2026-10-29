"""RAY-834 R1: jsonb writes send raw UTF-8; unhandled errors keep the envelope."""
from __future__ import annotations

import ast
from pathlib import Path
from uuid import UUID

import asyncpg
from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.contract_export import build_openapi, build_vectors

ROOT = Path(__file__).resolve().parents[1]


def _escaping_dumps(path: Path) -> list[int]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "dumps"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "json"
        and not any(
            keyword.arg == "ensure_ascii"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is False
            for keyword in node.keywords
        )
    ]


def test_postgres_repositories_never_escape_non_ascii_json() -> None:
    # A SQL_ASCII database rejects \uXXXX escapes of non-ASCII text in jsonb,
    # while raw UTF-8 is stored unchanged; the jsonb value is the same either way.
    server = ROOT / "src/techflex_cloud_foundation/server"
    modules = sorted([server / "postgres.py", *server.glob("*/postgres.py")])
    assert modules, "no Postgres repository modules found"
    offenders = {
        str(path.relative_to(ROOT)): lines
        for path in modules
        if (lines := _escaping_dumps(path))
    }
    assert offenders == {}


class _FailingIngestion:
    def __init__(self, error: Exception) -> None:
        self.error = error

    async def get_status(self, *_args, **_kwargs):
        raise self.error


async def _status_response(error: Exception, *, raise_app_exceptions: bool = False):
    app = create_app(ServiceContainer(ingestion=_FailingIngestion(error)))
    # Bypass authentication: only the route's own failure is under test.
    for route in app.routes:
        if getattr(route, "path", "") == "/v1/sessions/{session_id}/status":
            for dependency in route.dependant.dependencies:
                app.dependency_overrides[dependency.call] = lambda: object()
    transport = ASGITransport(app=app, raise_app_exceptions=raise_app_exceptions)
    async with AsyncClient(transport=transport, base_url="https://cloud.test") as client:
        response = await client.get(
            f"/v1/sessions/{UUID(int=1)}/status",
            headers={"X-Correlation-ID": str(UUID(int=7))},
        )
    return response


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("error", "status", "code", "retryable", "action"),
    [
        (RuntimeError("secret detail"), 500, "E-CLD-500", False, "CONTACT_SUPPORT"),
        (asyncpg.exceptions.FeatureNotSupportedError("secret detail"), 500, "E-CLD-500",
         False, "CONTACT_SUPPORT"),
        (asyncpg.exceptions.ConnectionDoesNotExistError("secret detail"), 503, "E-CLD-503",
         True, "RETRY_LATER"),
        (asyncpg.exceptions.TooManyConnectionsError("secret detail"), 503, "E-CLD-503",
         True, "RETRY_LATER"),
        (TimeoutError("secret detail"), 503, "E-CLD-503", True, "RETRY_LATER"),
        (asyncpg.exceptions.AdminShutdownError("secret detail"), 503, "E-CLD-503",
         True, "RETRY_LATER"),
        (asyncpg.exceptions.CannotConnectNowError("secret detail"), 503, "E-CLD-503",
         True, "RETRY_LATER"),
        (asyncpg.exceptions.DeadlockDetectedError("secret detail"), 503, "E-CLD-503",
         True, "RETRY_LATER"),
        (asyncpg.exceptions.SerializationError("secret detail"), 503, "E-CLD-503",
         True, "RETRY_LATER"),
        (asyncpg.exceptions.DataError("secret detail"), 500, "E-CLD-500",
         False, "CONTACT_SUPPORT"),
    ],
)
async def test_unhandled_errors_get_the_envelope(error, status, code, retryable, action):
    response = await _status_response(error)
    assert response.status_code == status
    body = response.json()
    assert body["error"] == {
        "code": code, "message": body["error"]["message"], "retryable": retryable,
        "action": action, "details": {},
    }
    assert body["meta"]["correlation_id"] == str(UUID(int=7))
    assert response.headers["X-Correlation-ID"] == str(UUID(int=7))
    assert "secret detail" not in response.text


def test_contract_publishes_the_internal_error() -> None:
    internal = build_vectors()["errors"]["internal"]["error"]
    assert (internal["code"], internal["retryable"], internal["action"]) == (
        "E-CLD-500", False, "CONTACT_SUPPORT")
    operation = build_openapi()["paths"]["/v1/sessions"]["post"]
    assert {"500", "503"} <= set(operation["responses"])


@pytest.mark.anyio
async def test_unhandled_errors_are_still_raised_for_logging() -> None:
    # Starlette sends the envelope and then re-raises, so the server logs the
    # traceback; the in-process transport surfaces that re-raise.
    with pytest.raises(RuntimeError, match="secret detail"):
        await _status_response(RuntimeError("secret detail"), raise_app_exceptions=True)
