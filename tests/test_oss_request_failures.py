"""RAY-1028 R1: object store request failures are retryable 503s and leave a trace.

OSS failures that say nothing about an object's content are translated at the
gateway into ``ObjectStoreUnavailable`` (no answer, or 5xx/429: retryable) and
``ObjectStoreRequestFailed`` (any other refusal, such as 403: a configuration
fault).  The HTTP layer answers the first with ``E-CLD-503``; ingestion records
either as one OPEN ``OBJECT_STORE_FAILURE`` per session and segment, which a
later success resolves.  Report and diagnostic reads no longer mistake them for
digest mismatches.
"""
from __future__ import annotations

import asyncio
import base64
from datetime import timedelta
import hashlib
import json
from types import SimpleNamespace
from typing import Any
from uuid import UUID, uuid4

from httpx import ASGITransport, AsyncClient
import pytest

from techflex_cloud_foundation.aliyun_oss import AliyunOSSObjectStore, AliyunOSSSDKGateway
from techflex_cloud_foundation.object_store import (
    InMemoryObjectStore,
    ObjectStoreError,
    ObjectStoreRequestFailed,
    ObjectStoreUnavailable,
)
from techflex_cloud_foundation.platform_errors import DigestMismatch
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.auth import TerminalTokenIssuer
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.report_copy.object_store import LocalBasicPdfStore
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from techflex_cloud_foundation.server.terminal_diagnostics.object_store import (
    DiagnosticPackageStore,
)
from tests.test_aliyun_oss import _SDK, _SDKClient
from tests.test_ffp_postgres_platform_live import Harness, _run
from tests.test_ffp_postgres_platform_live import cluster as cluster  # shared ephemeral PG fixture
from tests.test_registry_http_ingestion import canonical, vector

KEY = "tenants/t/sessions/s/segments/0.ffps"
SCHEMA = "gait-session-archive/1"


# --- gateway translation ----------------------------------------------------


class _FailingClient(_SDKClient):
    def __init__(self, error: Exception) -> None:
        super().__init__()
        self.error = error

    def put_object(self, request: SimpleNamespace) -> None:
        raise self.error

    def head_object(self, request: SimpleNamespace) -> SimpleNamespace:
        raise self.error

    def get_object(self, request: SimpleNamespace) -> SimpleNamespace:
        raise self.error

    def delete_object(self, request: SimpleNamespace) -> None:
        raise self.error

    def get_bucket_info(self, request: SimpleNamespace) -> None:
        raise self.error


class _GetRequest(SimpleNamespace):
    pass


class _SDKWithGet(_SDK):
    GetObjectRequest = _GetRequest


def _call(gateway: AliyunOSSSDKGateway, operation: str) -> None:
    if operation == "put":
        gateway.put_immutable(
            key=KEY, body=b"payload", content_type="application/octet-stream",
            metadata={"sha256": "a" * 64}, server_side_encryption="KMS",
        )
    elif operation == "check_ready":
        gateway.check_ready()
    else:
        getattr(gateway, operation)(KEY)


OPERATIONS = ("put", "head", "get", "delete", "check_ready")


@pytest.mark.parametrize("operation", OPERATIONS)
def test_no_answer_from_oss_is_transient_and_carries_no_key(operation: str) -> None:
    # A missing CA bundle, DNS, TLS or a timeout: the SDK wraps a non-service error.
    cause = OSError(f"certificate verify failed for {KEY} with secret-token")
    gateway = AliyunOSSSDKGateway(
        _FailingClient(_SDK.OperationError(cause)), _SDKWithGet, bucket="private-raw"
    )

    with pytest.raises(ObjectStoreUnavailable) as raised:
        _call(gateway, operation)

    failure = raised.value
    assert failure.transient is True
    assert failure.safe_evidence() == {
        "operation": operation, "category": "transport", "status_code": None,
        "error_code": None,
    }
    assert KEY not in str(failure) and "secret-token" not in str(failure)
    assert failure.__cause__ is not None  # the SDK error stays chained for the log


@pytest.mark.parametrize("operation", OPERATIONS)
@pytest.mark.parametrize(
    ("status", "code"), [(500, "InternalError"), (503, "ServiceUnavailable"), (429, "SlowDown")]
)
def test_oss_5xx_and_429_are_transient(operation: str, status: int, code: str) -> None:
    direct = _SDK.ServiceError(status, code)
    for error in (direct, _SDK.OperationError(_SDK.ServiceError(status, code))):
        gateway = AliyunOSSSDKGateway(_FailingClient(error), _SDKWithGet, bucket="private-raw")
        with pytest.raises(ObjectStoreUnavailable) as raised:
            _call(gateway, operation)
        assert raised.value.safe_evidence() == {
            "operation": operation, "category": "service", "status_code": status,
            "error_code": code,
        }


@pytest.mark.parametrize("operation", OPERATIONS)
def test_oss_refusal_is_a_non_transient_request_failure(operation: str) -> None:
    error = _SDK.OperationError(_SDK.ServiceError(403, "AccessDenied"))
    gateway = AliyunOSSSDKGateway(_FailingClient(error), _SDKWithGet, bucket="private-raw")

    with pytest.raises(ObjectStoreRequestFailed) as raised:
        _call(gateway, operation)

    assert not isinstance(raised.value, ObjectStoreUnavailable)
    assert raised.value.safe_evidence()["status_code"] == 403
    assert raised.value.safe_evidence()["error_code"] == "AccessDenied"
    assert isinstance(raised.value, ObjectStoreError)


# --- report and diagnostic reads --------------------------------------------


class _UnreachableStore(InMemoryObjectStore):
    def __init__(self, failure: Exception) -> None:
        super().__init__()
        self.failure = failure

    async def read(self, object_key: str) -> bytes:  # type: ignore[override]
        raise self.failure


@pytest.mark.parametrize(
    "failure",
    [ObjectStoreUnavailable("head", "transport"),
     ObjectStoreRequestFailed("get", "service", status_code=403, error_code="AccessDenied")],
)
def test_report_and_diagnostic_reads_do_not_call_an_unreachable_store_a_digest_mismatch(
    failure: ObjectStoreRequestFailed,
) -> None:
    async def body() -> None:
        with pytest.raises(type(failure)):
            await LocalBasicPdfStore(_UnreachableStore(failure)).read(KEY)
        with pytest.raises(type(failure)):
            await DiagnosticPackageStore(_UnreachableStore(failure)).read_diagnostic(KEY)
        # A genuine content verdict is still a digest mismatch.
        with pytest.raises(DigestMismatch):
            await LocalBasicPdfStore(_UnreachableStore(ObjectStoreError("bad"))).read(KEY)

    asyncio.run(body())


def test_oss_store_read_lets_an_unreachable_head_through() -> None:
    class Gateway:
        def head(self, key: str) -> Any:
            raise ObjectStoreUnavailable("head", "transport")

    store = AliyunOSSObjectStore(Gateway(), server_side_encryption="KMS")  # type: ignore[arg-type]
    with pytest.raises(ObjectStoreUnavailable):
        asyncio.run(store.read(KEY))


# --- ingestion over HTTP: 503, problem record, resolution -------------------


class _FlakyStore(InMemoryObjectStore):
    """An in-memory store whose next ``put_verified`` calls fail as configured."""

    def __init__(self) -> None:
        super().__init__()
        self.put_failures: list[Exception] = []
        self.delete_failures: list[Exception] = []

    async def put_verified(self, *args: Any, **kwargs: Any) -> Any:  # type: ignore[override]
        if self.put_failures:
            # Drain the chunks a real store would have consumed.
            async for _ in args[1]:
                pass
            raise self.put_failures.pop(0)
        return await super().put_verified(*args, **kwargs)

    async def delete(self, object_key: str) -> None:
        if self.delete_failures:
            raise self.delete_failures.pop(0)
        await super().delete(object_key)


class _Client:
    def __init__(self, repository: Any, tenant: Any, terminal: Any, store: _FlakyStore) -> None:
        self.store = store
        self.service = IngestionService(
            repository, SegmentObjectStore(store),
            supported_payload_schemas={SCHEMA},
            supported_manifest_schemas={"gait-session-manifest/1"},
        )
        issuer = TerminalTokenIssuer(
            secret=b"oss-failure-test-secret-at-least-32", key_id="test/1",
            token_ttl=timedelta(minutes=10),
        )
        self.app = create_app(ServiceContainer(ingestion=self.service, token_issuer=issuer))
        self.session = vector("session-create-vectors.json", SCHEMA)["session"]["document"]
        self.session.update(
            session_id=str(uuid4()), client_installation_id=str(terminal), site_id=None
        )
        self.payload = vector("payload-schema-vectors.json", SCHEMA)
        self.headers = {
            "Authorization": f"Bearer {issuer.issue(tenant, terminal)}",
            "X-Terminal-ID": str(terminal),
        }
        self.path = f"/v1/sessions/{self.session['session_id']}"

    async def request(self, method: str, url: str, **kwargs: Any) -> Any:
        async with AsyncClient(
            transport=ASGITransport(app=self.app, raise_app_exceptions=False),
            base_url="https://cloud.test",
        ) as client:
            return await client.request(method, url, **kwargs)

    async def create(self) -> None:
        response = await self.request(
            "POST", "/v1/sessions", json=self.session,
            headers={**self.headers, "Idempotency-Key": f"create:{self.session['session_id']}"},
        )
        assert response.status_code == 201, response.text

    async def put_segment(self, position: int) -> Any:
        segment = self.payload["segments"][position]
        metadata = segment["metadata"]
        encoded = base64.urlsafe_b64encode(canonical(metadata)).rstrip(b"=").decode()
        return await self.request(
            "PUT", f"{self.path}/segments/{metadata['segment_index']}",
            headers={**self.headers, "X-Segment-Metadata": encoded,
                     "X-Content-SHA256": metadata["sha256"], "X-Schema-Version": SCHEMA,
                     "Content-Type": "application/octet-stream"},
            content=base64.b64decode(segment["payload_base64"]),
        )

    async def complete(self) -> Any:
        manifest = self.payload["manifest"]["document"]
        return await self.request(
            "POST", f"{self.path}/complete", json=manifest,
            headers={**self.headers, "Idempotency-Key": f"complete:{self.session['session_id']}",
                     "X-Content-SHA256": hashlib.sha256(canonical(manifest)).hexdigest(),
                     "X-Schema-Version": manifest["schema_version"]},
        )

    def segment_index(self, position: int) -> int:
        return int(self.payload["segments"][position]["metadata"]["segment_index"])


def _assert_error(response: Any, status: int, code: str, retryable: bool, action: str) -> None:
    assert response.status_code == status, response.text
    error = response.json()["error"]
    assert (error["code"], error["retryable"], error["action"]) == (code, retryable, action)
    assert "tenants/" not in response.text  # no object key leaks into the envelope


async def _scenario(client: _Client, problems: Any) -> None:
    """Shared by the in-memory and PostgreSQL repositories."""
    await client.create()
    first = client.segment_index(0)

    # Two transient failures on segment 0: one OPEN row, refreshed.
    client.store.put_failures = [
        ObjectStoreUnavailable("head", "transport"),
        ObjectStoreUnavailable("put", "service", status_code=503, error_code="ServiceUnavailable"),
    ]
    _assert_error(await client.put_segment(0), 503, "E-CLD-503", True, "RETRY_LATER")
    (row,) = await problems()
    assert (row["segment_index"], row["status"]) == (first, "OPEN")
    first_seen = row["last_seen_at"]
    _assert_error(await client.put_segment(0), 503, "E-CLD-503", True, "RETRY_LATER")
    (row,) = await problems()
    assert row["status"] == "OPEN" and row["last_seen_at"] >= first_seen
    assert row["safe_evidence"] == {
        "operation": "put", "category": "service", "status_code": 503,
        "error_code": "ServiceUnavailable",
    }

    # A configuration refusal is a non-retryable 500 but is still recorded.
    client.store.put_failures = [
        ObjectStoreRequestFailed("put", "service", status_code=403, error_code="AccessDenied")
    ]
    _assert_error(await client.put_segment(0), 500, "E-CLD-500", False, "CONTACT_SUPPORT")
    (row,) = await problems()
    assert row["status"] == "OPEN" and row["safe_evidence"]["status_code"] == 403

    # The retry succeeds and resolves segment 0's problem.
    assert (await client.put_segment(0)).status_code == 201
    (row,) = await problems()
    assert row["status"] == "RESOLVED" and row["resolved_at"] is not None
    for position in range(1, len(client.payload["segments"])):
        assert (await client.put_segment(position)).status_code == 201

    # The manifest's store write fails once: a session-level (NULL segment) row.
    client.store.put_failures = [ObjectStoreUnavailable("head", "transport")]
    _assert_error(await client.complete(), 503, "E-CLD-503", True, "RETRY_LATER")
    rows = await problems()
    manifest_rows = [item for item in rows if item["segment_index"] is None]
    assert [item["status"] for item in manifest_rows] == ["OPEN"]

    response = await client.complete()
    assert response.status_code == 200, response.text
    assert all(item["status"] == "RESOLVED" for item in await problems())


def test_object_store_failures_over_http_in_memory() -> None:
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)
    client = _Client(repository, tenant, terminal, _FlakyStore())
    session_id = client.session["session_id"]

    async def problems() -> list[dict[str, Any]]:
        return [
            {"segment_index": p.segment_index, "status": p.status, "safe_evidence": p.safe_evidence,
             "last_seen_at": p.last_seen_at, "resolved_at": p.resolved_at}
            for p in repository.ingest_problems(tenant, UUID(session_id))
            if p.problem_type == "OBJECT_STORE_FAILURE"
        ]

    asyncio.run(_scenario(client, problems))


def test_object_store_failures_over_http_postgres(cluster) -> None:
    async def body(h: Harness) -> None:
        tenant = await h.tenant()
        client = _Client(h.repository, tenant.tenant_id, tenant.terminal_id, _FlakyStore())

        async def problems() -> list[dict[str, Any]]:
            rows = await h.admin.fetch(
                "SELECT segment_index, status, safe_evidence, last_seen_at, resolved_at "
                "FROM screening.ingest_problems WHERE session_id::text=$1 "
                "AND problem_type='OBJECT_STORE_FAILURE' ORDER BY first_seen_at",
                client.session["session_id"],
            )
            return [
                {**dict(row), "safe_evidence": json.loads(row["safe_evidence"])} for row in rows
            ]

        await _scenario(client, problems)
        # The evidence never holds a key, a message or a credential.
        raw = await h.admin.fetch(
            "SELECT safe_evidence::text AS e FROM screening.ingest_problems "
            "WHERE problem_type='OBJECT_STORE_FAILURE'"
        )
        assert raw and all("tenants/" not in row["e"] and "secret" not in row["e"] for row in raw)

    _run(cluster, body)


def test_open_object_store_failure_is_unique_per_segment_in_postgres(cluster) -> None:
    async def body(h: Harness) -> None:
        tenant = await h.tenant()
        client = _Client(h.repository, tenant.tenant_id, tenant.terminal_id, _FlakyStore())
        await client.create()
        session_id = UUID(client.session["session_id"])
        # Concurrent failures on one segment and on the manifest still leave one OPEN row each.
        await asyncio.gather(*(
            h.repository.record_object_store_failure(
                tenant.principal, session_id, index, {"operation": "put"}
            )
            for index in (0, 0, 0, None, None)
        ))
        counts = await h.admin.fetch(
            "SELECT segment_index, count(*) AS n FROM screening.ingest_problems "
            "WHERE session_id=$1 AND status='OPEN' GROUP BY segment_index", session_id,
        )
        assert sorted((row["segment_index"] is None, row["n"]) for row in counts) == [
            (False, 1), (True, 1)
        ]

    _run(cluster, body)


# --- the record never changes the client's answer ---------------------------


def test_a_failed_record_keeps_the_object_store_error() -> None:
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)

    async def unavailable(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("database is gone too")

    repository.record_object_store_failure = unavailable  # type: ignore[method-assign]
    client = _Client(repository, tenant, terminal, _FlakyStore())

    async def body() -> None:
        await client.create()
        client.store.put_failures = [ObjectStoreUnavailable("head", "transport")]
        _assert_error(await client.put_segment(0), 503, "E-CLD-503", True, "RETRY_LATER")

    asyncio.run(body())


def test_a_failed_cleanup_delete_does_not_hide_the_original_error() -> None:
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)
    store = _FlakyStore()
    client = _Client(repository, tenant, terminal, store)

    async def broken_register(*_args: Any, **_kwargs: Any) -> None:
        raise LookupError("registration failed")

    async def body() -> None:
        await client.create()
        repository.register_segment = broken_register  # type: ignore[method-assign]
        store.delete_failures = [ObjectStoreUnavailable("delete", "transport")]
        # A masked delete failure would answer 503; the registration error answers 500.
        response = await client.put_segment(0)
        _assert_error(response, 500, "E-CLD-500", False, "CONTACT_SUPPORT")
        assert store.delete_failures == []  # the delete was attempted and failed

    asyncio.run(body())


def test_migration_0023_grants_only_the_columns_it_updates() -> None:
    from techflex_cloud_foundation.schema import DEFAULT_PLAN
    from techflex_cloud_foundation.schema.plan import load_step_sql

    ids = [step.step_id for step in DEFAULT_PLAN]
    step = DEFAULT_PLAN[ids.index("0023_object_store_failure_problems")]
    assert ids.index("0023_object_store_failure_problems") == len(ids) - 1
    assert step.converges
    sql = load_step_sql(step)
    assert (
        "GRANT UPDATE (last_seen_at, safe_evidence, status, resolved_at)\n"
        "    ON screening.ingest_problems TO ffp_tenant_app;" in sql
    )
    assert "CREATE UNIQUE INDEX IF NOT EXISTS ingest_problems_open_object_store_failure" in sql
    assert "DELETE" not in sql and "INSERT" not in sql and "GRANT ALL" not in sql


# --- review follow-ups -------------------------------------------------------


class _CredentialsEmptyError(Exception):
    """Stands in for the SDK's client-side errors (credentials, names, params)."""


class _RequestError(Exception):
    def __init__(self, error: Exception) -> None:
        self._error = error

    def unwrap(self) -> Exception:
        return self._error


class _SDKWithTransport(_SDKWithGet):
    RequestError = _RequestError
    ResponseError = _RequestError


@pytest.mark.parametrize("operation", OPERATIONS)
def test_client_side_sdk_failure_is_a_configuration_fault(operation: str) -> None:
    # Missing RAM credentials or a bad bucket name: retrying will not help.
    error = _SDK.OperationError(_CredentialsEmptyError("no credentials"))
    gateway = AliyunOSSSDKGateway(_FailingClient(error), _SDKWithTransport, bucket="private-raw")

    with pytest.raises(ObjectStoreRequestFailed) as raised:
        _call(gateway, operation)

    assert not isinstance(raised.value, ObjectStoreUnavailable)
    assert raised.value.safe_evidence()["category"] == "client"


@pytest.mark.parametrize("operation", OPERATIONS)
def test_sdk_request_error_wrapping_a_network_failure_is_transient(operation: str) -> None:
    error = _SDK.OperationError(_RequestError(ConnectionResetError("reset by peer")))
    gateway = AliyunOSSSDKGateway(_FailingClient(error), _SDKWithTransport, bucket="private-raw")

    with pytest.raises(ObjectStoreUnavailable) as raised:
        _call(gateway, operation)

    assert raised.value.safe_evidence()["category"] == "transport"


def test_a_body_read_that_drops_is_transient() -> None:
    class _Body:
        def read(self) -> bytes:
            raise TimeoutError("read timed out")  # requests' ReadTimeout is an OSError too

        def close(self) -> None:
            pass

    class _Client(_SDKClient):
        def get_object(self, request: SimpleNamespace) -> SimpleNamespace:
            return SimpleNamespace(body=_Body())

    gateway = AliyunOSSSDKGateway(_Client(), _SDKWithGet, bucket="private-raw")
    with pytest.raises(ObjectStoreUnavailable) as raised:
        gateway.get(KEY)
    assert raised.value.safe_evidence()["operation"] == "get"


def test_a_duplicate_upload_replay_resolves_the_racing_failure() -> None:
    repository = InMemoryPlatformRepository()
    tenant, terminal = uuid4(), uuid4()
    repository.add_terminal(tenant, None, terminal)
    client = _Client(repository, tenant, terminal, _FlakyStore())

    async def body() -> None:
        await client.create()
        session_id = UUID(client.session["session_id"])
        assert (await client.put_segment(0)).status_code == 201
        # A duplicate upload that lost the race recorded a failure after the registration.
        from datetime import UTC, datetime

        from techflex_cloud_foundation.server.auth import TerminalContext

        principal = TerminalContext(
            tenant_id=tenant, terminal_id=terminal,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )
        await repository.record_object_store_failure(
            principal, session_id, client.segment_index(0), {"operation": "put"}
        )
        assert [p.status for p in repository.ingest_problems(tenant, session_id)] == ["OPEN"]
        # Its retry is answered as an idempotent replay, which resolves the row.
        assert (await client.put_segment(0)).status_code == 200
        assert [p.status for p in repository.ingest_problems(tenant, session_id)] == ["RESOLVED"]

    asyncio.run(body())


def test_registration_still_succeeds_before_migration_0023_is_applied(cluster) -> None:
    async def body(h: Harness) -> None:
        tenant = await h.tenant()
        client = _Client(h.repository, tenant.tenant_id, tenant.terminal_id, _FlakyStore())
        await client.create()
        await h.admin.execute(
            "REVOKE UPDATE (last_seen_at, safe_evidence, status, resolved_at) "
            "ON screening.ingest_problems FROM ffp_tenant_app"
        )
        try:
            assert (await client.put_segment(0)).status_code == 201
            for position in range(1, len(client.payload["segments"])):
                assert (await client.put_segment(position)).status_code == 201
            assert (await client.complete()).status_code == 200
        finally:
            await h.admin.execute(
                "GRANT UPDATE (last_seen_at, safe_evidence, status, resolved_at) "
                "ON screening.ingest_problems TO ffp_tenant_app"
            )

    _run(cluster, body)


def test_a_failed_diagnostic_cleanup_delete_keeps_the_insert_error() -> None:
    from techflex_cloud_foundation.server.terminal_diagnostics import service as diagnostics

    class _Objects:
        async def put_diagnostic(self, key: str, payload: bytes) -> None:
            return None

        async def delete(self, key: str) -> None:
            raise ObjectStoreUnavailable("delete", "transport")

    service = object.__new__(diagnostics.TerminalDiagnosticsService)
    service._objects = _Objects()  # type: ignore[attr-defined]
    # The private helper is what both cleanup paths now call.
    asyncio.run(service._discard("tenants/t/diagnostics/d"))  # does not raise
