from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
import sqlite3
from typing import cast
from uuid import UUID

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import techflex_cloud_foundation.transport as transport_module

from techflex_cloud_foundation import (
    AuthorizedTransport,
    EntitlementDecision,
    OperationState,
    ReliableOperation,
    RetryPolicy,
    SecureTransport,
    SqliteOperationStore,
    TrustBundle,
    TrustBundleVerifier,
)
from techflex_cloud_foundation.reliability import _operation_from_row


class _Tokens:
    def __init__(self) -> None:
        self.value = "first"
        self.refresh_count = 0

    def current_access_token(self) -> str:
        return self.value

    def refresh(self) -> None:
        self.refresh_count += 1
        self.value = "second"


def test_independent_consumer_uses_only_public_api(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    operation = ReliableOperation.create(
        kind="example.upload",
        payload_ref="spool/session-1",
        payload_digest="a" * 64,
        idempotency_key="example:session-1",
    )

    store.enqueue(operation)

    assert store.lease_due(now=datetime.now(UTC)) == operation


def test_retry_policy_keeps_server_retry_after_deadline() -> None:
    policy = RetryPolicy(base_delay=timedelta(seconds=5), cap_delay=timedelta(minutes=5))
    now = datetime(2026, 8, 24, tzinfo=UTC)

    assert policy.next_attempt_at(
        now=now,
        attempt_count=3,
        retry_after=timedelta(seconds=90),
    ) == now + timedelta(seconds=90)


def test_authorized_transport_refreshes_at_most_once_after_401() -> None:
    seen: list[str | None] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.headers.get("Authorization"))
        if request.headers.get("Authorization") == "Bearer first":
            return httpx.Response(401, request=request)
        return httpx.Response(200, json={"ok": True}, request=request)

    tokens = _Tokens()
    with SecureTransport(
        "https://foundation.test",
        transport=httpx.MockTransport(handler),
    ) as transport:
        response = AuthorizedTransport(transport, tokens).request("GET", "/v1/check")

    assert response.status_code == 200
    assert tokens.refresh_count == 1
    assert seen == ["Bearer first", "Bearer second"]


def test_secure_transport_reuses_a_supplied_correlation_id_without_generating_one(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def should_not_generate() -> object:
        raise AssertionError("a supplied correlation ID must be reused")

    monkeypatch.setattr(transport_module, "uuid4", should_not_generate)
    with SecureTransport(
        "https://foundation.test",
        transport=httpx.MockTransport(
            lambda request: httpx.Response(204, request=request)
        ),
    ) as transport:
        response = transport.request(
            "POST", "/v1/check", headers={"X-Correlation-ID": "known-id"}
        )

    assert response.request.headers["X-Correlation-ID"] == "known-id"


def test_trust_bundle_requires_root_signature_and_monotonic_revision() -> None:
    root = Ed25519PrivateKey.generate()
    bundle = TrustBundle(
        revision=2,
        issued_at=datetime(2026, 8, 24, tzinfo=UTC),
        signing_keys={"license/2": b"x" * 32},
        revoked_key_ids=("license/1",),
        policy={"screening.start": True},
    )
    signed = bundle.sign(root)

    verified = TrustBundleVerifier(root.public_key().public_bytes_raw()).verify(
        signed,
        minimum_revision=1,
    )

    assert verified.revision == 2
    with pytest.raises(ValueError, match="revision"):
        TrustBundleVerifier(root.public_key().public_bytes_raw()).verify(
            signed,
            minimum_revision=2,
        )


def test_entitlement_decision_is_immutable_and_application_scoped() -> None:
    decision = EntitlementDecision(
        license_id=UUID("00000000-0000-0000-0000-000000000001"),
        application_id="feetforceplate",
        capabilities=frozenset({"screening.start"}),
        policy_revision=3,
        evaluated_at=datetime(2026, 8, 24, tzinfo=UTC),
    )

    assert decision.allows("screening.start")
    assert not decision.allows("report.export")
    with pytest.raises((AttributeError, TypeError)):
        decision.application_id = "other"  # type: ignore[misc]


def test_operation_store_recovers_only_interrupted_leases(tmp_path: Path) -> None:
    store = SqliteOperationStore(tmp_path / "operations.sqlite3")
    operation = ReliableOperation.create(
        kind="example.upload",
        payload_ref="spool/session-2",
        payload_digest="b" * 64,
        idempotency_key="example:session-2",
    )
    store.enqueue(operation)
    leased = store.lease_due(now=datetime.now(UTC))
    assert leased is not None

    store.recover_interrupted_leases(now=datetime.now(UTC))

    assert store.get(operation.operation_id).state is OperationState.READY


def test_operation_row_rejects_missing_created_at() -> None:
    row = cast(
        sqlite3.Row,
        {
            "operation_id": "00000000-0000-0000-0000-000000000001",
            "kind": "example.upload",
            "payload_ref": "spool/session-3",
            "payload_digest": "c" * 64,
            "idempotency_key": "example:session-3",
            "created_at": None,
        },
    )

    with pytest.raises(ValueError, match="created_at"):
        _operation_from_row(row)
