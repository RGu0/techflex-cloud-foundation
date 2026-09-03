from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from techflex_cloud_foundation import (
    GatewayAuthenticationRefused,
    GatewayMalformed,
    GatewayPayloadTooLarge,
    GatewayRateLimited,
    GatewayTenantMismatch,
    HmacTokenCodec,
    InMemoryRateLimitStore,
    RateLimitPolicy,
    RequestValidator,
)

NOW = datetime(2026, 9, 3, tzinfo=UTC)
SECRET = b"g" * 32


def _codec() -> HmacTokenCodec:
    return HmacTokenCodec(
        secret=SECRET, key_id="tenant/1", token_type="access", audience="tenant-data"
    )


def _validator(**overrides: object) -> RequestValidator:
    values: dict[str, object] = {"max_payload_bytes": 1024}
    values.update(overrides)
    return RequestValidator(_codec(), **values)  # type: ignore[arg-type]


def _future(days: int = 1) -> datetime:
    return datetime.now(UTC) + timedelta(days=days)


def _token(codec: HmacTokenCodec | None = None, **claims: object) -> str:
    codec = codec or _codec()
    base: dict[str, object] = {"tenant_id": "tenant-a", "sub": "operator-1"}
    base.update(claims)
    return codec.issue(base, expires_at=_future())


def test_valid_request_yields_trusted_context() -> None:
    validator = _validator()
    context = validator.validate(
        f"Bearer {_token()}",
        correlation_id="corr-1234-abcd",
        payload_tenant="tenant-a",
        payload_bytes=100,
        now=NOW,
    )

    assert context.tenant_id == "tenant-a"
    assert context.subject_id == "operator-1"
    assert context.correlation_id == "corr-1234-abcd"
    assert len(context.token_digest) == 64
    assert context.token_expires_at is not None


def test_missing_or_non_bearer_authorization_is_refused() -> None:
    validator = _validator()
    with pytest.raises(GatewayAuthenticationRefused, match="missing"):
        validator.validate(None, now=NOW)
    with pytest.raises(GatewayAuthenticationRefused, match="Bearer"):
        validator.validate("Basic abc", now=NOW)


def test_wrong_audience_kid_and_expiry_are_refused() -> None:
    validator = _validator()
    other_audience = HmacTokenCodec(
        secret=SECRET, key_id="tenant/1", token_type="access", audience="platform-ops"
    )
    with pytest.raises(GatewayAuthenticationRefused):
        validator.validate(f"Bearer {_token(other_audience)}", now=NOW)

    other_key = HmacTokenCodec(
        secret=SECRET, key_id="tenant/2", token_type="access", audience="tenant-data"
    )
    with pytest.raises(GatewayAuthenticationRefused):
        validator.validate(f"Bearer {_token(other_key)}", now=NOW)

    expired = _codec().issue(
        {"tenant_id": "tenant-a", "sub": "operator-1"},
        expires_at=_future(),
    )
    with pytest.raises(GatewayAuthenticationRefused):
        validator.validate(
            f"Bearer {expired}", now=_future(days=2)
        )


def test_tampered_signature_is_refused() -> None:
    validator = _validator()
    token = _token()
    forged = token[:-2] + ("aa" if not token.endswith("aa") else "bb")
    with pytest.raises(GatewayAuthenticationRefused):
        validator.validate(f"Bearer {forged}", now=NOW)


def test_token_without_tenant_or_subject_claim_is_refused() -> None:
    validator = _validator()
    codec = _codec()
    no_tenant = codec.issue({"sub": "operator-1"}, expires_at=_future())
    with pytest.raises(GatewayAuthenticationRefused, match="tenant"):
        validator.validate(f"Bearer {no_tenant}", now=NOW)
    no_subject = codec.issue(
        {"tenant_id": "tenant-a"}, expires_at=_future()
    )
    with pytest.raises(GatewayAuthenticationRefused, match="subject"):
        validator.validate(f"Bearer {no_subject}", now=NOW)


def test_payload_never_selects_tenant() -> None:
    validator = _validator()
    with pytest.raises(GatewayTenantMismatch):
        validator.validate(
            f"Bearer {_token()}", payload_tenant="tenant-b", now=NOW
        )


def test_payload_size_cap() -> None:
    validator = _validator()
    with pytest.raises(GatewayPayloadTooLarge, match="cap"):
        validator.validate(f"Bearer {_token()}", payload_bytes=2048, now=NOW)


def test_malformed_correlation_id_is_replaced_not_trusted() -> None:
    validator = _validator()
    context = validator.validate(
        f"Bearer {_token()}", correlation_id="../../etc\n forged", now=NOW
    )
    assert context.correlation_id != "../../etc\n forged"
    assert len(context.correlation_id) == 32


def test_rate_limit_keys_on_authenticated_principal() -> None:
    store = InMemoryRateLimitStore()
    validator = _validator(
        rate_limit=RateLimitPolicy(max_requests=2, window_seconds=60),
        rate_store=store,
    )
    validator.validate(f"Bearer {_token()}", now=NOW)
    validator.validate(f"Bearer {_token()}", now=NOW)
    with pytest.raises(GatewayRateLimited) as excinfo:
        validator.validate(f"Bearer {_token()}", now=NOW)
    assert excinfo.value.retry_after_seconds > 0

    later = NOW + timedelta(seconds=61)
    validator.validate(f"Bearer {_token()}", now=later)

    other = _codec().issue(
        {"tenant_id": "tenant-b", "sub": "operator-9"},
        expires_at=_future(),
    )
    validator.validate(f"Bearer {other}", now=NOW)


def test_error_envelope_carries_stable_code_and_correlation() -> None:
    validator = _validator()
    try:
        validator.validate(None, correlation_id="corr-9999-zzzz", now=NOW)
    except GatewayAuthenticationRefused as exc:
        envelope = validator.envelope(exc, "corr-9999-zzzz")
    assert envelope.to_document() == {
        "code": "authentication_refused",
        "message": "missing Authorization header",
        "correlation_id": "corr-9999-zzzz",
    }


def test_rate_limit_policy_requires_store_and_positive_values() -> None:
    with pytest.raises(GatewayMalformed, match="rate store"):
        _validator(rate_limit=RateLimitPolicy(max_requests=1, window_seconds=60))
    with pytest.raises(GatewayMalformed, match="positive"):
        RateLimitPolicy(max_requests=0, window_seconds=60)
