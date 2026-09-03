"""Public contract tests for the HMAC token codec."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os

import pytest

from techflex_cloud_foundation import (
    HmacTokenCodec,
    TokenAudienceMismatch,
    TokenExpired,
    TokenHeaderMismatch,
    TokenMalformed,
    TokenSignatureInvalid,
)

SECRET = os.urandom(32)


def _codec(**overrides: object) -> HmacTokenCodec:
    kwargs = {"secret": SECRET, "key_id": "k1", "token_type": "access", "audience": "api"}
    kwargs.update(overrides)
    return HmacTokenCodec(**kwargs)  # type: ignore[arg-type]


def test_issue_verify_roundtrip() -> None:
    codec = _codec()
    token = codec.issue({"subject": "user-1", "role": "reader"})

    claims = codec.verify(token)

    assert claims["subject"] == "user-1"
    assert claims["aud"] == "api"
    assert isinstance(claims["iat"], int)


def test_three_segments_and_url_safe() -> None:
    token = _codec().issue({"subject": "user-1"})

    assert len(token.split(".")) == 3
    assert "+" not in token and "/" not in token and "=" not in token


def test_tampered_signature_is_refused() -> None:
    codec = _codec()
    token = codec.issue({"subject": "user-1"})
    forged = token[:-2] + ("aa" if not token.endswith("aa") else "bb")

    with pytest.raises(TokenSignatureInvalid):
        codec.verify(forged)


def test_wrong_secret_is_refused() -> None:
    token = _codec().issue({"subject": "user-1"})

    with pytest.raises(TokenSignatureInvalid):
        _codec(secret=os.urandom(32)).verify(token)


def test_wrong_key_id_is_refused() -> None:
    token = _codec().issue({"subject": "user-1"})

    # Same secret: the signature still matches, so the pinned kid header
    # check is what refuses the token (rotation with a new secret would
    # instead fail the signature check, covered above).
    with pytest.raises(TokenHeaderMismatch):
        _codec(key_id="k2").verify(token)


def test_wrong_type_or_audience_is_refused() -> None:
    token = _codec().issue({"subject": "user-1"})

    with pytest.raises(TokenHeaderMismatch):
        _codec(token_type="refresh").verify(token)
    with pytest.raises(TokenAudienceMismatch):
        _codec(audience="other").verify(token)


def test_malformed_tokens_are_refused() -> None:
    codec = _codec()
    with pytest.raises(TokenMalformed):
        codec.verify("not-a-token")
    with pytest.raises(TokenMalformed):
        codec.verify("a.b.!!!")


def test_expired_token_is_refused() -> None:
    codec = _codec()
    now = datetime.now(UTC)
    token = codec.issue({"subject": "user-1"}, expires_at=now + timedelta(minutes=5))

    codec.verify(token, now=now + timedelta(minutes=4))
    with pytest.raises(TokenExpired):
        codec.verify(token, now=now + timedelta(minutes=6))


def test_reserved_claims_are_rejected() -> None:
    codec = _codec()
    with pytest.raises(ValueError, match="reserved"):
        codec.issue({"aud": "sneaky"})
    with pytest.raises(ValueError, match="reserved"):
        codec.issue({"exp": 1})


def test_configuration_is_validated() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        _codec(secret=b"short")
    with pytest.raises(ValueError, match="key_id"):
        _codec(key_id="has.dot")
    with pytest.raises(ValueError, match="audience"):
        _codec(audience="")


def test_expires_at_must_be_future_and_aware() -> None:
    codec = _codec()
    with pytest.raises(ValueError, match="future"):
        codec.issue({"s": 1}, expires_at=datetime.now(UTC) - timedelta(seconds=1))
    with pytest.raises(ValueError, match="timezone-aware"):
        codec.issue({"s": 1}, expires_at=datetime(2030, 1, 1))
