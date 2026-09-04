"""Public contract tests for the HMAC token codec."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import os

import pytest

from techflex_cloud_foundation import (
    HmacTokenCodec,
    TokenAudienceMismatch,
    TokenError,
    TokenExpired,
    TokenHeaderMismatch,
    TokenMalformed,
    TokenSignatureInvalid,
    tokens,
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


def _signed(payload: dict[str, object], *, header: dict[str, object] | None = None) -> str:
    """A token this codec's secret actually signs, carrying a chosen payload.

    The signature covers whatever the issuer put in the payload, so a claim
    can be both authentic and nonsense.  Forging one here is the only way to
    reach the claim checks that run after the signature check passes.
    """

    encoded_header = tokens._encoded_json(header or {"alg": "HS256", "kid": "k1", "typ": "access"})
    encoded_payload = tokens._encoded_json(payload)
    signature = hmac.new(
        SECRET, f"{encoded_header}.{encoded_payload}".encode("ascii"), hashlib.sha256
    ).digest()
    return f"{encoded_header}.{encoded_payload}.{tokens._base64url(signature)}"


def test_non_ascii_token_is_malformed() -> None:
    """A non-ASCII token must report the same contract as any other bad one.

    The signing input was built with a bare ``.encode("ascii")`` on the first
    thing ``verify`` touches, so ``codec.verify("\N{LATIN SMALL LETTER E WITH ACUTE}.b.c")``
    raised ``UnicodeEncodeError`` -- not a ``TokenError`` at all -- while a
    wrong segment count and a bad base64url segment both reported
    ``TokenMalformed`` correctly.
    """

    codec = _codec()
    for token in ("\N{LATIN SMALL LETTER E WITH ACUTE}.b.c", "a.\N{LATIN SMALL LETTER E WITH ACUTE}.c", "\N{SNOWMAN}.\N{SNOWMAN}.\N{SNOWMAN}"):
        with pytest.raises(TokenMalformed):
            codec.verify(token)


def test_non_integer_exp_is_malformed() -> None:
    """An authentic token can still carry an exp that is not a timestamp."""

    codec = _codec()
    # NaN and infinity are absent on purpose: _encoded_json sets
    # allow_nan=False, so a token cannot carry them in the first place.
    for expires in ("soon", "1.5", "", ["later"], {"at": 1}):
        token = _signed({"aud": "api", "iat": 0, "exp": expires})
        with pytest.raises(TokenMalformed):
            codec.verify(token)


def test_numeric_exp_forms_are_accepted() -> None:
    codec = _codec()
    future = int((datetime.now(UTC) + timedelta(minutes=5)).timestamp())

    assert codec.verify(_signed({"aud": "api", "iat": 0, "exp": future}))["exp"] == future
    assert codec.verify(_signed({"aud": "api", "iat": 0, "exp": future + 0.5}))["exp"] == future + 0.5


def test_every_verification_failure_is_a_token_error() -> None:
    """One contract for the whole surface: nothing escapes as a raw builtin."""

    codec = _codec()
    rejected = (
        "not-a-token",
        "a.b",
        "a.b.c.d",
        "a.b.!!!",
        "\N{LATIN SMALL LETTER E WITH ACUTE}.\N{LATIN SMALL LETTER E WITH ACUTE}.\N{LATIN SMALL LETTER E WITH ACUTE}",
        _signed({"aud": "api", "iat": 0, "exp": "soon"}),
        _signed({"aud": "other", "iat": 0}),
        _signed({"aud": "api", "iat": 0}, header={"alg": "HS256", "kid": "other", "typ": "access"}),
    )
    for token in rejected:
        with pytest.raises(TokenError):
            codec.verify(token)


def test_issuing_is_unaffected_by_the_shared_signing_input() -> None:
    """Both segments come from base64url, so issuing cannot hit the new path."""

    codec = _codec()
    token = codec.issue({"subject": "\N{LATIN SMALL LETTER E WITH ACUTE}\N{SNOWMAN}"})

    assert codec.verify(token)["subject"] == "\N{LATIN SMALL LETTER E WITH ACUTE}\N{SNOWMAN}"
    assert token.isascii()
