"""Framework-neutral request validation primitives (CP-02).

The server-side counterpart to the token and transport contracts: one
validator turns an Authorization header into a `TrustedRequestContext`,
enforcing audience/key-id/expiry through the token codec, rate limits per
authenticated principal, payload size caps, and the tenant invariant — the
tenant comes only from the token claims; a payload that names a different
tenant is refused, never honored.

Invariants carried over from RAY-341 and the reference gateway:

- Authentication failures, rate limits, and contract violations produce a
  stable `ErrorEnvelope` with a correlation id; they never leak internals.
- Every request carries a correlation id: a well-formed inbound one is kept,
  anything else is replaced, never trusted blindly.
- Rate limiting keys on the authenticated principal, not on client-supplied
  attributes.
- Unknown or malformed credentials are refused, never guessed; product
  routing, DTOs, and audience registration stay with the application.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import re
from typing import Protocol
from uuid import uuid4

from .manifest import _require_text
from .tokens import HmacTokenCodec, TokenError

_CORRELATION_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{7,63}")


class GatewayError(Exception):
    """Base class for request validation failures.

    Carries a stable ``code`` for the error envelope contract.
    """

    code = "gateway_error"


class GatewayMalformed(GatewayError):
    """A request component is structurally invalid."""

    code = "malformed_request"


class GatewayAuthenticationRefused(GatewayError):
    """The credential is missing, malformed, expired, or mismatched."""

    code = "authentication_refused"


class GatewayRateLimited(GatewayError):
    """The principal exceeded its rate policy; retry after the given delay."""

    code = "rate_limited"

    def __init__(self, message: str, *, retry_after_seconds: float) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class GatewayPayloadTooLarge(GatewayError):
    """The payload exceeds the configured size cap."""

    code = "payload_too_large"


class GatewayTenantMismatch(GatewayError):
    """The payload names a tenant other than the authenticated one."""

    code = "tenant_mismatch"


@dataclass(frozen=True)
class ErrorEnvelope:
    """The stable error body: code, message, and correlation id."""

    code: str
    message: str
    correlation_id: str

    def __post_init__(self) -> None:
        _require_text(self.code, field_name="error code")
        _require_text(self.message, field_name="error message")
        _require_text(self.correlation_id, field_name="correlation id")

    def to_document(self) -> dict[str, str]:
        return {
            "code": self.code,
            "message": self.message,
            "correlation_id": self.correlation_id,
        }


@dataclass(frozen=True)
class TrustedRequestContext:
    """What a validated request may rely on; tenant is token-derived only."""

    tenant_id: str
    subject_id: str
    correlation_id: str
    token_digest: str
    token_expires_at: datetime | None

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.subject_id, field_name="subject id")
        _require_text(self.correlation_id, field_name="correlation id")
        if len(self.token_digest) != 64:
            raise GatewayMalformed("token digest must be a complete SHA-256 hex")
        if self.token_expires_at is not None and self.token_expires_at.tzinfo is None:
            raise GatewayMalformed("token_expires_at must be timezone-aware")


@dataclass(frozen=True)
class RateLimitPolicy:
    """Token-bucket policy per authenticated principal."""

    max_requests: int
    window_seconds: int

    def __post_init__(self) -> None:
        if (
            not isinstance(self.max_requests, int)
            or isinstance(self.max_requests, bool)
            or self.max_requests <= 0
        ):
            raise GatewayMalformed("rate limit max_requests must be a positive integer")
        if (
            not isinstance(self.window_seconds, int)
            or isinstance(self.window_seconds, bool)
            or self.window_seconds <= 0
        ):
            raise GatewayMalformed("rate limit window_seconds must be a positive integer")


class RateLimitStore(Protocol):
    """Persistence boundary for rate buckets; production binds shared state."""

    def hit(self, key: str, policy: RateLimitPolicy, *, now: datetime) -> float | None:
        """Consume one token; return None when allowed, else retry-after seconds."""
        ...


class InMemoryRateLimitStore:
    """Volatile token-bucket reference, suitable for tests and integration."""

    def __init__(self) -> None:
        self._buckets: dict[str, tuple[float, datetime]] = {}

    def hit(self, key: str, policy: RateLimitPolicy, *, now: datetime) -> float | None:
        tokens, updated = self._buckets.get(key, (float(policy.max_requests), now))
        elapsed = (now - updated).total_seconds()
        refill = elapsed * (policy.max_requests / policy.window_seconds)
        tokens = min(float(policy.max_requests), tokens + refill)
        if tokens < 1.0:
            deficit = 1.0 - tokens
            self._buckets[key] = (tokens, now)
            return deficit * (policy.window_seconds / policy.max_requests)
        self._buckets[key] = (tokens - 1.0, now)
        return None


class RequestValidator:
    """One validation pipeline: authenticate, cap, rate-limit, bind tenant."""

    def __init__(
        self,
        codec: HmacTokenCodec,
        *,
        max_payload_bytes: int,
        rate_limit: RateLimitPolicy | None = None,
        rate_store: RateLimitStore | None = None,
    ) -> None:
        if not isinstance(codec, HmacTokenCodec):
            raise GatewayMalformed("codec must be an HmacTokenCodec")
        if (
            not isinstance(max_payload_bytes, int)
            or isinstance(max_payload_bytes, bool)
            or max_payload_bytes <= 0
        ):
            raise GatewayMalformed("max_payload_bytes must be a positive integer")
        if rate_limit is not None and rate_store is None:
            raise GatewayMalformed("a rate limit policy requires a rate store")
        self._codec = codec
        self._max_payload_bytes = max_payload_bytes
        self._rate_limit = rate_limit
        self._rate_store = rate_store

    def validate(
        self,
        authorization: str | None,
        *,
        payload_bytes: int | None = None,
        payload_tenant: str | None = None,
        correlation_id: str | None = None,
        now: datetime,
    ) -> TrustedRequestContext:
        """Validate one request and return its trusted context."""
        if now.tzinfo is None:
            raise GatewayMalformed("now must be timezone-aware")
        correlation = self._correlation_id(correlation_id)
        if (
            payload_bytes is not None
            and payload_bytes > self._max_payload_bytes
        ):
            raise GatewayPayloadTooLarge(
                f"payload of {payload_bytes} bytes exceeds the "
                f"{self._max_payload_bytes}-byte cap"
            )
        token = self._bearer_token(authorization)
        try:
            claims = self._codec.verify(token, now=now)
        except TokenError as exc:
            raise GatewayAuthenticationRefused(str(exc)) from exc
        tenant_id = claims.get("tenant_id")
        subject_id = claims.get("sub")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise GatewayAuthenticationRefused(
                "token carries no tenant claim; tenant is never taken from "
                "the request payload"
            )
        if not isinstance(subject_id, str) or not subject_id:
            raise GatewayAuthenticationRefused("token carries no subject claim")
        if payload_tenant is not None and payload_tenant != tenant_id:
            raise GatewayTenantMismatch(
                "payload tenant disagrees with the authenticated tenant; the "
                "payload never selects the tenant"
            )
        if self._rate_limit is not None and self._rate_store is not None:
            retry_after = self._rate_store.hit(
                f"{tenant_id}:{subject_id}", self._rate_limit, now=now
            )
            if retry_after is not None:
                raise GatewayRateLimited(
                    "rate limit exceeded for this principal",
                    retry_after_seconds=retry_after,
                )
        expires_at = None
        if claims.get("exp") is not None:
            expires_at = datetime.fromtimestamp(int(claims["exp"]), tz=now.tzinfo)
        return TrustedRequestContext(
            tenant_id=tenant_id,
            subject_id=subject_id,
            correlation_id=correlation,
            token_digest=hashlib.sha256(token.encode("ascii")).hexdigest(),
            token_expires_at=expires_at,
        )

    @staticmethod
    def envelope(exc: GatewayError, correlation_id: str) -> ErrorEnvelope:
        """Render a failure as the stable error envelope."""
        return ErrorEnvelope(
            code=exc.code, message=str(exc), correlation_id=correlation_id
        )

    @staticmethod
    def _correlation_id(supplied: str | None) -> str:
        if supplied is not None and _CORRELATION_ID_RE.fullmatch(supplied):
            return supplied
        return uuid4().hex

    @staticmethod
    def _bearer_token(authorization: str | None) -> str:
        if authorization is None:
            raise GatewayAuthenticationRefused("missing Authorization header")
        scheme, _, token = authorization.partition(" ")
        if scheme != "Bearer" or not token.strip():
            raise GatewayAuthenticationRefused(
                "Authorization must carry a Bearer token"
            )
        return token.strip()
