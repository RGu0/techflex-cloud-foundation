"""Framework-neutral request validation primitives (CP-02).

The server-side counterpart to the token and transport contracts: one
validator turns an Authorization header into a `TrustedRequestContext`,
enforcing audience/key-id/expiry through the token codec, rate limits per
authenticated principal, payload size caps, and the tenant invariant — the
tenant comes only from the token claims; a payload that names a different
tenant is refused, never honored.

Invariants carried over from RAY-341 and the reference gateway:

- Authentication failures, rate limits, and contract violations produce a
  stable `ErrorEnvelope` — code, correlation id, and the disposition fields
  `retryable`/`action`; they never leak internals.  The action set is the
  product's own, registered in an `ErrorActionCatalog`; the foundation
  hardcodes no business action names.
- Every request carries a correlation id: a well-formed inbound one is kept,
  anything else is replaced, never trusted blindly.
- Rate limiting keys on the authenticated principal, not on client-supplied
  attributes.
- Unknown or malformed credentials are refused, never guessed; product
  routing, DTOs, and audience registration stay with the application.
"""

from __future__ import annotations

from collections.abc import Iterable
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


_ERROR_ACTION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


@dataclass(frozen=True)
class ErrorEnvelope:
    """The stable error body a consumer receives across a process boundary.

    Fields answer the two questions every consumer must resolve before it
    can act: ``retryable`` — back off silently, or stop and escalate — and
    ``action`` — what to show or do next, from the product's own registered
    action set (see `ErrorActionCatalog`).

    ``action`` is not redundant with ``code`` and must not be removed as
    such: one code can legitimately name several dispositions, and only the
    action says which applies.  A real case: a payload-validation code under
    which the client may need to re-seal and resend (silent), to fetch
    missing segments (silent), to upgrade the client (interrupt the user),
    or to repeat the whole capture (interrupt the user).  The code is the
    same in all four; retrying the last two instead of stopping is the worst
    possible mistake, so the disposition travels with the error rather than
    being re-derived per consumer.

    Fallback contract for consumers: an action the consumer does not
    recognize — for example one introduced by a newer server — is decided
    from ``retryable`` alone: retryable means back off and retry the same
    request, non-retryable means stop and surface the error.  A consumer
    never invents a disposition for an unknown action beyond that rule.

    Serializes through `to_document` only; there is no other wire form.
    """

    code: str
    message: str
    correlation_id: str
    retryable: bool
    action: str

    def __post_init__(self) -> None:
        _require_text(self.code, field_name="error code")
        _require_text(self.message, field_name="error message")
        _require_text(self.correlation_id, field_name="correlation id")
        if not isinstance(self.retryable, bool):
            raise GatewayMalformed("error envelope retryable must be a bool")
        _require_text(self.action, field_name="error action")
        if not _ERROR_ACTION_RE.fullmatch(self.action):
            raise GatewayMalformed(
                "error action must be a stable token of letters, digits, "
                "and '._-' with no whitespace"
            )

    def to_document(self) -> dict[str, str | bool]:
        return {
            "code": self.code,
            "message": self.message,
            "correlation_id": self.correlation_id,
            "retryable": self.retryable,
            "action": self.action,
        }


class ErrorActionCatalog:
    """The product-registered set of actions an error envelope may carry.

    Foundation hardcodes no business action names: which dispositions exist
    — re-seal and resend, upgrade the client, contact the administrator —
    is product vocabulary, injected here the way `RoleCatalog` receives
    role names.  The catalog makes the set explicit and refuses anything
    outside it, so a typo or an unregistered invention is an error at the
    server that renders the envelope, never a surprise on the client.

    Construction validates shape; `require` is the registration check, and
    `envelope` is the render path that refuses to emit an unregistered
    action.
    """

    def __init__(self, actions: Iterable[str]) -> None:
        registered: set[str] = set()
        for action in actions:
            _require_text(action, field_name="error action")
            if not _ERROR_ACTION_RE.fullmatch(action):
                raise GatewayMalformed(
                    f"error action {action!r} must be a stable token of "
                    "letters, digits, and '._-' with no whitespace"
                )
            if action in registered:
                raise GatewayMalformed(
                    f"error action {action!r} is registered more than once"
                )
            registered.add(action)
        if not registered:
            raise GatewayMalformed("an error action catalog cannot be empty")
        self._actions = frozenset(registered)

    def __contains__(self, action: object) -> bool:
        return action in self._actions

    def require(self, action: str) -> str:
        """Return ``action`` when registered; refuse anything else."""
        if action not in self._actions:
            raise GatewayMalformed(
                f"error action {action!r} is not registered; the action set "
                "belongs to the product and unknown actions are refused, "
                "never guessed"
            )
        return action

    def envelope(
        self,
        *,
        code: str,
        message: str,
        correlation_id: str,
        retryable: bool,
        action: str,
    ) -> ErrorEnvelope:
        """Render an error envelope, refusing an unregistered action."""
        self.require(action)
        return ErrorEnvelope(
            code=code,
            message=message,
            correlation_id=correlation_id,
            retryable=retryable,
            action=action,
        )


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
        error_actions: ErrorActionCatalog | None = None,
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
        if error_actions is not None and not isinstance(
            error_actions, ErrorActionCatalog
        ):
            raise GatewayMalformed("error_actions must be an ErrorActionCatalog")
        self._codec = codec
        self._max_payload_bytes = max_payload_bytes
        self._rate_limit = rate_limit
        self._rate_store = rate_store
        self._error_actions = error_actions

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

    def envelope(
        self,
        exc: GatewayError,
        correlation_id: str,
        *,
        retryable: bool,
        action: str,
    ) -> ErrorEnvelope:
        """Render a failure as the stable error envelope.

        The disposition is stated by the caller — which exception is being
        rendered, and what the product wants the client to do about it, is
        handler knowledge — and when this validator was built with an
        ``error_actions`` catalog, an action outside the registered set is
        refused here rather than emitted.
        """
        if self._error_actions is not None:
            self._error_actions.require(action)
        return ErrorEnvelope(
            code=exc.code,
            message=str(exc),
            correlation_id=correlation_id,
            retryable=retryable,
            action=action,
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
