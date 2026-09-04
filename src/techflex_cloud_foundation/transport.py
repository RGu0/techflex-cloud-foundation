"""Secure HTTP transport with no ambient proxy or credential authority.

TLS verification is not configurable off.  ``SecureTransport`` accepts a
private CA as PEM bytes or a prepared ``ssl.SSLContext`` and refuses anything
that would weaken verification, including a plaintext ``base_url``.
"""

from __future__ import annotations

import ssl
from typing import Any, Mapping, Protocol
from uuid import uuid4

import httpx


class InsecureTransportRejected(ValueError):
    """A transport configuration would have disabled or weakened TLS."""


class TokenProvider(Protocol):
    def current_access_token(self) -> str: ...

    def refresh(self) -> object: ...


class CredentialVault(Protocol):
    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...

    def delete(self, key: str) -> None: ...


class SecureTransport:
    """HTTPS client that cannot be configured into an insecure state.

    ``verify`` used to be ``bool | str`` defaulting to True, so a caller could
    pass ``verify=False`` and turn every certificate check off -- the single
    edit most likely to be made while debugging a private-CA environment and
    least likely to be noticed once it works.  A library that offers the switch
    is responsible for the deployments that flip it, so the switch is gone.

    A private CA is supplied as PEM ``bytes``, which is the form
    ``CloudDefaultConfig.ca_bundle_pem`` already has.  Previously every
    consumer had to write those bytes to a file with ``atomic_write`` and pass
    the path, because httpx only accepted a path; the resulting CA file then
    belonged to nobody and outlived the process that made it.  The PEM is now
    loaded straight into an in-memory ``ssl.SSLContext``.

    Callers with their own policy -- client certificates, a pinned protocol
    version -- pass a prepared ``ssl.SSLContext``.  It is checked rather than
    trusted: a context with verification or hostname checking disabled is the
    same hole through a different door.
    """

    def __init__(
        self,
        base_url: str,
        *,
        verify: bytes | ssl.SSLContext | None = None,
        transport: httpx.BaseTransport | None = None,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=_verified_base_url(base_url), verify=_ssl_context(verify),
            transport=transport,
            trust_env=False,
            timeout=timeout or httpx.Timeout(connect=5, read=20, write=20, pool=5),
        )

    def __enter__(self) -> "SecureTransport":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def request(
        self,
        method: str,
        path: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: Any = None,
        **kwargs: Any,
    ) -> httpx.Response:
        if headers is not None and "X-Correlation-ID" in headers:
            if kwargs:
                return self._client.request(
                    method, path, headers=headers, content=content, **kwargs
                )
            return self._client.request(method, path, headers=headers, content=content)
        effective_headers = dict(headers or {})
        effective_headers["X-Correlation-ID"] = str(uuid4())
        return self._client.request(
            method, path, headers=effective_headers, content=content, **kwargs
        )


class AuthorizedTransport:
    def __init__(self, transport: SecureTransport, tokens: TokenProvider) -> None:
        self._transport = transport
        self._tokens = tokens

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        correlation_id = str(uuid4())
        response = self._request(method, path, correlation_id=correlation_id, **kwargs)
        if response.status_code != 401:
            return response
        self._tokens.refresh()
        return self._request(method, path, correlation_id=correlation_id, **kwargs)

    def _request(self, method: str, path: str, *, correlation_id: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}) or {})
        headers.update({"Authorization": f"Bearer {self._tokens.current_access_token()}", "X-Correlation-ID": correlation_id})
        return self._transport.request(method, path, headers=headers, **kwargs)


def _verified_base_url(base_url: str) -> str:
    """Require https, so a relative request path cannot leave TLS behind."""

    if not isinstance(base_url, str) or not base_url.startswith("https://"):
        raise InsecureTransportRejected(
            f"base_url must be an https:// URL, got {base_url!r}. Every request "
            "on this client is relative to it, so a plaintext base URL sends "
            "bearer tokens in the clear."
        )
    return base_url.rstrip("/")


def _ssl_context(verify: bytes | ssl.SSLContext | None) -> ssl.SSLContext:
    """Build the TLS context, refusing anything that weakens verification."""

    if verify is None:
        return ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    if isinstance(verify, ssl.SSLContext):
        if verify.verify_mode == ssl.CERT_NONE or not verify.check_hostname:
            raise InsecureTransportRejected(
                "the supplied SSLContext does not verify certificates or "
                "hostnames; set verify_mode=ssl.CERT_REQUIRED and "
                "check_hostname=True"
            )
        return verify
    if isinstance(verify, bytes | bytearray):
        return _context_from_pem(bytes(verify))
    # bool lands here, which is the point: verify=False no longer exists, and
    # verify=True is not spelled that way either -- omit it for the system
    # trust store.
    raise InsecureTransportRejected(
        f"verify must be PEM bytes, an ssl.SSLContext, or None for the system "
        f"trust store; got {type(verify).__name__}. TLS verification cannot be "
        "turned off through this transport."
    )


def _context_from_pem(pem: bytes) -> ssl.SSLContext:
    """Trust a private CA without writing it to disk.

    ``cadata`` keeps the bundle in the process.  The alternative every
    consumer was performing by hand -- ``atomic_write`` the PEM to a file and
    pass the path -- produced a trust anchor on disk with no owner and no
    lifetime, in a library whose whole point is that such files are managed.
    """

    try:
        return ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cadata=pem.decode("ascii")
        )
    except UnicodeDecodeError as exc:
        raise InsecureTransportRejected(
            "CA bundle must be PEM text; DER bytes are not accepted"
        ) from exc
    except ssl.SSLError as exc:
        raise InsecureTransportRejected(
            f"CA bundle is not a usable PEM certificate bundle: {exc}"
        ) from exc
