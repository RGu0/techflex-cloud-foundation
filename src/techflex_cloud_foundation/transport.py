"""Secure HTTP transport with no ambient proxy or credential authority."""

from __future__ import annotations

from typing import Any, Mapping, Protocol
from uuid import uuid4

import httpx


class TokenProvider(Protocol):
    def current_access_token(self) -> str: ...

    def refresh(self) -> object: ...


class CredentialVault(Protocol):
    def get(self, key: str) -> str | None: ...

    def set(self, key: str, value: str) -> None: ...

    def delete(self, key: str) -> None: ...


class SecureTransport:
    def __init__(
        self,
        base_url: str,
        *,
        verify: bool | str = True,
        transport: httpx.BaseTransport | None = None,
        timeout: httpx.Timeout | None = None,
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url.rstrip("/"), verify=verify, transport=transport,
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
