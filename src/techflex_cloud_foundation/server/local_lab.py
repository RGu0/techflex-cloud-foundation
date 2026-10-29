"""Loopback-only support for the private local integration fault lab."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
from typing import Any, cast
from urllib.parse import urlparse
from uuid import uuid4

# A source checkout's root; the runtime root must stay outside it.
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]
_REPARSE_POINT = 0x0400
ASGIApp = Callable[..., Awaitable[None]]


def validate_loopback_host(host: str) -> str:
    """Return a canonical loopback IP address or reject a network-exposed bind."""

    try:
        address = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ValueError("local lab host must be a literal loopback address") from exc
    if not address.is_loopback:
        raise ValueError("local lab must bind to a loopback address")
    return str(address)


def validate_local_seed_endpoint(seed_settings: Any) -> None:
    """Refuse to install the fault boundary in front of a remote seed endpoint."""

    endpoint = urlparse(str(seed_settings.public_base_url))
    if endpoint.scheme != "https" or endpoint.hostname is None:
        raise ValueError("local lab seed endpoint must be HTTPS on a loopback address")
    try:
        validate_loopback_host(endpoint.hostname)
    except ValueError as exc:
        raise ValueError("local lab seed endpoint must use a loopback address") from exc


@dataclass(frozen=True, slots=True)
class LocalLabPaths:
    """Private local directories used by a single lab runtime."""

    root: Path
    runtime: Path
    secrets: Path
    objects: Path
    audit: Path

    @classmethod
    def create(cls, root: Path) -> LocalLabPaths:
        resolved = root.expanduser().resolve()
        _validate_private_root(resolved)
        paths = cls(
            root=resolved,
            runtime=resolved / "runtime",
            secrets=resolved / "secrets",
            objects=resolved / "objects",
            audit=resolved / "audit",
        )
        for path in (paths.root, paths.runtime, paths.secrets, paths.objects, paths.audit):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return paths


@dataclass(frozen=True, slots=True)
class LocalLabSettings:
    """Non-secret operator settings for a local fault lab process."""

    paths: LocalLabPaths
    bind_host: str
    bind_port: int

    @classmethod
    def from_environment(cls, environ: dict[str, str] | None = None) -> LocalLabSettings:
        values = os.environ if environ is None else environ
        root = values.get("FFP_LOCAL_LAB_RUNTIME_ROOT", "")
        if not root:
            raise ValueError("FFP_LOCAL_LAB_RUNTIME_ROOT is required")
        host = validate_loopback_host(values.get("FFP_LOCAL_LAB_BIND_HOST", "127.0.0.1"))
        try:
            port = int(values.get("FFP_LOCAL_LAB_BIND_PORT", "8743"))
        except ValueError as exc:
            raise ValueError("FFP_LOCAL_LAB_BIND_PORT must be an integer") from exc
        if not 1 <= port <= 65535:
            raise ValueError("FFP_LOCAL_LAB_BIND_PORT must be between 1 and 65535")
        return cls(paths=LocalLabPaths.create(Path(root)), bind_host=host, bind_port=port)


def _validate_private_root(root: Path) -> None:
    repository = REPOSITORY_ROOT.resolve()
    if root == repository or root.is_relative_to(repository):
        raise ValueError("local lab runtime root must stay outside the repository")
    if any(part.casefold() == "onedrive" for part in root.parts):
        raise ValueError("local lab runtime root must not be in OneDrive")
    for path in (root, *root.parents):
        if _is_reparse_point(path):
            raise ValueError("local lab runtime root must not traverse a reparse point")


def _is_reparse_point(path: Path) -> bool:
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & _REPARSE_POINT)


async def build_local_lab_app(
    seed_settings: Any,
    control_token: str,
    audit_root: Path,
    *,
    pool_factory: Callable[..., Any] | None = None,
    restart_callback: Callable[[], None] | None = None,
) -> FaultInjectingApp:
    """Compose the existing persistent seed app behind the local fault boundary."""

    from techflex_cloud_foundation.server.seed import build_seed_app

    validate_local_seed_endpoint(seed_settings)
    seed_app = await build_seed_app(seed_settings, pool_factory=pool_factory)
    return FaultInjectingApp(
        seed_app,
        FaultController(control_token, audit_root),
        restart_callback=restart_callback,
    )


class FaultKind(StrEnum):
    """Finite failures that may be enabled only in the local fault lab."""

    UNAVAILABLE = "unavailable"
    LATENCY = "latency"
    THROTTLE = "throttle"
    DROP_AFTER_UPSTREAM = "drop_after_upstream"


@dataclass(frozen=True, slots=True)
class FaultRule:
    rule_id: str
    kind: FaultKind
    method: str
    path_prefix: str
    expires_at: datetime
    path_exact: str | None = None
    delay_seconds: float = 0.0
    throttle_bytes_per_second: int | None = None
    applications: int = 1

    @classmethod
    def create(
        cls,
        *,
        kind: FaultKind,
        method: str,
        path_prefix: str,
        expires_at: datetime,
        path_exact: str | None = None,
        delay_seconds: float = 0.0,
        throttle_bytes_per_second: int | None = None,
        applications: int = 1,
    ) -> FaultRule:
        normalized_method = method.strip().upper()
        if not normalized_method:
            raise ValueError("fault rule method is required")
        if not path_prefix.startswith("/"):
            raise ValueError("fault rule path prefix must start with /")
        if path_exact is not None and not path_exact.startswith("/"):
            raise ValueError("fault rule exact path must start with /")
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC):
            raise ValueError("fault rule expiry must be in the future")
        if delay_seconds < 0:
            raise ValueError("fault rule delay cannot be negative")
        if throttle_bytes_per_second is not None and throttle_bytes_per_second <= 0:
            raise ValueError("fault rule throttle must be positive")
        if applications <= 0:
            raise ValueError("fault rule applications must be positive")
        return cls(
            rule_id=str(uuid4()),
            kind=kind,
            method=normalized_method,
            path_prefix=path_prefix,
            expires_at=expires_at,
            path_exact=path_exact,
            delay_seconds=delay_seconds,
            throttle_bytes_per_second=throttle_bytes_per_second,
            applications=applications,
        )


class FaultController:
    """Owns local-only fault state and writes redacted application events."""

    def __init__(self, control_token: str, audit_root: Path) -> None:
        if len(control_token) < 16:
            raise ValueError("local fault control token is too short")
        self._control_token = control_token
        self._audit_path = audit_root / "fault-events.jsonl"
        self._rules: dict[str, FaultRule] = {}

    def apply(self, token: str, rule: FaultRule) -> str:
        self.authorize(token)
        self._rules[rule.rule_id] = rule
        self._record("enabled", rule, None)
        return rule.rule_id

    def authorize(self, token: str) -> None:
        if not secrets.compare_digest(token, self._control_token):
            raise PermissionError("local fault control token is invalid")

    def match(self, scope: dict[str, Any]) -> FaultRule | None:
        now = datetime.now(UTC)
        method = str(scope["method"]).upper()
        path = str(scope["path"])
        for rule_id, rule in tuple(self._rules.items()):
            if rule.expires_at <= now:
                self._rules.pop(rule_id)
                self._record("expired", rule, scope)
                continue
            if rule.method != method or not path.startswith(rule.path_prefix):
                continue
            if rule.path_exact is not None and path != rule.path_exact:
                continue
            if rule.applications == 1:
                self._rules.pop(rule_id)
            else:
                self._rules[rule_id] = replace(rule, applications=rule.applications - 1)
            self._record("applied", rule, scope)
            return rule
        return None

    def record_restart(self, token: str) -> None:
        """Authorize and audit an operator-requested local supervisor restart."""

        self.authorize(token)
        restart = FaultRule.create(
            kind=FaultKind.UNAVAILABLE,
            method="POST",
            path_prefix="/__local_lab/control/restart",
            expires_at=datetime.now(UTC) + timedelta(seconds=1),
        )
        self._record("restart_requested", restart, None)

    def _record(self, event: str, rule: FaultRule, scope: dict[str, Any] | None) -> None:
        correlation = _header(scope, b"x-correlation-id") if scope else None
        safe = {
            "event": event,
            "kind": rule.kind.value,
            "rule_id": rule.rule_id,
            "occurred_at": datetime.now(UTC).isoformat(),
            "method": rule.method,
            "path_digest": _digest(str(scope["path"])) if scope else None,
            "correlation_digest": _digest(correlation) if correlation else None,
        }
        with self._audit_path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(safe, sort_keys=True, separators=(",", ":")) + "\n")


class FaultInjectingApp:
    """Applies one controlled local rule before returning an ASGI response."""

    def __init__(
        self,
        app: ASGIApp,
        controller: FaultController,
        *,
        restart_callback: Callable[[], None] | None = None,
    ) -> None:
        self._app = app
        self._controller = controller
        self._restart_callback = restart_callback

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        if scope["path"] == "/__local_lab/control/rules":
            await self._control(scope, receive, send)
            return
        if scope["path"] == "/__local_lab/control/restart":
            await self._restart(scope, send)
            return
        rule = self._controller.match(scope)
        if rule is None:
            await self._app(scope, receive, send)
            return
        if rule.kind is FaultKind.UNAVAILABLE:
            await _service_unavailable(send)
            return
        if rule.kind is FaultKind.DROP_AFTER_UPSTREAM:
            await self._app(scope, receive, _discard)
            await _service_unavailable(send)
            return
        if rule.kind is FaultKind.LATENCY:
            import asyncio

            await asyncio.sleep(rule.delay_seconds)
        if rule.kind is FaultKind.THROTTLE:
            await self._app(scope, receive, _throttled_send(send, rule))
            return
        await self._app(scope, receive, send)

    async def _control(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["method"] != "POST":
            await _json_response(send, 405, {"error": "method_not_allowed"})
            return
        token = _header(scope, b"x-local-lab-control-token")
        try:
            self._controller.authorize(token or "")
            payload = json.loads((await _read_body(receive)).decode("utf-8"))
            expires = datetime.now(UTC) + timedelta(seconds=int(payload["expires_in_seconds"]))
            rule = FaultRule.create(
                kind=FaultKind(payload["kind"]),
                method=str(payload["method"]),
                path_prefix=str(payload["path_prefix"]),
                expires_at=expires,
                path_exact=(str(payload["path_exact"]) if payload.get("path_exact") else None),
                delay_seconds=float(payload.get("delay_seconds", 0)),
                throttle_bytes_per_second=payload.get("throttle_bytes_per_second"),
                applications=int(payload.get("applications", 1)),
            )
            rule_id = self._controller.apply(token or "", rule)
        except PermissionError:
            await _json_response(send, 403, {"error": "forbidden"})
            return
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            await _json_response(send, 400, {"error": "invalid_fault_rule"})
            return
        await _json_response(send, 201, {"rule_id": rule_id})

    async def _restart(
        self,
        scope: dict[str, Any],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope["method"] != "POST":
            await _json_response(send, 405, {"error": "method_not_allowed"})
            return
        if self._restart_callback is None:
            await _json_response(send, 409, {"error": "supervisor_restart_unavailable"})
            return
        try:
            self._controller.record_restart(_header(scope, b"x-local-lab-control-token") or "")
        except PermissionError:
            await _json_response(send, 403, {"error": "forbidden"})
            return
        await _json_response(send, 202, {"status": "restart_requested"})
        self._restart_callback()


async def _service_unavailable(send: Callable[[dict[str, Any]], Awaitable[None]]) -> None:
    await send({"type": "http.response.start", "status": 503, "headers": []})
    await send({"type": "http.response.body", "body": b"", "more_body": False})


async def _json_response(
    send: Callable[[dict[str, Any]], Awaitable[None]], status: int, payload: dict[str, str]
) -> None:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    await send(
        {
            "type": "http.response.start",
            "status": status,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": body, "more_body": False})


async def _read_body(
    receive: Callable[[], Awaitable[dict[str, Any]]]
) -> bytes:
    chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] != "http.request":
            return b"".join(chunks)
        chunks.append(message.get("body", b""))
        if not message.get("more_body", False):
            return b"".join(chunks)


async def _discard(_: dict[str, Any]) -> None:
    return None


def _throttled_send(
    send: Callable[[dict[str, Any]], Awaitable[None]], rule: FaultRule
) -> Callable[[dict[str, Any]], Awaitable[None]]:
    async def throttled(message: dict[str, Any]) -> None:
        if message["type"] == "http.response.body" and message.get("body"):
            import asyncio

            assert rule.throttle_bytes_per_second is not None
            await asyncio.sleep(len(message["body"]) / rule.throttle_bytes_per_second)
        await send(message)

    return throttled


def _header(scope: dict[str, Any] | None, name: bytes) -> str | None:
    if scope is None:
        return None
    for key, value in scope.get("headers", []):
        if key.lower() == name:
            return cast(str, value.decode("latin-1"))
    return None


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


__all__ = [
    "FaultController",
    "FaultInjectingApp",
    "FaultKind",
    "FaultRule",
    "build_local_lab_app",
    "LocalLabPaths",
    "LocalLabSettings",
    "validate_local_seed_endpoint",
    "validate_loopback_host",
]
