from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Protocol
from uuid import UUID

from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.validation_telemetry import (
    DeviceValidationTelemetryBatchRequest,
    DeviceValidationTelemetryEvent,
    DeviceValidationTelemetryReceipt,
)
from techflex_cloud_foundation.platform_errors import IdempotencyConflict, TenantAccessDenied
from techflex_cloud_foundation.server.access_auth import TenantAccessContext


@dataclass(frozen=True, slots=True)
class StoredValidationTelemetryEvent:
    tenant_id: UUID
    client_installation_id: UUID
    event: DeviceValidationTelemetryEvent
    sha256: str


class InMemoryValidationTelemetryRepository:
    def __init__(self) -> None:
        self._events: dict[
            tuple[UUID, UUID], StoredValidationTelemetryEvent
        ] = {}

    def accept(
        self,
        *,
        tenant_id: UUID,
        client_installation_id: UUID,
        event: DeviceValidationTelemetryEvent,
    ) -> bool:
        digest = hashlib.sha256(
            canonical_json_bytes(event.model_dump(mode="json"))
        ).hexdigest()
        key = (tenant_id, event.event_id)
        existing = self._events.get(key)
        if existing is not None:
            if existing.sha256 != digest:
                raise IdempotencyConflict("遥测事件摘要冲突") from None
            return True
        self._events[key] = StoredValidationTelemetryEvent(
            tenant_id=tenant_id,
            client_installation_id=client_installation_id,
            event=event,
            sha256=digest,
        )
        return False

    def events_for(self, tenant_id: UUID) -> tuple[StoredValidationTelemetryEvent, ...]:
        return tuple(
            event
            for (candidate_tenant, _), event in self._events.items()
            if candidate_tenant == tenant_id
        )


class ValidationTelemetryRepository(Protocol):
    def accept(
        self,
        *,
        tenant_id: UUID,
        client_installation_id: UUID,
        event: DeviceValidationTelemetryEvent,
    ) -> bool: ...


class FileSystemValidationTelemetryRepository:
    """Private, durable, immutable storage for strictly validated telemetry."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).resolve()
        self._staging = self.root / ".staging"
        self._mkdir_private(self.root)
        self._mkdir_private(self._staging)

    @staticmethod
    def _mkdir_private(path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            path.chmod(0o700)
        except OSError:
            pass

    def _event_path(self, tenant_id: UUID, event_id: UUID) -> Path:
        directory = self.root / "tenants" / str(tenant_id) / "events"
        self._mkdir_private(directory)
        return directory / f"{event_id}.json"

    @staticmethod
    def _digest(event: DeviceValidationTelemetryEvent) -> str:
        return hashlib.sha256(
            canonical_json_bytes(event.model_dump(mode="json"))
        ).hexdigest()

    @staticmethod
    def _set_private_file_mode(path: Path, descriptor: int) -> None:
        """Apply private permissions on POSIX and Windows Python versions."""

        fchmod = getattr(os, "fchmod", None)
        if fchmod is not None:
            fchmod(descriptor, 0o600)
        else:
            os.chmod(path, 0o600)

    @staticmethod
    def _decode(path: Path) -> StoredValidationTelemetryEvent:
        document = json.loads(path.read_bytes())
        if document.get("schema_version") != "validation-telemetry-store/1":
            raise ValueError("unsupported validation telemetry store schema")
        event = DeviceValidationTelemetryEvent.model_validate(document["event"])
        stored = StoredValidationTelemetryEvent(
            tenant_id=UUID(document["tenant_id"]),
            client_installation_id=UUID(document["client_installation_id"]),
            event=event,
            sha256=document["sha256"],
        )
        if stored.sha256 != FileSystemValidationTelemetryRepository._digest(event):
            raise ValueError("validation telemetry digest mismatch")
        return stored

    def accept(
        self,
        *,
        tenant_id: UUID,
        client_installation_id: UUID,
        event: DeviceValidationTelemetryEvent,
    ) -> bool:
        digest = self._digest(event)
        final_path = self._event_path(tenant_id, event.event_id)
        if final_path.exists():
            existing = self._decode(final_path)
            if existing.sha256 != digest:
                raise IdempotencyConflict("遥测事件摘要冲突") from None
            return True

        document = {
            "schema_version": "validation-telemetry-store/1",
            "tenant_id": str(tenant_id),
            "client_installation_id": str(client_installation_id),
            "event": event.model_dump(mode="json"),
            "sha256": digest,
        }
        payload = canonical_json_bytes(document)
        descriptor, staging_name = tempfile.mkstemp(
            prefix="validation-telemetry-", suffix=".part", dir=self._staging
        )
        staging_path = Path(staging_name)
        try:
            self._set_private_file_mode(staging_path, descriptor)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.link(staging_path, final_path)
            except FileExistsError:
                existing = self._decode(final_path)
                if existing.sha256 != digest:
                    raise IdempotencyConflict("遥测事件摘要冲突") from None
                return True
            return False
        finally:
            staging_path.unlink(missing_ok=True)

    def events_for(self, tenant_id: UUID) -> tuple[StoredValidationTelemetryEvent, ...]:
        directory = self.root / "tenants" / str(tenant_id) / "events"
        if not directory.is_dir():
            return ()
        return tuple(self._decode(path) for path in sorted(directory.glob("*.json")))


class ValidationTelemetryService:
    def __init__(self, repository: ValidationTelemetryRepository) -> None:
        self._repository = repository

    def ingest(
        self,
        context: TenantAccessContext,
        request: DeviceValidationTelemetryBatchRequest,
    ) -> DeviceValidationTelemetryReceipt:
        if request.client_installation_id != context.client_installation_id:
            raise TenantAccessDenied("遥测安装实例与登录凭据不一致")
        if not context.capabilities.allow_upload:
            raise TenantAccessDenied("当前 License 不允许上传")
        replay_count = sum(
            self._repository.accept(
                tenant_id=context.tenant_id,
                client_installation_id=context.client_installation_id,
                event=event,
            )
            for event in request.events
        )
        return DeviceValidationTelemetryReceipt(
            acknowledged_event_ids=tuple(event.event_id for event in request.events),
            idempotent_replays=replay_count,
        )
