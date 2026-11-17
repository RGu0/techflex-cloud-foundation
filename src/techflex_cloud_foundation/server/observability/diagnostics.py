from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import io
import json
from typing import Protocol
import zipfile

from techflex_cloud_foundation.server.observability.events import TelemetryEvent


@dataclass(frozen=True, slots=True)
class EncryptedPayload:
    ciphertext: bytes
    algorithm: str
    key_id: str


class EnvelopeEncryptor(Protocol):
    def encrypt(self, plaintext: bytes, context: dict[str, str]) -> EncryptedPayload: ...


@dataclass(frozen=True, slots=True)
class DiagnosticSource:
    tenant_id: str
    terminal_id: str
    requested_at: datetime
    software_versions: tuple[tuple[str, str], ...]
    health_summary: tuple[tuple[str, int | float | str | bool], ...]
    events: tuple[TelemetryEvent, ...]


@dataclass(frozen=True, slots=True)
class DiagnosticArtifact:
    ciphertext: bytes
    plaintext_sha256: str
    ciphertext_sha256: str
    size_bytes: int
    encryption_algorithm: str
    key_id: str


def _archive_entry(name: str, payload: bytes) -> tuple[zipfile.ZipInfo, bytes]:
    info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o600 << 16
    return info, payload


class DiagnosticBundleBuilder:
    def __init__(self, encryptor: EnvelopeEncryptor) -> None:
        self.encryptor = encryptor

    def build(
        self,
        source: DiagnosticSource,
        *,
        include_session_data: bool = False,
    ) -> DiagnosticArtifact:
        if include_session_data:
            raise ValueError("session data requires a separate authorization and artifact action")
        software = dict(source.software_versions)
        health = dict(source.health_summary)
        allowed_software = {"app_version", "config_version", "protocol_version"}
        allowed_health = {
            "disk_free_bytes",
            "pending_sessions",
            "pending_bytes",
            "clock_skew_seconds",
            "device_state",
            "database_state",
        }
        if not set(software).issubset(allowed_software):
            raise ValueError("diagnostic software version field is not allowlisted")
        if not set(health).issubset(allowed_health):
            raise ValueError("diagnostic health field is not allowlisted")

        manifest = {
            "schema_version": "diagnostic-bundle/1",
            "tenant_id": source.tenant_id,
            "terminal_id": source.terminal_id,
            "requested_at": source.requested_at.isoformat(),
            "software_versions": software,
            "health_summary": health,
            "contains_session_data": False,
        }
        events = [event.to_safe_dict() for event in source.events]
        entries = (
            _archive_entry(
                "manifest.json",
                json.dumps(
                    manifest,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
            ),
            _archive_entry(
                "events.json",
                json.dumps(
                    events,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
            ),
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w") as archive:
            for info, payload in entries:
                archive.writestr(info, payload)
        plaintext = buffer.getvalue()
        encrypted = self.encryptor.encrypt(
            plaintext,
            {
                "tenant_id": source.tenant_id,
                "terminal_id": source.terminal_id,
                "artifact_type": "diagnostic-bundle/1",
            },
        )
        return DiagnosticArtifact(
            ciphertext=encrypted.ciphertext,
            plaintext_sha256=hashlib.sha256(plaintext).hexdigest(),
            ciphertext_sha256=hashlib.sha256(encrypted.ciphertext).hexdigest(),
            size_bytes=len(encrypted.ciphertext),
            encryption_algorithm=encrypted.algorithm,
            key_id=encrypted.key_id,
        )


@dataclass(frozen=True, slots=True)
class SupportAuditRecord:
    actor_id: str
    role: str
    tenant_id: str
    action: str
    resource_type: str
    resource_id: str
    reason: str
    occurred_at: datetime


class SupportAccessAuthorizer:
    _ALLOWED_ROLES = {"SUPPORT_ENGINEER", "SECURITY_ADMIN"}

    def authorize(
        self,
        *,
        actor_id: str,
        role: str,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        reason: str,
        occurred_at: datetime,
    ) -> SupportAuditRecord:
        if role not in self._ALLOWED_ROLES:
            raise PermissionError("support diagnostic access is not allowed for this role")
        if not reason.strip():
            raise ValueError("support access requires a reason")
        return SupportAuditRecord(
            actor_id=actor_id,
            role=role,
            tenant_id=tenant_id,
            action="SUPPORT_DIAGNOSTIC_ACCESS",
            resource_type=resource_type,
            resource_id=resource_id,
            reason=reason,
            occurred_at=occurred_at,
        )
