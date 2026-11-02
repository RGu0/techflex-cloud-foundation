"""Versioned terminal diagnostic package contracts (RAY-802 R1).

A terminal uploads the diagnostic export of gait-insole-flutter RAY-910 as
is: one JSON Lines text (``gait-insole-diagnostics/1``), a ``header`` line
first, then ``log`` and ``command`` lines. The cloud accepts the package
whole or rejects it whole; it never repairs or partially stores one.

Every top-level field of every line must be in the fixed set of its
``kind``. ``log.fields`` and ``command.params`` cannot be enumerated, so
they (and every other string) are screened for identity data the way the
client's ``Redactor`` removes it: a field whose key looks like identity data
may only hold ``<redacted>``, and no string may hold an unredacted mobile,
landline, e-mail or resident ID number. A bare name with neither a telling
key nor a pattern cannot be recognised here; the client's export-time
registration of every identity value it holds covers it.

Packages are kept for ``DIAGNOSTICS_RETENTION_DAYS`` from upload. A purge
then deletes the content and keeps a tombstone (id, institution, size,
digest, timestamps, ``deleted_at``) for audit.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Final
from uuid import UUID

from .cloud import ContractModel

DIAGNOSTICS_FORMAT: Final = "gait-insole-diagnostics/1"
DIAGNOSTICS_MEDIA_TYPE: Final = "application/x-ndjson"
# Uncompressed body; R1 does not accept a Content-Encoding.
DIAGNOSTICS_MAX_BYTES: Final = 8 * 1024 * 1024
DIAGNOSTICS_RETENTION_DAYS: Final = 30
DIAGNOSTICS_SHA256_PATTERN: Final = r"^[0-9a-f]{64}$"
# The only value a field with an identity-looking key may hold.
DIAGNOSTICS_REDACTED_VALUE: Final = "<redacted>"

DIAGNOSTICS_LINE_FIELDS: Final[dict[str, frozenset[str]]] = {
    "header": frozenset({
        "kind", "exported_at", "app_version", "cloud_environment", "platform",
        "os_version", "terminal_id", "tenant_id", "format", "dropped_lines",
    }),
    "log": frozenset({"kind", "t", "level", "cat", "msg", "fields", "error", "stack"}),
    "command": frozenset({
        "kind", "t", "command", "params", "expected_reply", "actual_reply",
        "elapsed_ms", "status", "ending", "rejection", "summary",
    }),
}


class DiagnosticRejectionReason(StrEnum):
    """Why a package was rejected; the error names only a line and this."""

    NOT_JSON = "not_json"
    HEADER_MISSING = "header_missing"
    FORMAT_UNSUPPORTED = "format_unsupported"
    UNKNOWN_KIND = "unknown_kind"
    UNKNOWN_FIELD = "unknown_field"
    HEADER_MISMATCH = "header_mismatch"
    IDENTITY_DETECTED = "identity_detected"


class DiagnosticUploadResponse(ContractModel):
    """The stored package; an idempotent replay returns the identical body."""

    diagnostic_id: UUID
    format: str
    size_bytes: int
    sha256: str
    received_at: datetime
    expires_at: datetime


class DiagnosticSummary(ContractModel):
    """Platform support metadata; a tombstone has ``deleted_at`` set."""

    diagnostic_id: UUID
    client_installation_id: UUID
    format: str
    size_bytes: int
    sha256: str
    received_at: datetime
    expires_at: datetime
    deleted_at: datetime | None = None


class DiagnosticListResponse(ContractModel):
    """Newest first, tombstones included."""

    items: tuple[DiagnosticSummary, ...]


__all__ = [
    "DIAGNOSTICS_FORMAT",
    "DIAGNOSTICS_LINE_FIELDS",
    "DIAGNOSTICS_MAX_BYTES",
    "DIAGNOSTICS_MEDIA_TYPE",
    "DIAGNOSTICS_REDACTED_VALUE",
    "DIAGNOSTICS_RETENTION_DAYS",
    "DIAGNOSTICS_SHA256_PATTERN",
    "DiagnosticListResponse",
    "DiagnosticRejectionReason",
    "DiagnosticSummary",
    "DiagnosticUploadResponse",
]
