"""Wire-preserving adapters from the payload registry to the HTTP data plane.

Legacy DTOs remain unchanged. Root documents retain omitted/default fields so
canonical digests describe exactly the client's contract, not an expanded DTO.
"""
from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from pydantic import ConfigDict, RootModel, model_validator

from techflex_cloud_foundation.payload_contracts import (
    PayloadContractError,
    default_payload_schema_registry,
)

LEGACY_PAYLOAD_SCHEMAS = frozenset({"raw-segment/1", "insole-session-archive/1"})


def _require_neutral(schema_id: str) -> None:
    if schema_id in LEGACY_PAYLOAD_SCHEMAS:
        raise ValueError("legacy schema requires its legacy DTO")


class RegisteredSessionRequest(RootModel[dict[str, Any]]):
    model_config = ConfigDict(frozen=True, json_schema_extra={
        "description": "Registry-validated neutral session. See payload-schema-vectors.json "
                       "and registry-ingestion.md for registered fields. "
                       "Terminal credentials required.",
        "x-payload-registry": "versions.payload_schema",
    })

    @model_validator(mode="after")
    def validate_registry(self) -> RegisteredSessionRequest:
        try:
            default_payload_schema_registry().validate_session(self.root)
        except PayloadContractError as exc:
            raise ValueError(str(exc)) from exc
        # Legacy products must go through their existing typed/authenticated path.
        _require_neutral(self.root["versions"]["payload_schema"])
        return self

    @property
    def session_id(self) -> UUID:
        return UUID(str(self.root["session_id"]))

    @property
    def client_installation_id(self) -> UUID:
        return UUID(str(self.root["client_installation_id"]))

    @property
    def terminal_id(self) -> UUID:
        return self.client_installation_id

    @property
    def site_id(self) -> UUID | None:
        value = self.root.get("site_id")
        return UUID(str(value)) if value is not None else None

    @property
    def started_at(self) -> datetime:
        return datetime.fromisoformat(str(self.root["started_at"]).replace("Z", "+00:00"))

    @property
    def versions(self) -> Any:
        return SimpleNamespace(**self.root["versions"])


class RegisteredSegmentMetadata(RootModel[dict[str, Any]]):
    model_config = ConfigDict(frozen=True, json_schema_extra={
        "description": "Registry-validated segment core plus declared profile/extension fields.",
        "x-payload-registry": "payload_schema_version",
    })

    @model_validator(mode="after")
    def validate_registry(self) -> RegisteredSegmentMetadata:
        try:
            default_payload_schema_registry().validate_segment(
                self.root.get("payload_schema_version", ""), self.root)
            _require_neutral(self.root["payload_schema_version"])
        except PayloadContractError as exc:
            raise ValueError(str(exc)) from exc
        return self

    @property
    def segment_index(self) -> int:
        return int(self.root["segment_index"])

    @property
    def size_bytes(self) -> int:
        return int(self.root["size_bytes"])

    @property
    def sha256(self) -> str:
        return str(self.root["sha256"])

    @property
    def payload_schema_version(self) -> str:
        return str(self.root["payload_schema_version"])


class RegisteredManifest(RootModel[dict[str, Any]]):
    model_config = ConfigDict(frozen=True, json_schema_extra={
        "description": "Registry-validated manifest; omitted quality remains UNKNOWN. "
                       "Accepted bytes and declared profile metadata must match.",
        "x-payload-registry": "schema_version",
    })

    @model_validator(mode="after")
    def validate_registry(self) -> RegisteredManifest:
        registry = default_payload_schema_registry()
        try:
            schema = next(
                (registry.get(s) for s in registry.schema_ids
                 if registry.get(s).manifest_schema == self.root.get("schema_version")), None
            )
            if schema is None:
                raise ValueError("unregistered manifest schema")
            _require_neutral(schema.schema_id)
            registry.validate_manifest(schema.schema_id, self.root)
        except PayloadContractError as exc:
            raise ValueError(str(exc)) from exc
        return self

    @property
    def schema_version(self) -> str:
        return str(self.root["schema_version"])

    @property
    def segments(self) -> tuple[Any, ...]:
        return tuple(SimpleNamespace(**part) for part in self.root["segments"])

    @property
    def segment_count(self) -> int:
        return int(self.root["segment_count"])

    @property
    def total_bytes(self) -> int:
        return int(self.root["total_bytes"])

    @property
    def local_quality_outcome(self) -> Any:
        from .cloud import ValidityStatus
        return ValidityStatus(self.root.get("local_quality_outcome", "UNKNOWN"))

    @property
    def ended_at(self) -> datetime | None:
        value = self.root.get("ended_at")
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None


def registered_receipts_match(
    manifest: RegisteredManifest, documents: list[dict[str, Any]]
) -> bool:
    registry = default_payload_schema_registry()
    schema = next(registry.get(s) for s in registry.schema_ids
                  if registry.get(s).manifest_schema == manifest.schema_version)
    try:
        validated = registry.validate_manifest(schema.schema_id, manifest.root)
        segments = [registry.validate_segment(schema.schema_id, doc) for doc in documents]
        registry.verify_received(validated, segments)
    except PayloadContractError:
        return False
    return True


def segment_metadata_matches(left: Any, right: Any) -> bool:
    """Registry receipts bind all metadata; legacy receipts retain digest-only replay."""
    if isinstance(left, RegisteredSegmentMetadata) or isinstance(right, RegisteredSegmentMetadata):
        return bool(left.model_dump(mode="json") == right.model_dump(mode="json"))
    return bool(left.sha256 == right.sha256)
