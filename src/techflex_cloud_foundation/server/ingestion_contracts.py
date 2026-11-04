"""Strict registry boundary, with an explicit legacy insole compatibility path.

Original JSON is separate from interpreted values: timestamps, optional defaults
and product extensions must not change a client's canonical identity on reload.
"""
from __future__ import annotations

import copy
from datetime import datetime
from types import SimpleNamespace
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict, model_serializer

from techflex_cloud_foundation.contracts.cloud import SessionCreateRequest, ValidityStatus
from techflex_cloud_foundation.payload_contracts import (
    CORE_SESSION_FIELDS,
    CORE_VERSION_FIELDS,
    PROFILES,
    FieldKind,
    FieldSpec,
    PayloadSchemaRegistry,
)

LEGACY_FIELDS = {"subject_uuid", "consent_record_id", "terminal_id", "device_id", "test_protocol"}
LEGACY_VERSIONS = {"protocol_profile", "calibration"}


def known_instant(value: datetime | None) -> datetime | None:
    """A registry timestamp without an offset identifies no global SQL instant."""
    return value if value is not None and value.utcoffset() is not None else None


class RegistryDocument(BaseModel):
    """Validated wire document plus interpreted values for repository operations."""

    model_config = ConfigDict(arbitrary_types_allowed=True)
    document: dict[str, Any]
    values: dict[str, Any]
    profile: str
    payload_schema: str
    registry: PayloadSchemaRegistry | None = None

    @model_serializer
    def wire_document(self) -> dict[str, Any]:
        return copy.deepcopy(self.document)

    def __getattr__(self, name: str) -> Any:
        values = self.__dict__.get("values", {})
        if name in values:
            return values[name]
        raise AttributeError(name)

    def verify_received(self, metadata: list[Any]) -> None:
        assert self.registry is not None
        manifest = self.registry.validate_manifest(self.payload_schema, self.document)
        segments = [self.registry.validate_segment(
            self.payload_schema, item.model_dump(mode="json")
        ) for item in metadata]
        self.registry.verify_received(manifest, segments)


def restored_document(
    document: dict[str, Any], kind: str, profile: str, payload_schema: str,
    registry: PayloadSchemaRegistry | None = None,
) -> RegistryDocument:
    """Interpret a document already checked at admission; keep its bytes' identity."""
    values = copy.deepcopy(document)
    if profile == "byte-segment":
        if kind == "segment":
            for field in (
                "start_frame_index", "frame_count", "start_monotonic_ns", "end_monotonic_ns",
                "compression", "cipher",
            ):
                values[field] = None
        elif kind == "manifest":
            values["total_frames"] = None
    if kind == "session":
        for name in ("session_id", "site_id", "client_installation_id"):
            values[name] = UUID(document[name]) if document.get(name) is not None else None
        values["started_at"] = datetime.fromisoformat(document["started_at"].replace("Z", "+00:00"))
        values["terminal_id"] = values["client_installation_id"]
        for name in ("device_id", "subject_uuid", "consent_record_id"):
            values[name] = None
        values["test_protocol"] = SimpleNamespace(id=None, version=None)
        values["versions"] = SimpleNamespace(
            protocol_profile=None, calibration=None,
            app=document["versions"]["app"], payload_schema=payload_schema,
        )
        values.setdefault("config_snapshot", {})
    elif kind == "manifest":
        if registry is not None:
            values.setdefault("schema_version", registry.get(payload_schema).manifest_schema)
        values["segments"] = tuple(SimpleNamespace(**item) for item in document["segments"])
        specs = {
            spec.name: spec for spec in registry.get(payload_schema).manifest_extension
        } if registry else {}
        end_spec = specs.get("ended_at")
        quality_spec = specs.get("local_quality_outcome")
        values["ended_at"] = (
            datetime.fromisoformat(document["ended_at"].replace("Z", "+00:00"))
            if end_spec and end_spec.kind == FieldKind.TIMESTAMP and document.get("ended_at")
            else None
        )
        values["local_quality_outcome"] = ValidityStatus(
            document.get("local_quality_outcome", "UNKNOWN")
        ) if (
            quality_spec and quality_spec.kind == FieldKind.ENUM
            and set(quality_spec.allowed).issubset({item.value for item in ValidityStatus})
        ) else ValidityStatus.UNKNOWN
    return RegistryDocument(
        document=copy.deepcopy(document), values=values, profile=profile,
        payload_schema=payload_schema, registry=registry,
    )


def parse_session(document: Any, registry: PayloadSchemaRegistry) -> Any:
    versions = document.get("versions", {}) if isinstance(document, dict) else {}
    schema_id = versions.get("payload_schema") if isinstance(versions, dict) else None
    if schema_id == "raw-segment/1" or (
        schema_id == "insole-session-archive/1" and (
            bool(LEGACY_FIELDS.intersection(document))
            or bool(LEGACY_VERSIONS.intersection(versions))
        )
    ):
        return SessionCreateRequest.model_validate(document)
    validated = registry.validate_session(document)
    return restored_document(
        document, "session", registry.get(validated.schema_id).profile.value, validated.schema_id
    )


def parse_registered(
    document: Any, kind: str, schema: str, registry: PayloadSchemaRegistry,
) -> Any:
    if kind == "segment":
        registry.validate_segment(schema, document)
    else:
        registry.validate_manifest(schema, document)
    return restored_document(document, kind, registry.get(schema).profile.value, schema, registry)


def _object_schema(specs: tuple[FieldSpec, ...]) -> dict[str, Any]:
    return {
        "type": "object", "additionalProperties": False,
        "properties": {spec.name: _field_schema(spec) for spec in specs},
        "required": [spec.name for spec in specs if spec.required],
    }


def _field_schema(spec: FieldSpec) -> dict[str, Any]:
    if spec.kind == FieldKind.OBJECT:
        result = _object_schema(spec.fields)
    elif spec.kind == FieldKind.MAPPING:
        result = {"type": "object", "additionalProperties": True}
    else:
        result = {"type": {
            FieldKind.INTEGER: "integer", FieldKind.BOOLEAN: "boolean",
        }.get(spec.kind, "string")}
    if spec.kind == FieldKind.ENUM:
        result["enum"] = list(spec.allowed)
    if spec.kind == FieldKind.UUID:
        result["format"] = "uuid"
    if spec.kind == FieldKind.TIMESTAMP:
        result["description"] = (
            "ISO-8601 timestamp; timezone optional. Original spelling is preserved; "
            "a timestamp without an offset has no SQL instant."
        )
    if spec.kind == FieldKind.SHA256:
        result["pattern"] = "^[0-9a-f]{64}$"
    if spec.minimum is not None:
        result["minimum"] = spec.minimum
    if spec.max_length is not None:
        result["maxLength"] = spec.max_length
    if spec.kind == FieldKind.TEXT:
        result["minLength"] = 1
    return {"anyOf": [result, {"type": "null"}]} if spec.nullable else result


def registry_openapi(
    registry: PayloadSchemaRegistry,
) -> tuple[dict[str, Any], list[Any], list[Any]]:
    """Describe declared fields without weakening runtime cross-field validation."""
    schemas: dict[str, Any] = {}
    sessions: list[Any] = []
    manifests: list[Any] = []
    for name in registry.schema_ids:
        schema = registry.get(name)
        profile = PROFILES[schema.profile]
        tag = name.replace("/", "-")
        session = _object_schema((*CORE_SESSION_FIELDS, *schema.session_extension))
        versions = _object_schema((*CORE_VERSION_FIELDS, *schema.version_extension))
        versions["properties"]["payload_schema"]["const"] = name
        session["properties"]["versions"] = versions
        session["required"].append("versions")
        session["description"] = (
            "Strict registered core and declared extensions. Original canonical JSON is retained. "
            "Legacy insole requests use the separate SessionCreateRequest compatibility boundary."
        )
        schemas[f"RegistrySession-{tag}"] = session
        if name != "raw-segment/1":
            sessions.append({"$ref": f"#/components/schemas/RegistrySession-{tag}"})
        segment = _object_schema((
            FieldSpec("index", FieldKind.INTEGER, minimum=0),
            FieldSpec("sha256", FieldKind.SHA256),
            FieldSpec("size_bytes", FieldKind.INTEGER, minimum=1),
            *profile.manifest_segment_fields,
        ))
        manifest = _object_schema((
            FieldSpec("schema_version", FieldKind.ENUM, allowed=(schema.manifest_schema,),
                      required=not schema.manifest_schema_implied),
            FieldSpec("segment_count", FieldKind.INTEGER, minimum=1),
            FieldSpec("total_bytes", FieldKind.INTEGER, minimum=1),
            *(FieldSpec(total, FieldKind.INTEGER, minimum=1)
              for _, total in profile.manifest_totals),
            *schema.manifest_extension,
        ))
        manifest["properties"]["segments"] = {"type": "array", "minItems": 1, "items": segment}
        manifest["required"].append("segments")
        manifest["description"] = (
            "Registry profile totals, offsets and received metadata must agree."
        )
        schemas[f"RegistryManifest-{tag}"] = manifest
        manifests.append({"$ref": f"#/components/schemas/RegistryManifest-{tag}"})
    return schemas, sessions, manifests
