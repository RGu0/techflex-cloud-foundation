"""Product-neutral payload schema registry and segment profiles (RAY-828).

A *payload schema* (``raw-segment/1``, ``insole-session-archive/1``, ...) is
registered once, together with the segment profile it uses, the extension
fields its application adds on top of the neutral core, the manifest schema
it completes with, and the products allowed to use it.  Validation is driven
entirely by that registered data, so a new schema is a registration and never
a change to this module.

Neutral core
------------
Every segment must carry ``segment_index``, ``size_bytes``, ``sha256`` and
``payload_schema_version``.  Every manifest must carry ``schema_version``,
``segment_count``, ``total_bytes`` and, per segment, ``index``, ``sha256`` and
``size_bytes``.  Anything else is either a *profile* field (the segment
profile's own vocabulary) or an *extension* field declared by the schema;
undeclared fields are refused, never guessed.

Profiles
--------
``frame-segment``
    Sample-frame streams: frame range, monotonic clock span, compression and
    cipher.  Manifest segments also carry ``frame_count`` and the manifest
    ``total_frames``.
``byte-segment``
    Opaque byte ranges (archives, raw IMU captures): the core plus an optional
    ``offset``.

Invariants carried over from the product registry and ingestion plane:

- Unregistered schemas, schemas used by an unlisted product, and segments or
  manifests that disagree with their schema's profile are refused.
- A published schema version is immutable: registering the same identifier
  again with a different definition is refused.
- The registry hosts no business algorithm and decides no VALID/INVALID
  verdict; it only checks structure and the declared integrity of the set.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum
import re
from typing import Any

from .ingestion import PartMetadata
from .manifest import _DIGEST_RE
from .product_registry import ProductCatalog

PAYLOAD_SCHEMA_ID = re.compile(r"[a-z0-9-]+/[1-9][0-9]*")


class PayloadContractError(Exception):
    """Base class for payload schema registry failures."""


class PayloadSchemaUnregistered(PayloadContractError):
    """The schema is not registered; unknown schemas are refused, never guessed."""


class PayloadSchemaConflict(PayloadContractError):
    """A published schema version may not be redefined."""


class PayloadSchemaMalformed(PayloadContractError):
    """A schema definition itself is structurally invalid."""


class SegmentRejected(PayloadContractError):
    """A segment metadata document violates its schema or profile."""


class ManifestRejected(PayloadContractError):
    """A manifest violates its schema, or disagrees with the received segments."""


class SegmentProfileName(StrEnum):
    FRAME_SEGMENT = "frame-segment"
    BYTE_SEGMENT = "byte-segment"


class FieldKind(StrEnum):
    """Closed vocabulary for profile and extension fields."""

    INTEGER = "integer"
    TEXT = "text"
    ENUM = "enum"
    TIMESTAMP = "timestamp"
    SHA256 = "sha256"
    BOOLEAN = "boolean"


@dataclass(frozen=True)
class FieldSpec:
    """One declared field: kind, requiredness, and its bounds."""

    name: str
    kind: FieldKind
    required: bool = True
    minimum: int | None = None
    allowed: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not self.name:
            raise PayloadSchemaMalformed("field name must be non-empty text")
        if not isinstance(self.kind, FieldKind):
            raise PayloadSchemaMalformed(f"field {self.name!r} kind must be a FieldKind")
        if (self.kind is FieldKind.ENUM) != bool(self.allowed):
            raise PayloadSchemaMalformed(
                f"field {self.name!r} must list allowed values exactly when it is an enum"
            )
        if self.minimum is not None and self.kind is not FieldKind.INTEGER:
            raise PayloadSchemaMalformed(f"field {self.name!r}: only integers take a minimum")

    def check(self, value: Any) -> Any:
        """Return ``value`` when it satisfies the spec; raise ``ValueError``."""
        if self.kind is FieldKind.INTEGER:
            if not isinstance(value, int) or isinstance(value, bool):
                raise ValueError(f"{self.name} must be an integer")
            if self.minimum is not None and value < self.minimum:
                raise ValueError(f"{self.name} must be at least {self.minimum}")
        elif self.kind is FieldKind.BOOLEAN:
            if not isinstance(value, bool):
                raise ValueError(f"{self.name} must be a boolean")
        elif self.kind is FieldKind.SHA256:
            if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
                raise ValueError(f"{self.name} must be a complete lowercase hex SHA-256 digest")
        elif self.kind is FieldKind.ENUM:
            if value not in self.allowed:
                raise ValueError(f"{self.name} must be one of {list(self.allowed)}")
        elif self.kind is FieldKind.TIMESTAMP:
            if not isinstance(value, str):
                raise ValueError(f"{self.name} must be an ISO-8601 timestamp")
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError as exc:
                raise ValueError(f"{self.name} must be an ISO-8601 timestamp") from exc
            del parsed
        elif not isinstance(value, str) or not value:
            raise ValueError(f"{self.name} must be non-empty text")
        return value


_INDEX = FieldSpec("segment_index", FieldKind.INTEGER, minimum=0)
_SIZE = FieldSpec("size_bytes", FieldKind.INTEGER, minimum=1)
_SHA = FieldSpec("sha256", FieldKind.SHA256)
_SCHEMA_REF = FieldSpec("payload_schema_version", FieldKind.TEXT)

#: The fields every segment carries, whatever its schema or profile.
CORE_SEGMENT_FIELDS: tuple[FieldSpec, ...] = (_INDEX, _SIZE, _SHA, _SCHEMA_REF)

_MANIFEST_SEGMENT_CORE: tuple[FieldSpec, ...] = (
    FieldSpec("index", FieldKind.INTEGER, minimum=0),
    FieldSpec("sha256", FieldKind.SHA256),
    FieldSpec("size_bytes", FieldKind.INTEGER, minimum=1),
)


@dataclass(frozen=True)
class SegmentProfile:
    """A segment profile: extra fields, ordering rules and summed totals.

    ``increasing_pairs`` lists ``(earlier, later)`` fields where ``later``
    must be strictly greater.  ``manifest_totals`` lists ``(segment field,
    manifest total)`` pairs: the manifest total must equal the sum over its
    segments, and the segment field is required on every manifest segment.
    """

    name: SegmentProfileName
    segment_fields: tuple[FieldSpec, ...] = ()
    manifest_segment_fields: tuple[FieldSpec, ...] = ()
    manifest_totals: tuple[tuple[str, str], ...] = ()
    increasing_pairs: tuple[tuple[str, str], ...] = ()


FRAME_SEGMENT = SegmentProfile(
    name=SegmentProfileName.FRAME_SEGMENT,
    segment_fields=(
        FieldSpec("start_frame_index", FieldKind.INTEGER, minimum=0),
        FieldSpec("frame_count", FieldKind.INTEGER, minimum=1),
        FieldSpec("start_monotonic_ns", FieldKind.INTEGER, minimum=0),
        FieldSpec("end_monotonic_ns", FieldKind.INTEGER, minimum=1),
        FieldSpec("compression", FieldKind.ENUM, allowed=("none", "zstd")),
        FieldSpec("cipher", FieldKind.ENUM, allowed=("aes-256-gcm",)),
    ),
    manifest_segment_fields=(FieldSpec("frame_count", FieldKind.INTEGER, minimum=1),),
    manifest_totals=(("frame_count", "total_frames"),),
    increasing_pairs=(("start_monotonic_ns", "end_monotonic_ns"),),
)

BYTE_SEGMENT = SegmentProfile(
    name=SegmentProfileName.BYTE_SEGMENT,
    segment_fields=(FieldSpec("offset", FieldKind.INTEGER, required=False, minimum=0),),
)

PROFILES: Mapping[SegmentProfileName, SegmentProfile] = {
    SegmentProfileName.FRAME_SEGMENT: FRAME_SEGMENT,
    SegmentProfileName.BYTE_SEGMENT: BYTE_SEGMENT,
}


@dataclass(frozen=True)
class PayloadSchema:
    """One registered payload schema.  Immutable once published."""

    schema_id: str
    profile: SegmentProfileName
    manifest_schema: str
    allowed_products: tuple[str, ...]
    segment_extension: tuple[FieldSpec, ...] = ()
    manifest_extension: tuple[FieldSpec, ...] = ()
    manifest_schema_implied: bool = False

    def __post_init__(self) -> None:
        for label, value in (
            ("schema id", self.schema_id),
            ("manifest schema", self.manifest_schema),
        ):
            if not isinstance(value, str) or not PAYLOAD_SCHEMA_ID.fullmatch(value):
                raise PayloadSchemaMalformed(f"{label} {value!r} must look like 'name/1'")
        if self.schema_id == self.manifest_schema:
            raise PayloadSchemaMalformed("a manifest schema must differ from its payload schema")
        if not isinstance(self.profile, SegmentProfileName):
            raise PayloadSchemaMalformed("profile must be a SegmentProfileName")
        if not self.allowed_products or len(set(self.allowed_products)) != len(
            self.allowed_products
        ):
            raise PayloadSchemaMalformed("allowed_products must be non-empty and unique")
        if any(not isinstance(item, str) or not item for item in self.allowed_products):
            raise PayloadSchemaMalformed("allowed_products entries must be non-empty text")
        profile = PROFILES[self.profile]
        taken = {spec.name for spec in (*CORE_SEGMENT_FIELDS, *profile.segment_fields)}
        _no_overlap(self.segment_extension, taken, "segment extension")
        taken_manifest = {"schema_version", "segment_count", "total_bytes", "segments"} | {
            total for _, total in profile.manifest_totals
        }
        _no_overlap(self.manifest_extension, taken_manifest, "manifest extension")


def _no_overlap(specs: Sequence[FieldSpec], taken: set[str], label: str) -> None:
    names = [spec.name for spec in specs]
    if len(set(names)) != len(names):
        raise PayloadSchemaMalformed(f"{label} field names must be unique")
    clash = sorted(set(names) & taken)
    if clash:
        raise PayloadSchemaMalformed(f"{label} may not redefine core or profile field(s) {clash}")


@dataclass(frozen=True)
class ValidatedSegment:
    """A segment document that satisfies its registered schema."""

    schema_id: str
    profile: SegmentProfileName
    segment_index: int
    size_bytes: int
    sha256: str
    fields: Mapping[str, Any] = field(default_factory=dict)

    def to_part_metadata(self) -> PartMetadata:
        """Bridge to the ingestion plane's per-part declaration."""
        return PartMetadata(
            index=self.segment_index,
            sha256=self.sha256,
            size=self.size_bytes,
            payload_schema=self.schema_id,
        )


@dataclass(frozen=True)
class ValidatedManifest:
    """A manifest document that satisfies its registered schema."""

    payload_schema: str
    manifest_schema: str
    segment_count: int
    total_bytes: int
    segments: tuple[Mapping[str, Any], ...]
    fields: Mapping[str, Any] = field(default_factory=dict)


def _check_fields(
    document: Mapping[str, Any],
    specs: Iterable[FieldSpec],
    *,
    context: str,
    error: type[PayloadContractError],
) -> dict[str, Any]:
    specs = tuple(specs)
    unknown = sorted(set(document) - {spec.name for spec in specs})
    if unknown:
        raise error(f"{context} declares unknown field(s) {unknown}; refused, never guessed")
    values: dict[str, Any] = {}
    for spec in specs:
        if spec.name not in document:
            if spec.required:
                raise error(f"{context} is missing required field {spec.name!r}")
            continue
        try:
            values[spec.name] = spec.check(document[spec.name])
        except ValueError as exc:
            raise error(f"{context}: {exc}") from exc
    return values


class PayloadSchemaRegistry:
    """Registered payload schemas and the checks they drive."""

    def __init__(self, schemas: Iterable[PayloadSchema] = ()) -> None:
        self._schemas: dict[str, PayloadSchema] = {}
        for schema in schemas:
            self.register(schema)

    def register(self, schema: PayloadSchema) -> None:
        """Publish ``schema``.  Re-registering an identical definition is a
        no-op; a different one under the same identifier is refused."""
        if not isinstance(schema, PayloadSchema):
            raise PayloadSchemaMalformed("only a PayloadSchema can be registered")
        existing = self._schemas.get(schema.schema_id)
        if existing is not None:
            if existing != schema:
                raise PayloadSchemaConflict(
                    f"{schema.schema_id!r} is already published with a different definition; "
                    "register a new version instead"
                )
            return
        self._schemas[schema.schema_id] = schema

    @property
    def schema_ids(self) -> tuple[str, ...]:
        return tuple(self._schemas)

    def get(self, schema_id: str) -> PayloadSchema:
        schema = self._schemas.get(schema_id) if isinstance(schema_id, str) else None
        if schema is None:
            raise PayloadSchemaUnregistered(
                f"payload schema {schema_id!r} is not registered; unknown schemas are refused"
            )
        return schema

    def ensure_products_registered(self, catalog: ProductCatalog) -> None:
        """Every product a schema names must exist in the product catalog."""
        known = {product.product_id for product in catalog.products}
        for schema in self._schemas.values():
            missing = sorted(set(schema.allowed_products) - known)
            if missing:
                raise PayloadSchemaMalformed(
                    f"{schema.schema_id!r} names product(s) {missing} absent from the catalog"
                )

    def _authorise(self, schema: PayloadSchema, product_id: str | None) -> None:
        if product_id is not None and product_id not in schema.allowed_products:
            raise PayloadSchemaUnregistered(
                f"payload schema {schema.schema_id!r} is not registered for product "
                f"{product_id!r}"
            )

    def validate_segment(
        self,
        schema_id: str,
        document: Any,
        *,
        product_id: str | None = None,
    ) -> ValidatedSegment:
        """Validate segment metadata declared for ``schema_id``."""
        schema = self.get(schema_id)
        self._authorise(schema, product_id)
        if not isinstance(document, Mapping):
            raise SegmentRejected("segment metadata must be an object")
        profile = PROFILES[schema.profile]
        values = _check_fields(
            document,
            (*CORE_SEGMENT_FIELDS, *profile.segment_fields, *schema.segment_extension),
            context="segment metadata",
            error=SegmentRejected,
        )
        if values["payload_schema_version"] != schema.schema_id:
            raise SegmentRejected(
                f"segment payload_schema_version {values['payload_schema_version']!r} does "
                f"not match session schema {schema.schema_id!r}"
            )
        for earlier, later in profile.increasing_pairs:
            if values[later] <= values[earlier]:
                raise SegmentRejected(f"{later} must follow {earlier}")
        core = {spec.name for spec in CORE_SEGMENT_FIELDS}
        return ValidatedSegment(
            schema_id=schema.schema_id,
            profile=schema.profile,
            segment_index=values["segment_index"],
            size_bytes=values["size_bytes"],
            sha256=values["sha256"],
            fields={k: v for k, v in values.items() if k not in core},
        )

    def validate_manifest(
        self,
        schema_id: str,
        document: Any,
        *,
        product_id: str | None = None,
    ) -> ValidatedManifest:
        """Validate a manifest document for a session pinned to ``schema_id``."""
        schema = self.get(schema_id)
        self._authorise(schema, product_id)
        if not isinstance(document, Mapping):
            raise ManifestRejected("manifest must be an object")
        profile = PROFILES[schema.profile]
        totals = tuple(total for _, total in profile.manifest_totals)
        specs = (
            FieldSpec(
                "schema_version", FieldKind.TEXT, required=not schema.manifest_schema_implied
            ),
            FieldSpec("segment_count", FieldKind.INTEGER, minimum=1),
            FieldSpec("total_bytes", FieldKind.INTEGER, minimum=1),
            *(FieldSpec(total, FieldKind.INTEGER, minimum=1) for total in totals),
            *schema.manifest_extension,
        )
        rest = {k: v for k, v in document.items() if k != "segments"}
        values = _check_fields(rest, specs, context="manifest", error=ManifestRejected)
        declared = values.get("schema_version", schema.manifest_schema)
        if declared != schema.manifest_schema:
            raise ManifestRejected(
                f"manifest schema {declared!r} is not the one paired with "
                f"{schema.schema_id!r} ({schema.manifest_schema!r})"
            )
        segments = document.get("segments")
        if not isinstance(segments, (list, tuple)):
            raise ManifestRejected("manifest segments must be a list")
        item_specs = (*_MANIFEST_SEGMENT_CORE, *profile.manifest_segment_fields)
        items: list[dict[str, Any]] = []
        for position, segment in enumerate(segments):
            if not isinstance(segment, Mapping):
                raise ManifestRejected(f"manifest segments[{position}] must be an object")
            items.append(
                _check_fields(
                    segment,
                    item_specs,
                    context=f"manifest segments[{position}]",
                    error=ManifestRejected,
                )
            )
        if len(items) != values["segment_count"]:
            raise ManifestRejected("segment_count does not match segments")
        if [item["index"] for item in items] != list(range(len(items))):
            raise ManifestRejected("manifest indices must be unique, ordered, and contiguous")
        if sum(item["size_bytes"] for item in items) != values["total_bytes"]:
            raise ManifestRejected("total_bytes does not match segments")
        for segment_field, total in profile.manifest_totals:
            if sum(item[segment_field] for item in items) != values[total]:
                raise ManifestRejected(f"{total} does not match segments")
        core = {"schema_version", "segment_count", "total_bytes"}
        return ValidatedManifest(
            payload_schema=schema.schema_id,
            manifest_schema=schema.manifest_schema,
            segment_count=values["segment_count"],
            total_bytes=values["total_bytes"],
            segments=tuple(items),
            fields={k: v for k, v in values.items() if k not in core},
        )

    def verify_received(
        self, manifest: ValidatedManifest, received: Sequence[ValidatedSegment]
    ) -> None:
        """The manifest must describe exactly the received segments, by index,
        SHA-256 and size (and any profile total carried per segment)."""
        schema = self.get(manifest.payload_schema)
        by_index = {segment.segment_index: segment for segment in received}
        if len(by_index) != len(received):
            raise ManifestRejected("received segments repeat an index")
        if sorted(by_index) != [item["index"] for item in manifest.segments]:
            raise ManifestRejected("manifest segments do not match the received set")
        profile = PROFILES[schema.profile]
        for item in manifest.segments:
            segment = by_index[item["index"]]
            if segment.schema_id != schema.schema_id:
                raise ManifestRejected("a received segment belongs to a different schema")
            if (segment.sha256, segment.size_bytes) != (item["sha256"], item["size_bytes"]):
                raise ManifestRejected(
                    f"segment {item['index']} sha256/size_bytes differs from the manifest"
                )
            for spec in profile.manifest_segment_fields:
                if segment.fields.get(spec.name) != item[spec.name]:
                    raise ManifestRejected(
                        f"segment {item['index']} {spec.name} differs from the manifest"
                    )


#: Product identifier used by the feet-force-plate vectors.
FEET_FORCE_PLATE_PRODUCT = "feet-force-plate"

RAW_SEGMENT_SCHEMA = PayloadSchema(
    schema_id="raw-segment/1",
    profile=SegmentProfileName.FRAME_SEGMENT,
    manifest_schema="session-manifest/1",
    allowed_products=(FEET_FORCE_PLATE_PRODUCT,),
    # The existing service defaults a missing manifest schema_version.
    manifest_schema_implied=True,
    manifest_extension=(
        FieldSpec("ended_at", FieldKind.TIMESTAMP),
        FieldSpec(
            "local_quality_outcome",
            FieldKind.ENUM,
            allowed=("UNKNOWN", "VALID", "INVALID", "INCOMPLETE", "FAILED"),
        ),
    ),
)


def default_payload_schema_registry() -> PayloadSchemaRegistry:
    """The schemas this foundation release publishes: ``raw-segment/1`` only.

    Applications register their own (insole archive, gait IMU, ...) onto a
    registry of their own; nothing here needs to change for them.
    """
    return PayloadSchemaRegistry([RAW_SEGMENT_SCHEMA])
