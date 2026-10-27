"""RAY-833: insole and gait-IMU archive schemas registered as byte-segment."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    GAIT_ARCHIVE_SCHEMA,
    INSOLE_ARCHIVE_SCHEMA,
    FieldKind,
    FieldSpec,
    ManifestRejected,
    PayloadSchema,
    PayloadSchemaMalformed,
    PayloadSchemaRegistry,
    SegmentProfileName,
    SegmentRejected,
    default_payload_schema_registry,
)

VECTORS = Path(__file__).parents[1] / "docs/contracts/payload-schema-vectors.json"


def entry(schema_id):
    fixture = json.loads(VECTORS.read_bytes())
    return next(e for e in fixture["schemas"] if e["schema"] == schema_id)


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def test_default_registry_publishes_the_three_applications():
    assert default_payload_schema_registry().schema_ids == (
        "raw-segment/1",
        "insole-session-archive/1",
        "gait-session-archive/1",
    )
    for schema in (INSOLE_ARCHIVE_SCHEMA, GAIT_ARCHIVE_SCHEMA):
        assert schema.profile is SegmentProfileName.BYTE_SEGMENT
        assert schema.session_extension == ()


def test_insole_vectors_are_the_ray_825_bytes():
    """Frozen from the feet-force-plate interim release (RAY-825, PR #84)."""
    insole = entry("insole-session-archive/1")
    assert [hashlib.sha256(canonical(s["metadata"])).hexdigest() for s in insole["segments"]] == [
        hashlib.sha256(bytes.fromhex(s["canonical_hex"])).hexdigest() for s in insole["segments"]
    ]
    assert insole["segments"][0]["canonical_hex"].startswith("7b227061796c6f61645f736368656d61")
    assert insole["manifest"]["sha256"] == (
        "a00239c69e17e4262097bce598f3aa8423abe7892694ee005231f4efd2071caf"
    )
    assert insole["manifest"]["document"]["segments"][0]["sha256"] == (
        "4728ae55340e30ffe85cbb026082b03178411ae32d7379a6109e5d8934aa7cf9"
    )
    assert insole["manifest"]["document"]["segments"][1]["sha256"] == (
        "4e5deffb2d5f42af69187dff66790751adc142cf3947b6c71e17a2dcd050aca8"
    )


@pytest.mark.parametrize("schema_id", ["insole-session-archive/1", "gait-session-archive/1"])
def test_vector_rejections_name_their_case(schema_id):
    registry = default_payload_schema_registry()
    item = entry(schema_id)
    for case in item["segment_rejections"]:
        with pytest.raises(SegmentRejected):
            registry.validate_segment(schema_id, case["document"])
    for case in item["manifest_rejections"]:
        with pytest.raises(ManifestRejected):
            registry.validate_manifest(schema_id, case["document"])


def test_insole_manifest_requires_quality_and_end():
    registry = default_payload_schema_registry()
    manifest = copy.deepcopy(entry("insole-session-archive/1")["manifest"]["document"])
    assert registry.validate_manifest("insole-session-archive/1", manifest).fields[
        "local_quality_outcome"
    ] == "VALID"
    for missing in ("local_quality_outcome", "ended_at"):
        broken = {k: v for k, v in manifest.items() if k != missing}
        with pytest.raises(ManifestRejected):
            registry.validate_manifest("insole-session-archive/1", broken)


def test_gait_quality_is_optional_and_defaults_to_unknown():
    registry = default_payload_schema_registry()
    manifest = entry("gait-session-archive/1")["manifest"]["document"]
    assert "local_quality_outcome" not in manifest
    validated = registry.validate_manifest("gait-session-archive/1", manifest)
    assert validated.fields["local_quality_outcome"] == "UNKNOWN"
    for outcome in ("VALID", "INVALID", "INCOMPLETE", "FAILED", "UNKNOWN"):
        stated = {**manifest, "local_quality_outcome": outcome, "ended_at": "2026-10-26T01:05:00Z"}
        parsed = registry.validate_manifest("gait-session-archive/1", stated)
        assert parsed.fields["local_quality_outcome"] == outcome


def test_gait_offset_is_optional_but_checked_when_stated():
    registry = default_payload_schema_registry()
    item = entry("gait-session-archive/1")
    segments = [registry.validate_segment("gait-session-archive/1", s["metadata"])
                for s in item["segments"]]
    manifest = registry.validate_manifest("gait-session-archive/1", item["manifest"]["document"])
    registry.verify_received(manifest, segments)

    no_offsets = copy.deepcopy(item["manifest"]["document"])
    for part in no_offsets["segments"]:
        del part["offset"]
    registry.verify_received(
        registry.validate_manifest("gait-session-archive/1", no_offsets), segments
    )

    bare = [
        registry.validate_segment(
            "gait-session-archive/1",
            {k: v for k, v in s["metadata"].items() if k != "offset"},
        )
        for s in item["segments"]
    ]
    registry.verify_received(
        registry.validate_manifest("gait-session-archive/1", no_offsets), bare
    )
    with pytest.raises(ManifestRejected):
        registry.verify_received(manifest, bare)


def test_gait_segment_offset_must_agree_with_the_manifest():
    registry = default_payload_schema_registry()
    item = entry("gait-session-archive/1")
    manifest = registry.validate_manifest("gait-session-archive/1", item["manifest"]["document"])
    moved = copy.deepcopy(item["segments"][1]["metadata"])
    moved["offset"] += 1
    segments = [
        registry.validate_segment("gait-session-archive/1", item["segments"][0]["metadata"]),
        registry.validate_segment("gait-session-archive/1", moved),
    ]
    with pytest.raises(ManifestRejected):
        registry.verify_received(manifest, segments)


def test_frame_fields_do_not_apply_to_byte_schemas():
    registry = default_payload_schema_registry()
    for schema_id in ("insole-session-archive/1", "gait-session-archive/1"):
        item = entry(schema_id)
        for field_name in ("frame_count", "start_frame_index", "compression", "cipher"):
            bad = {**item["segments"][0]["metadata"], field_name: 1}
            with pytest.raises(SegmentRejected):
                registry.validate_segment(schema_id, bad)
        bad_manifest = {**item["manifest"]["document"], "total_frames": 1}
        with pytest.raises(ManifestRejected):
            registry.validate_manifest(schema_id, bad_manifest)


def test_products_are_not_interchangeable():
    registry = default_payload_schema_registry()
    document = entry("gait-session-archive/1")["segments"][0]["metadata"]
    registry.validate_segment("gait-session-archive/1", document, product_id="gait-imu")
    with pytest.raises(Exception, match="not registered for product"):
        registry.validate_segment("gait-session-archive/1", document, product_id="gait-insole")


def test_registered_definitions_are_immutable():
    registry = PayloadSchemaRegistry([GAIT_ARCHIVE_SCHEMA])
    registry.register(GAIT_ARCHIVE_SCHEMA)
    changed = PayloadSchema(
        schema_id=GAIT_ARCHIVE_SCHEMA.schema_id,
        profile=SegmentProfileName.BYTE_SEGMENT,
        manifest_schema=GAIT_ARCHIVE_SCHEMA.manifest_schema,
        allowed_products=GAIT_ARCHIVE_SCHEMA.allowed_products,
    )
    with pytest.raises(Exception, match="already published"):
        registry.register(changed)


def test_field_defaults_and_manifest_equalities_are_validated():
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("x", FieldKind.TEXT, default="a")  # required fields cannot default
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("x", FieldKind.ENUM, required=False, allowed=("a",), default="b")
    with pytest.raises(PayloadSchemaMalformed):
        PayloadSchema(
            schema_id="acme-dump/1",
            profile=SegmentProfileName.BYTE_SEGMENT,
            manifest_schema="acme-manifest/1",
            allowed_products=("acme",),
            manifest_equalities=(("archive_size", "total_bytes"),),
        )
