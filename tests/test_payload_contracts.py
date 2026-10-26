"""RAY-828: product-neutral payload schema registry and segment profiles."""

import base64
import copy
import hashlib
import json
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    FieldKind,
    FieldSpec,
    ManifestRejected,
    PartMetadata,
    PayloadSchema,
    PayloadSchemaConflict,
    PayloadSchemaMalformed,
    PayloadSchemaRegistry,
    PayloadSchemaUnregistered,
    ProductCatalog,
    ProductRecord,
    SegmentProfileName,
    SegmentRejected,
    default_payload_schema_registry,
)

VECTORS = Path(__file__).parents[1] / "docs/contracts/payload-schema-vectors.json"


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def load():
    fixture = json.loads(VECTORS.read_bytes())
    assert fixture["vector_schema"] == "techflex-payload-schema-vectors/1"
    return fixture


def vectors():
    return load()["schemas"]


def _apply(registry, entry, received=None):
    schema_id = entry["schema"]
    segs = [registry.validate_segment(schema_id, s["metadata"]) for s in entry["segments"]]
    manifest = registry.validate_manifest(schema_id, entry["manifest"]["document"])
    registry.verify_received(manifest, segs if received is None else received(segs))
    return segs, manifest


@pytest.mark.parametrize("entry", vectors(), ids=lambda e: e["schema"])
def test_frozen_vectors_hold_for_every_registered_schema(entry):
    registry = default_payload_schema_registry()
    assert entry["schema"] in registry.schema_ids
    assert registry.get(entry["schema"]).profile.value == entry["profile"]
    for item in entry["segments"]:
        payload = base64.b64decode(item["payload_base64"])
        assert canonical(item["metadata"]).hex() == item["canonical_hex"]
        assert hashlib.sha256(payload).hexdigest() == item["metadata"]["sha256"]
        assert len(payload) == item["metadata"]["size_bytes"]
    segs, manifest = _apply(registry, entry)
    assert canonical(entry["manifest"]["document"]).hex() == entry["manifest"]["canonical_hex"]
    assert hashlib.sha256(canonical(entry["manifest"]["document"])).hexdigest() == (
        entry["manifest"]["sha256"]
    )
    assert segs[0].to_part_metadata() == PartMetadata(
        index=0,
        sha256=entry["segments"][0]["metadata"]["sha256"],
        size=entry["segments"][0]["metadata"]["size_bytes"],
        payload_schema=entry["schema"],
    )
    assert manifest.total_bytes == sum(s.size_bytes for s in segs)


def test_raw_segment_vector_is_the_force_plate_vector_byte_for_byte():
    """The pre-existing mobile vector, frozen from feet-force-plate."""
    (entry,) = vectors()
    segment = entry["segment"]
    assert segment["canonical_hex"] == (
        "7b22636970686572223a226165732d3235362d67636d222c22636f6d7072657373696f6e223a226e6f6e65222c"
        "22656e645f6d6f6e6f746f6e69635f6e73223a3230302c226672616d655f636f756e74223a312c227061796c6f"
        "61645f736368656d615f76657273696f6e223a227261772d7365676d656e742f31222c227365676d656e745f69"
        "6e646578223a302c22736861323536223a22616461663730333966616433346630336665356231613138633163"
        "32353131313538366139383066373838653532343638366230393964383864653266626463222c2273697a655f"
        "6279746573223a32352c2273746172745f6672616d655f696e646578223a302c2273746172745f6d6f6e6f746f"
        "6e69635f6e73223a3130307d"
    )
    assert canonical(segment["metadata"]).hex() == segment["canonical_hex"]
    assert segment["sha256"] == "adaf7039fad34f03fe5b1a18c1c25111586a980f788e524686b099d88de2fbdc"
    header = base64.urlsafe_b64encode(canonical(segment["metadata"])).rstrip(b"=").decode()
    assert header == segment["metadata_header"]
    assert segment["metadata"]["payload_schema_version"] == "raw-segment/1"


@pytest.mark.parametrize("entry", vectors(), ids=lambda e: e["schema"])
def test_segment_rejection_vectors(entry):
    registry = default_payload_schema_registry()
    for case in entry["segment_rejections"]:
        with pytest.raises(SegmentRejected):
            registry.validate_segment(entry["schema"], case["document"])


@pytest.mark.parametrize("entry", vectors(), ids=lambda e: e["schema"])
def test_manifest_rejection_vectors(entry):
    registry = default_payload_schema_registry()
    for case in entry["manifest_rejections"]:
        with pytest.raises(ManifestRejected):
            registry.validate_manifest(entry["schema"], case["document"])


@pytest.mark.parametrize("entry", vectors(), ids=lambda e: e["schema"])
def test_set_and_product_rejection_vectors(entry):
    registry = default_payload_schema_registry()
    differs, unreceived = entry["set_rejections"]
    document = copy.deepcopy(entry["manifest"]["document"])
    document["segments"][differs["segment_index"]]["sha256"] = differs["manifest_segment_sha256"]
    segs = [registry.validate_segment(entry["schema"], s["metadata"]) for s in entry["segments"]]
    with pytest.raises(ManifestRejected):
        registry.verify_received(registry.validate_manifest(entry["schema"], document), segs)
    manifest = registry.validate_manifest(entry["schema"], entry["manifest"]["document"])
    kept = [s for s in segs if s.segment_index != unreceived["drop_received_index"]]
    with pytest.raises(ManifestRejected):
        registry.verify_received(manifest, kept)
    with pytest.raises(PayloadSchemaUnregistered):
        registry.validate_segment(
            entry["schema"],
            entry["segments"][0]["metadata"],
            product_id=entry["product_rejections"][0]["product_id"],
        )
    registry.validate_segment(
        entry["schema"], entry["segments"][0]["metadata"], product_id="feet-force-plate"
    )


def test_unregistered_schema_is_refused():
    registry = default_payload_schema_registry()
    for bad in ("insole-session-archive/1", "raw-segment/2", "", None):
        with pytest.raises(PayloadSchemaUnregistered):
            registry.validate_segment(bad, {})
        with pytest.raises(PayloadSchemaUnregistered):
            registry.validate_manifest(bad, {})


# --- a fictional schema proves registration, not core changes, adds a schema ---

SHA_A = hashlib.sha256(b"aaaa").hexdigest()
SHA_B = hashlib.sha256(b"bbbbbb").hexdigest()

FICTIONAL = PayloadSchema(
    schema_id="acme-thermal-dump/1",
    profile=SegmentProfileName.BYTE_SEGMENT,
    manifest_schema="acme-thermal-manifest/1",
    allowed_products=("acme-thermal",),
    segment_extension=(FieldSpec("sensor_bank", FieldKind.ENUM, allowed=("a", "b")),),
    manifest_extension=(FieldSpec("captured_at", FieldKind.TIMESTAMP),),
)


def fictional_segments():
    return [
        {"segment_index": 0, "size_bytes": 4, "sha256": SHA_A, "sensor_bank": "a",
         "payload_schema_version": "acme-thermal-dump/1"},
        {"segment_index": 1, "size_bytes": 6, "sha256": SHA_B, "sensor_bank": "b", "offset": 4,
         "payload_schema_version": "acme-thermal-dump/1"},
    ]


def fictional_manifest():
    return {
        "schema_version": "acme-thermal-manifest/1",
        "segment_count": 2,
        "total_bytes": 10,
        "captured_at": "2026-10-25T00:00:00+00:00",
        "segments": [
            {"index": 0, "sha256": SHA_A, "size_bytes": 4},
            {"index": 1, "sha256": SHA_B, "size_bytes": 6},
        ],
    }


def test_a_new_schema_is_registration_only():
    registry = default_payload_schema_registry()
    registry.register(FICTIONAL)
    segs = [registry.validate_segment(FICTIONAL.schema_id, s, product_id="acme-thermal")
            for s in fictional_segments()]
    assert segs[1].fields == {"sensor_bank": "b", "offset": 4}
    manifest = registry.validate_manifest(FICTIONAL.schema_id, fictional_manifest())
    registry.verify_received(manifest, segs)
    assert manifest.fields == {"captured_at": "2026-10-25T00:00:00+00:00"}


@pytest.mark.parametrize(
    "mutate",
    [
        lambda s: s.update(sensor_bank="c"),
        lambda s: s.pop("sensor_bank"),
        lambda s: s.update(unknown=1),
        lambda s: s.update(frame_count=1),  # a frame-segment field on a byte-segment schema
        lambda s: s.update(offset=-1),
        lambda s: s.update(offset=True),
        lambda s: s.update(size_bytes=0),
        lambda s: s.update(payload_schema_version="raw-segment/1"),
    ],
)
def test_byte_segment_profile_mismatches_are_refused(mutate):
    registry = PayloadSchemaRegistry([FICTIONAL])
    segment = fictional_segments()[0]
    mutate(segment)
    with pytest.raises(SegmentRejected):
        registry.validate_segment(FICTIONAL.schema_id, segment)


def test_byte_segment_offset_is_optional():
    registry = PayloadSchemaRegistry([FICTIONAL])
    segment = registry.validate_segment(FICTIONAL.schema_id, fictional_segments()[0])
    assert "offset" not in segment.fields


def test_manifest_extension_and_totals_are_checked():
    registry = PayloadSchemaRegistry([FICTIONAL])
    for mutate in (
        lambda m: m.update(total_bytes=11),
        lambda m: m.update(segment_count=1),
        lambda m: m.pop("captured_at"),
        lambda m: m.update(captured_at="yesterday"),
        lambda m: m.update(total_frames=2),
        lambda m: m.update(schema_version="session-manifest/1"),
        lambda m: m["segments"][0].update(frame_count=1),
        lambda m: m["segments"].reverse(),
    ):
        manifest = fictional_manifest()
        mutate(manifest)
        with pytest.raises(ManifestRejected):
            registry.validate_manifest(FICTIONAL.schema_id, manifest)


def test_profile_mismatch_between_segment_sets_is_refused():
    registry = default_payload_schema_registry()
    registry.register(FICTIONAL)
    with pytest.raises(SegmentRejected):
        # byte-profile segment offered under the frame-segment schema
        registry.validate_segment("raw-segment/1", fictional_segments()[0])


def test_published_schema_versions_are_immutable():
    registry = PayloadSchemaRegistry([FICTIONAL])
    registry.register(FICTIONAL)  # identical re-registration is a no-op
    changed = PayloadSchema(
        schema_id=FICTIONAL.schema_id,
        profile=SegmentProfileName.FRAME_SEGMENT,
        manifest_schema=FICTIONAL.manifest_schema,
        allowed_products=FICTIONAL.allowed_products,
    )
    with pytest.raises(PayloadSchemaConflict):
        registry.register(changed)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"schema_id": "Bad/1"},
        {"schema_id": "x/0"},
        {"manifest_schema": "acme-x/1"},
        {"allowed_products": ()},
        {"allowed_products": ("a", "a")},
        {"segment_extension": (FieldSpec("sha256", FieldKind.TEXT),)},
        {"manifest_extension": (FieldSpec("total_bytes", FieldKind.INTEGER),)},
        {"segment_extension": (FieldSpec("offset", FieldKind.INTEGER),)},
    ],
)
def test_malformed_schema_definitions_are_refused(kwargs):
    base = {
        "schema_id": "acme-x/1",
        "profile": SegmentProfileName.BYTE_SEGMENT,
        "manifest_schema": "acme-x-manifest/1",
        "allowed_products": ("acme",),
    }
    with pytest.raises(PayloadSchemaMalformed):
        PayloadSchema(**{**base, **kwargs})


def test_field_spec_declarations_are_validated():
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("kind", FieldKind.ENUM)
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("kind", FieldKind.TEXT, allowed=("a",))
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("n", FieldKind.TEXT, minimum=1)


def test_products_must_exist_in_the_product_catalog():
    registry = default_payload_schema_registry()
    registry.register(FICTIONAL)
    catalog = ProductCatalog(
        products=(ProductRecord(product_id="feet-force-plate", supported_schema_versions=("1",)),)
    )
    with pytest.raises(PayloadSchemaMalformed):
        registry.ensure_products_registered(catalog)
    registry_ok = default_payload_schema_registry()
    registry_ok.ensure_products_registered(catalog)


def test_non_object_documents_are_refused():
    registry = default_payload_schema_registry()
    with pytest.raises(SegmentRejected):
        registry.validate_segment("raw-segment/1", [])
    with pytest.raises(ManifestRejected):
        registry.validate_manifest("raw-segment/1", [])
    manifest = copy.deepcopy(vectors()[0]["manifest"]["document"])
    manifest["segments"][0] = 5
    with pytest.raises(ManifestRejected):
        registry.validate_manifest("raw-segment/1", manifest)
    manifest["segments"] = "x"
    with pytest.raises(ManifestRejected):
        registry.validate_manifest("raw-segment/1", manifest)


def test_raw_segment_manifest_may_omit_its_implied_schema_version():
    registry = default_payload_schema_registry()
    document = copy.deepcopy(vectors()[0]["manifest"]["document"])
    del document["schema_version"]
    assert registry.validate_manifest("raw-segment/1", document).manifest_schema == (
        "session-manifest/1"
    )
    # a schema that does not imply its manifest schema still requires it
    manifest = fictional_manifest()
    del manifest["schema_version"]
    with pytest.raises(ManifestRejected):
        PayloadSchemaRegistry([FICTIONAL]).validate_manifest(FICTIONAL.schema_id, manifest)


def test_frozen_segment_block_is_self_consistent():
    (entry,) = vectors()
    segment = entry["segment"]
    assert hashlib.sha256(base64.b64decode(segment["payload_base64"])).hexdigest() == (
        segment["sha256"]
    )
    assert entry["segments"][0]["metadata"] == segment["metadata"]
    assert entry["segments"][0]["payload_base64"] == segment["payload_base64"]
