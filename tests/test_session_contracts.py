"""RAY-829: product-neutral session core and schema-declared session extensions."""

import copy
import hashlib
import json
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    FieldKind,
    FieldSpec,
    PayloadSchema,
    PayloadSchemaMalformed,
    PayloadSchemaRegistry,
    PayloadSchemaUnregistered,
    SegmentProfileName,
    SessionRejected,
    default_payload_schema_registry,
)

VECTORS = Path(__file__).parents[1] / "docs/contracts/session-create-vectors.json"


def canonical(document):
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode()


def load():
    fixture = json.loads(VECTORS.read_bytes())
    assert fixture["vector_schema"] == "techflex-session-create-vectors/1"
    return fixture


def entries():
    return load()["schemas"]


def byte_schema(schema_id, manifest_schema, product):
    # Illustrative registrations: the applications register their own (RAY-833).
    return PayloadSchema(
        schema_id=schema_id,
        profile=SegmentProfileName.BYTE_SEGMENT,
        manifest_schema=manifest_schema,
        allowed_products=(product,),
    )


def registry_with_all():
    registry = default_payload_schema_registry()
    registry.register(byte_schema("insole-session-archive/1", "insole-session-manifest/1",
                                  "gait-insole"))
    registry.register(byte_schema("gait-session-archive/1", "gait-session-manifest/1",
                                  "gait-imu"))
    return registry


@pytest.mark.parametrize("entry", entries(), ids=lambda e: e["schema"])
def test_session_vector_is_valid_and_frozen(entry):
    registry = registry_with_all()
    document = entry["session"]["document"]
    assert canonical(document).hex() == entry["session"]["canonical_hex"]
    assert hashlib.sha256(canonical(document)).hexdigest() == entry["session"]["sha256"]
    session = registry.validate_session(document, product_id=entry["product"])
    schema = registry.get(entry["schema"])
    assert session.schema_id == entry["schema"]
    assert sorted(spec.name for spec in schema.session_extension) == entry["session_extension"]
    assert sorted(spec.name for spec in schema.version_extension) == entry["version_extension"]
    assert [list(pair) for pair in schema.session_equalities] == entry["equalities"]
    assert set(session.extension) == set(entry["session_extension"])
    assert set(session.version_extension) == set(entry["version_extension"])


@pytest.mark.parametrize("entry", entries(), ids=lambda e: e["schema"])
def test_session_rejection_vectors(entry):
    registry = registry_with_all()
    assert entry["session_rejections"]
    for case in entry["session_rejections"]:
        with pytest.raises(SessionRejected):
            registry.validate_session(case["document"], product_id=entry["product"])
    for case in entry["product_rejections"]:
        with pytest.raises(PayloadSchemaUnregistered):
            registry.validate_session(entry["session"]["document"], product_id=case["product_id"])


def test_core_declaration_matches_the_registry():
    core = load()["core"]
    from techflex_cloud_foundation.payload_contracts import (
        CORE_SESSION_FIELDS,
        CORE_VERSION_FIELDS,
    )

    assert [spec.name for spec in CORE_SESSION_FIELDS] + ["versions"] == core["fields"][:5] + [
        "versions"
    ]
    assert sorted(spec.name for spec in CORE_SESSION_FIELDS if spec.required) + ["versions"] == (
        sorted(core["required"])
    )
    assert [spec.name for spec in CORE_SESSION_FIELDS if spec.nullable] == core["nullable"]
    assert [spec.name for spec in CORE_VERSION_FIELDS] == core["versions_fields"]


def test_force_plate_session_keeps_its_existing_fields_and_rules():
    registry = default_payload_schema_registry()
    (entry,) = [e for e in entries() if e["schema"] == "raw-segment/1"]
    document = entry["session"]["document"]
    # the exact SessionCreateRequest field set, with nested versions unchanged
    assert set(document) == {
        "session_id", "subject_uuid", "consent_record_id", "site_id", "terminal_id",
        "client_installation_id", "device_id", "test_protocol", "versions", "started_at",
        "config_snapshot",
    }
    assert set(document["versions"]) == {"app", "protocol_profile", "payload_schema", "calibration"}
    session = registry.validate_session(document, product_id="feet-force-plate")
    assert session.app_version == document["versions"]["app"]
    assert session.extension["subject_uuid"] == document["subject_uuid"]
    assert session.version_extension["calibration"] == document["versions"]["calibration"]
    assert session.config_snapshot == document["config_snapshot"]


def test_site_id_may_be_null_and_config_snapshot_defaults_empty():
    registry = registry_with_all()
    document = copy.deepcopy(
        next(e for e in entries() if e["schema"] == "gait-session-archive/1")["session"]["document"]
    )
    document["site_id"] = None
    del document["config_snapshot"]
    session = registry.validate_session(document)
    assert session.site_id is None
    assert session.config_snapshot == {}


@pytest.mark.parametrize("bad", [None, [], "x", {}, {"versions": []}, {"versions": {}},
                                 {"versions": {"payload_schema": 5}}])
def test_documents_without_a_schema_are_refused(bad):
    with pytest.raises(SessionRejected):
        default_payload_schema_registry().validate_session(bad)


def test_fields_are_checked_against_the_schema_the_document_names():
    registry = registry_with_all()
    document = copy.deepcopy(entries()[0]["session"]["document"])
    document["versions"]["payload_schema"] = "insole-session-archive/1"
    with pytest.raises(SessionRejected):  # force-plate fields are undeclared there
        registry.validate_session(document)


def test_unregistered_schema_is_refused():
    document = copy.deepcopy(entries()[0]["session"]["document"])
    document["versions"]["payload_schema"] = "nobody/1"
    with pytest.raises(PayloadSchemaUnregistered):
        default_payload_schema_registry().validate_session(document)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.update(started_at="yesterday"),
        lambda d: d.update(session_id=5),
        lambda d: d.update(site_id="x"),
        lambda d: d["versions"].update(app=""),
        lambda d: d["versions"].update(app="x" * 65),
        lambda d: d["test_protocol"].update(id="x" * 129),
        lambda d: d["versions"].update(calibration="x" * 129),
        lambda d: d.update(config_snapshot=[]),
        lambda d: d.update(versions="1.0"),
    ],
)
def test_field_kinds_and_bounds_are_enforced(mutate):
    document = copy.deepcopy(entries()[0]["session"]["document"])
    mutate(document)
    with pytest.raises(SessionRejected):
        default_payload_schema_registry().validate_session(document)


def test_a_new_extension_is_registration_only():
    schema = PayloadSchema(
        schema_id="acme-thermal-dump/1",
        profile=SegmentProfileName.BYTE_SEGMENT,
        manifest_schema="acme-thermal-manifest/1",
        allowed_products=("acme-thermal",),
        session_extension=(FieldSpec("rig", FieldKind.ENUM, allowed=("a", "b")),),
        version_extension=(FieldSpec("firmware", FieldKind.TEXT, required=False),),
    )
    registry = PayloadSchemaRegistry([schema])
    base = copy.deepcopy(entries()[1]["session"]["document"])
    base["versions"]["payload_schema"] = schema.schema_id
    with pytest.raises(SessionRejected):  # required extension missing
        registry.validate_session(base)
    base["rig"] = "a"
    assert registry.validate_session(base).extension == {"rig": "a"}
    base["versions"]["firmware"] = "7"
    assert registry.validate_session(base).version_extension == {"firmware": "7"}
    base["rig"] = "z"
    with pytest.raises(SessionRejected):
        registry.validate_session(base)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"session_extension": (FieldSpec("session_id", FieldKind.UUID),)},
        {"session_extension": (FieldSpec("versions", FieldKind.TEXT),)},
        {"session_extension": (FieldSpec("config_snapshot", FieldKind.TEXT),)},
        {"session_extension": (FieldSpec("a", FieldKind.TEXT), FieldSpec("a", FieldKind.TEXT))},
        {"version_extension": (FieldSpec("app", FieldKind.TEXT),)},
        {"version_extension": (FieldSpec("payload_schema", FieldKind.TEXT),)},
        {"session_equalities": (("nope", "session_id"),)},
        {"session_equalities": (("session_id", "session_id"),)},
        {"session_equalities": (("session_id", "config_snapshot"),)},
    ],
)
def test_malformed_session_declarations_are_refused(kwargs):
    base = {
        "schema_id": "acme-x/1",
        "profile": SegmentProfileName.BYTE_SEGMENT,
        "manifest_schema": "acme-x-manifest/1",
        "allowed_products": ("acme",),
    }
    with pytest.raises(PayloadSchemaMalformed):
        PayloadSchema(**{**base, **kwargs})


def test_object_and_text_declarations_are_validated():
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("o", FieldKind.OBJECT)
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("o", FieldKind.TEXT, fields=(FieldSpec("x", FieldKind.TEXT),))
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("o", FieldKind.OBJECT, fields=(FieldSpec("x", FieldKind.TEXT),) * 2)
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("t", FieldKind.INTEGER, max_length=3)
    with pytest.raises(PayloadSchemaMalformed):
        FieldSpec("t", FieldKind.TEXT, max_length=0)


def test_raw_segment_registration_still_publishes_its_segment_and_manifest_vectors():
    # RAY-828 vectors are untouched by the session extension.
    registry = default_payload_schema_registry()
    assert registry.get("raw-segment/1").manifest_schema == "session-manifest/1"


def test_equal_uuids_spelled_differently_are_equal_and_returned_canonical():
    registry = default_payload_schema_registry()
    document = copy.deepcopy(entries()[0]["session"]["document"])
    installation = document["client_installation_id"]
    document["terminal_id"] = installation.upper().replace("-", "")
    session = registry.validate_session(document)
    assert session.extension["terminal_id"] == installation
    assert session.client_installation_id == installation


@pytest.mark.parametrize("bad", [True, 7, None, ["x"]])
def test_non_text_uuids_are_refused(bad):
    document = copy.deepcopy(entries()[0]["session"]["document"])
    document["subject_uuid"] = bad
    with pytest.raises(SessionRejected):
        default_payload_schema_registry().validate_session(document)


def test_config_snapshot_is_copied():
    document = copy.deepcopy(entries()[0]["session"]["document"])
    session = default_payload_schema_registry().validate_session(document)
    document["config_snapshot"]["sample_rate_hz"] = 1
    assert session.config_snapshot["sample_rate_hz"] == 100
