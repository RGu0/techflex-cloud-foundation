"""RAY-556: frozen, language-neutral inputs exercise existing public contracts."""

from datetime import datetime
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from uuid import UUID

import pytest
from test_ingestion_content import NOW, finish, opened
from test_wheel_consumer import _uv

from techflex_cloud_foundation import (
    ArtifactManifest,
    ArtifactReceipt,
    ErrorEnvelope,
    GatewayMalformed,
    IngestionConflict,
    IngestionMalformed,
    InMemoryObjectStore,
    LicenseDocument,
    LicenseKeyset,
    LicenseLifecycleState,
    LicenseSignatureInvalid,
    LicenseSigningKeyUnknown,
    ManifestMalformed,
    ResumeDriver,
    SignedLicenseDocument,
)

CONTRACTS = Path(__file__).parents[1] / "docs/contracts"


def load_vector(name):
    path = CONTRACTS / name
    assert path.is_file(), f"missing portable contract fixture: {name}"
    return json.loads(path.read_bytes())


def test_error_envelope_frozen_wire_and_rejected_inputs():
    fixture = load_vector("error-envelope-vectors.json")
    for case in fixture["positive_cases"]:
        assert ErrorEnvelope(**case["input"]).to_document() == case["expected_document"]
    errors = {"GatewayMalformed": GatewayMalformed, "ManifestMalformed": ManifestMalformed}
    for case in fixture["negative_cases"]:
        with pytest.raises(errors[case["expected_error"]]):
            ErrorEnvelope(**case["input"])


@pytest.mark.parametrize("case_id", ["valid", "tampered-document", "unknown-key", "revoked-key"])
def test_license_public_key_verifies_frozen_signed_document(case_id):
    fixture = load_vector("license-document-vectors.json")
    case = next(case for case in fixture["cases"] if case["case"] == case_id)
    signed_values = case["signed"]
    values = dict(signed_values["document"])
    for field in ("license_id", "tenant_id", "account_id"):
        values[field] = UUID(values[field]) if values[field] else None
    for field in ("issued_at", "valid_from", "valid_until"):
        values[field] = datetime.fromisoformat(values[field]) if values[field] else None
    values["state"] = LicenseLifecycleState(values["state"])
    values["features"] = frozenset(values["features"])
    document = LicenseDocument(**values)
    canonical = document.canonical_bytes()
    assert canonical.hex() == case["canonical_hex"]
    assert hashlib.sha256(canonical).hexdigest() == case["sha256"]
    signed = SignedLicenseDocument(
        document=document,
        **{name: signed_values[name] for name in ("key_id", "signature", "keyset_revision")},
    )
    keyset_values = case["keyset"]
    keyset = LicenseKeyset(
        revision=keyset_values["revision"],
        active_key_id=keyset_values["active_key_id"],
        public_keys={
            key: bytes.fromhex(value) for key, value in keyset_values["public_keys_hex"].items()
        },
        revoked_key_ids=tuple(keyset_values["revoked_key_ids"]),
    )
    if case["expected"] == "verified":
        assert keyset.verify(signed) is document
    else:
        errors = {
            "LicenseSignatureInvalid": LicenseSignatureInvalid,
            "LicenseSigningKeyUnknown": LicenseSigningKeyUnknown,
        }
        with pytest.raises(errors[case["expected"]]):
            keyset.verify(signed)


@pytest.mark.anyio
@pytest.mark.parametrize("case_id", [
    "swap-global-slots-0-2", "all-parts-valid-entry-sha-wrong",
    "mapping-future-version", "legacy-multipart-unmarked",
])
async def test_ingestion_negative_vectors_execute_complete_inputs(case_id):
    fixture = load_vector("ingestion-content-vectors.json")
    case = next(case for case in fixture["negative_cases"] if case["case"] == case_id)
    assert "manifest" in case and "slots" in case, "negative vector needs complete inputs"
    document = ArtifactManifest.from_bytes(json.dumps(case["manifest"]).encode())
    slots = case["slots"]
    assert [slot["global_index"] for slot in slots] == list(range(len(slots)))
    payloads = [bytes.fromhex(slot["payload_hex"]) for slot in slots]
    for slot, payload in zip(slots, payloads, strict=True):
        assert len(payload) == slot["size"]
        assert hashlib.sha256(payload).hexdigest() == slot["sha256"]
    objects = InMemoryObjectStore()
    service, _, principal, sid = await opened(objects, payloads)
    errors = {"content-conflict": IngestionConflict, "malformed": IngestionMalformed}
    error = errors[case["expected"]]
    with pytest.raises(error):
        await finish(service, principal, sid, document)
    assert (await service.status(principal, sid, now=NOW)).receipt is None
    assert objects.object_count == len(slots)


@pytest.mark.anyio
async def test_ingestion_positive_documents_match_frozen_canonical_bytes():
    fixture = load_vector("ingestion-content-vectors.json")
    document = ArtifactManifest.from_bytes(json.dumps(fixture["manifest"]).encode())
    assert document.to_canonical_bytes().hex() == fixture["manifest_canonical_hex"]
    assert document.digest() == fixture["manifest_sha256"]
    service, _, principal, sid = await opened(
        InMemoryObjectStore(), [bytes.fromhex(slot["payload_hex"]) for slot in fixture["slots"]]
    )
    actual = await finish(service, principal, sid, document)
    assert actual.verification_version == "content/1"
    assert ResumeDriver.may_retire_local(actual, document)
    for case in fixture["receipts"]:
        values = dict(case["document"])
        values["session_id"] = UUID(values["session_id"])
        values["completed_at"] = datetime.fromisoformat(values["completed_at"])
        receipt = ArtifactReceipt(**values)
        assert receipt.canonical_bytes().hex() == case["canonical_hex"]
        assert receipt.digest() == case["sha256"]
        assert ResumeDriver.may_retire_local(receipt, document) is case["may_retire_local"]


@pytest.mark.anyio
async def test_built_sdist_vectors_are_identical_and_public_api_consumable(tmp_path, monkeypatch):
    """Detect packaging omissions and execute bytes from the actual sdist."""
    subprocess.run(
        [_uv(), "build", "--sdist", "--out-dir", str(tmp_path / "dist")],
        cwd=CONTRACTS.parents[1], check=True, capture_output=True, text=True,
    )
    sdist = next((tmp_path / "dist").glob("*.tar.gz"))
    unpacked = tmp_path / "contracts"
    unpacked.mkdir()
    with tarfile.open(sdist) as archive:
        root = archive.getnames()[0].split("/")[0]
        for name in ("error-envelope-vectors.json", "license-document-vectors.json",
                     "ingestion-content-vectors.json"):
            member = archive.extractfile(f"{root}/docs/contracts/{name}")
            assert member is not None
            data = member.read()
            assert data == (CONTRACTS / name).read_bytes()
            (unpacked / name).write_bytes(data)
    monkeypatch.setattr(sys.modules[__name__], "CONTRACTS", unpacked)
    test_error_envelope_frozen_wire_and_rejected_inputs()
    for case in ("valid", "tampered-document", "unknown-key", "revoked-key"):
        test_license_public_key_verifies_frozen_signed_document(case)
    await test_ingestion_positive_documents_match_frozen_canonical_bytes()
    for case in ("swap-global-slots-0-2", "all-parts-valid-entry-sha-wrong",
                 "mapping-future-version", "legacy-multipart-unmarked"):
        await test_ingestion_negative_vectors_execute_complete_inputs(case)


@pytest.fixture
def anyio_backend():
    return "asyncio"
