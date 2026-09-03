"""Contract tests for the content-addressed artifact manifest (F-27)."""

from __future__ import annotations

import hashlib
import json

import pytest

from techflex_cloud_foundation import (
    ArtifactEntry,
    ArtifactManifest,
    ArtifactPart,
    ManifestIntegrityError,
    ManifestMalformed,
    ManifestVersionUnsupported,
    ParentReference,
    verify_entry_payload,
)

PAYLOAD = b"force plate samples" * 100
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


def _manifest(**overrides: object) -> ArtifactManifest:
    kwargs: dict[str, object] = {
        "artifact_kind": "test/artifact",
        "entries": (ArtifactEntry(path="data.bin", size=len(PAYLOAD), sha256=DIGEST),),
    }
    kwargs.update(overrides)
    return ArtifactManifest(**kwargs)  # type: ignore[arg-type]


def test_canonical_bytes_are_reproducible() -> None:
    a = _manifest(annotations={"b": "2", "a": "1"})
    b = _manifest(annotations={"a": "1", "b": "2"})

    assert a.to_canonical_bytes() == b.to_canonical_bytes()
    assert a.digest() == b.digest()
    assert len(a.digest()) == 64


def test_roundtrip_preserves_all_fields() -> None:
    manifest = _manifest(
        codec_version=3,
        parent=ParentReference(digest=DIGEST, relationship="derived-from"),
        annotations={"origin": "test"},
        entries=(
            ArtifactEntry(
                path="data.bin",
                size=len(PAYLOAD),
                sha256=DIGEST,
                codec="raw",
                parts=(
                    ArtifactPart(
                        index=0, offset=0, size=100,
                        sha256=hashlib.sha256(PAYLOAD[:100]).hexdigest(),
                    ),
                ),
            ),
        ),
    )

    parsed = ArtifactManifest.from_bytes(manifest.to_canonical_bytes())

    assert parsed == manifest


def test_short_digest_prefix_is_refused() -> None:
    with pytest.raises(ManifestMalformed, match="complete"):
        _manifest(
            entries=(ArtifactEntry(path="x", size=1, sha256=DIGEST[:32]),)
        )


def test_unknown_versions_are_refused_not_guessed() -> None:
    with pytest.raises(ManifestVersionUnsupported):
        _manifest(format_version=99)
    with pytest.raises(ManifestVersionUnsupported):
        _manifest(schema_version=2)
    document = json.loads(_manifest().to_canonical_bytes())
    document["format_version"] = 99
    with pytest.raises(ManifestVersionUnsupported):
        ArtifactManifest.from_bytes(json.dumps(document).encode())


def test_malformed_payloads_are_refused() -> None:
    with pytest.raises(ManifestMalformed):
        ArtifactManifest.from_bytes(b"not json")
    with pytest.raises(ManifestMalformed, match="missing field"):
        ArtifactManifest.from_bytes(b'{"format_version": 1}')


def test_unsafe_or_duplicate_paths_are_refused() -> None:
    with pytest.raises(ManifestMalformed):
        _manifest(entries=(ArtifactEntry(path="../escape", size=1, sha256=DIGEST),))
    with pytest.raises(ManifestMalformed):
        _manifest(
            entries=(
                ArtifactEntry(path="same", size=1, sha256=DIGEST),
                ArtifactEntry(path="same", size=1, sha256=DIGEST),
            )
        )


def test_part_must_stay_inside_entry() -> None:
    with pytest.raises(ManifestMalformed, match="beyond"):
        _manifest(
            entries=(
                ArtifactEntry(
                    path="data.bin",
                    size=10,
                    sha256=DIGEST,
                    parts=(ArtifactPart(index=0, offset=5, size=10, sha256=DIGEST),),
                ),
            )
        )


def test_verify_entry_payload_accepts_matching_bytes() -> None:
    entry = ArtifactEntry(path="data.bin", size=len(PAYLOAD), sha256=DIGEST)

    verify_entry_payload(entry, [PAYLOAD[:100], PAYLOAD[100:]])


def test_verify_entry_payload_rejects_size_and_digest_mismatch() -> None:
    entry = ArtifactEntry(path="data.bin", size=len(PAYLOAD), sha256=DIGEST)

    with pytest.raises(ManifestIntegrityError, match="size"):
        verify_entry_payload(entry, [PAYLOAD[:-1]])
    with pytest.raises(ManifestIntegrityError, match="digest"):
        verify_entry_payload(entry, [b"x" * len(PAYLOAD)])
