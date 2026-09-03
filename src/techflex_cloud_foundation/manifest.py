"""Content-addressed artifact manifests (PRD F-27).

An artifact manifest describes a payload as a flat list of entries with
full-length digests, sizes, and optional parts, plus the format/schema/codec
versions needed to interpret it.  The manifest's canonical byte form is
reproducible: two constructions of the same manifest serialize to the same
bytes, and the manifest digest commits to every byte.

Invariants carried over from the reference implementations:

- Manifest bytes are reproducible (canonical serialization).
- Security integrity always uses complete digests; a short prefix is never
  accepted as a digest.
- Unknown versions are refused, never guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import re
from typing import Any, Iterable

SUPPORTED_FORMAT_VERSION = 1
SUPPORTED_SCHEMA_VERSION = 1

_DIGEST_RE = re.compile(r"[0-9a-f]{64}")


class ManifestError(Exception):
    """Base class for manifest failures."""


class ManifestMalformed(ManifestError):
    """The serialized form or a field value is structurally invalid."""


class ManifestVersionUnsupported(ManifestError):
    """The manifest declares a format or schema version this build refuses."""


class ManifestIntegrityError(ManifestError):
    """Payload bytes do not match the size or digest the manifest commits to."""


def _require_digest(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not _DIGEST_RE.fullmatch(value):
        raise ManifestMalformed(
            f"{field_name} must be a complete lowercase hex SHA-256 digest; "
            "short prefixes never carry security integrity"
        )
    return value


def _require_non_negative(value: int, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ManifestMalformed(f"{field_name} must be a non-negative integer")
    return value


def _require_text(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ManifestMalformed(f"{field_name} must be non-empty text")
    return value


@dataclass(frozen=True)
class ArtifactPart:
    """One byte range of an entry, digest-addressed for resumable transfer."""

    index: int
    offset: int
    size: int
    sha256: str

    def __post_init__(self) -> None:
        _require_non_negative(self.index, field_name="part index")
        _require_non_negative(self.offset, field_name="part offset")
        _require_non_negative(self.size, field_name="part size")
        _require_digest(self.sha256, field_name="part sha256")


@dataclass(frozen=True)
class ArtifactEntry:
    """One named payload member with its complete digest and optional parts."""

    path: str
    size: int
    sha256: str
    codec: str | None = None
    parts: tuple[ArtifactPart, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.path, field_name="entry path")
        if "\\" in self.path or self.path.startswith("/") or ".." in self.path.split("/"):
            raise ManifestMalformed(f"entry path must be relative and contained: {self.path!r}")
        _require_non_negative(self.size, field_name="entry size")
        _require_digest(self.sha256, field_name="entry sha256")
        if self.codec is not None:
            _require_text(self.codec, field_name="entry codec")
        offsets = sorted((part.offset for part in self.parts))
        if offsets != [part.offset for part in self.parts]:
            raise ManifestMalformed("entry parts must be ordered by offset")
        for part in self.parts:
            if part.offset + part.size > self.size:
                raise ManifestMalformed("entry part extends beyond the entry size")


@dataclass(frozen=True)
class ParentReference:
    """Link to the manifest this artifact derives from."""

    digest: str
    relationship: str

    def __post_init__(self) -> None:
        _require_digest(self.digest, field_name="parent digest")
        _require_text(self.relationship, field_name="parent relationship")


@dataclass(frozen=True)
class ArtifactManifest:
    """Versioned, content-addressed description of one artifact payload."""

    entries: tuple[ArtifactEntry, ...]
    artifact_kind: str
    format_version: int = SUPPORTED_FORMAT_VERSION
    schema_version: int = SUPPORTED_SCHEMA_VERSION
    codec_version: int = 1
    parent: ParentReference | None = None
    annotations: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.format_version != SUPPORTED_FORMAT_VERSION:
            raise ManifestVersionUnsupported(
                f"unsupported manifest format version: {self.format_version!r}"
            )
        if self.schema_version != SUPPORTED_SCHEMA_VERSION:
            raise ManifestVersionUnsupported(
                f"unsupported manifest schema version: {self.schema_version!r}"
            )
        if not isinstance(self.codec_version, int) or self.codec_version < 1:
            raise ManifestMalformed("codec_version must be a positive integer")
        _require_text(self.artifact_kind, field_name="artifact_kind")
        paths = [entry.path for entry in self.entries]
        if len(set(paths)) != len(paths):
            raise ManifestMalformed("entry paths must be unique")
        for key, value in self.annotations.items():
            _require_text(key, field_name="annotation key")
            _require_text(value, field_name="annotation value")

    def to_canonical_bytes(self) -> bytes:
        """Serialize reproducibly: sorted keys, tight separators, entry order preserved."""
        document: dict[str, Any] = {
            "format_version": self.format_version,
            "schema_version": self.schema_version,
            "codec_version": self.codec_version,
            "artifact_kind": self.artifact_kind,
            "annotations": dict(sorted(self.annotations.items())),
            "parent": (
                {"digest": self.parent.digest, "relationship": self.parent.relationship}
                if self.parent
                else None
            ),
            "entries": [
                {
                    "path": entry.path,
                    "size": entry.size,
                    "sha256": entry.sha256,
                    "codec": entry.codec,
                    "parts": [
                        {
                            "index": part.index,
                            "offset": part.offset,
                            "size": part.size,
                            "sha256": part.sha256,
                        }
                        for part in entry.parts
                    ],
                }
                for entry in self.entries
            ],
        }
        return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def digest(self) -> str:
        """Complete SHA-256 of the canonical bytes — the artifact's own address."""
        return hashlib.sha256(self.to_canonical_bytes()).hexdigest()

    @classmethod
    def from_bytes(cls, payload: bytes) -> ArtifactManifest:
        """Parse a manifest, refusing unknown versions instead of guessing."""
        try:
            document = json.loads(payload)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ManifestMalformed(f"manifest is not valid JSON: {exc}") from exc
        if not isinstance(document, dict):
            raise ManifestMalformed("manifest must be a JSON object")
        try:
            parent = document.get("parent")
            return cls(
                format_version=document["format_version"],
                schema_version=document["schema_version"],
                codec_version=document.get("codec_version", 1),
                artifact_kind=document["artifact_kind"],
                parent=(
                    ParentReference(digest=parent["digest"], relationship=parent["relationship"])
                    if parent
                    else None
                ),
                annotations=dict(document.get("annotations") or {}),
                entries=tuple(
                    ArtifactEntry(
                        path=entry["path"],
                        size=entry["size"],
                        sha256=entry["sha256"],
                        codec=entry.get("codec"),
                        parts=tuple(
                            ArtifactPart(
                                index=part["index"],
                                offset=part["offset"],
                                size=part["size"],
                                sha256=part["sha256"],
                            )
                            for part in entry.get("parts", ())
                        ),
                    )
                    for entry in document["entries"]
                ),
            )
        except KeyError as exc:
            raise ManifestMalformed(f"manifest is missing field: {exc}") from exc
        except TypeError as exc:
            raise ManifestMalformed(f"manifest field has the wrong shape: {exc}") from exc


def verify_entry_payload(entry: ArtifactEntry, chunks: Iterable[bytes]) -> None:
    """Check streamed payload bytes against the entry's size and complete digest."""
    running = hashlib.sha256()
    total = 0
    for chunk in chunks:
        running.update(chunk)
        total += len(chunk)
    if total != entry.size:
        raise ManifestIntegrityError(
            f"entry {entry.path!r} size mismatch: expected {entry.size}, received {total}"
        )
    if running.hexdigest() != entry.sha256:
        raise ManifestIntegrityError(f"entry {entry.path!r} digest mismatch")
