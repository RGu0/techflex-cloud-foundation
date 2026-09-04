"""Sealed artifact containers and crash-recovery building blocks.

A sealed container is an immutable, self-verifying file:
``MAGIC | header length | canonical-JSON header (AAD) | ciphertext length |
ciphertext | ciphertext SHA-256 | TAIL``.  The header authenticates as
AEAD associated data, so moving a ciphertext under a different header
fails decryption.  Writes are staged through the durability primitives
and re-verified after publication; corrupt artifacts are quarantined, not
deleted.  Marker-based registration gives exactly-once coupling between a
filesystem action and any bookkeeping step across a crash, and reversible
deletes provide a regret window.  Nothing here knows about any
application's payload format.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
from typing import Any, Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .durability import StagedAtomicFileWriter, atomic_write, fsync_directory
from .keystore import KeyProvider, KeyProviderUnavailable

_MAGIC = b"TCFSEAL1"
_TAIL = b"TCFEND01"
_NONCE_BYTES = 12
_KEY_BYTES = 32
_QUARANTINE_DIRNAME = ".quarantine"
# Names a marker id may take.  A whitelist, because the interesting inputs are
# the ones nobody enumerated; see :meth:`MarkerRegistry.begin`.
_MARKER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\Z")
# How many random names to try before giving up on finding a free one.  Each
# carries 64 bits of entropy, so reaching the end means something other than
# collision is wrong.
_NAME_ATTEMPTS = 8
# errno values that mean "this filesystem cannot hard-link", as opposed to a
# transient or unrelated failure.
_LINK_UNSUPPORTED_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, name, None)
        for name in ("EPERM", "EOPNOTSUPP", "ENOTSUP", "EXDEV", "ENOSYS", "EMLINK")
    )
    if value is not None
)


class SealVerificationError(ValueError):
    """A sealed container failed structural, digest, or decryption checks."""


class SealAtomicityUnsupported(RuntimeError):
    """A directory cannot provide the move semantics these primitives need."""


class SealEncryptor(Protocol):
    """AEAD boundary; the header is supplied as associated data."""

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes: ...

    def decrypt(self, ciphertext: bytes, *, aad: bytes) -> bytes: ...


class AesGcmSealEncryptor:
    """AES-256-GCM encryptor; the nonce is prepended to the ciphertext."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._key_provider = key_provider

    def encrypt(self, plaintext: bytes, *, aad: bytes) -> bytes:
        key = self._load_key()
        nonce = os.urandom(_NONCE_BYTES)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, ciphertext: bytes, *, aad: bytes) -> bytes:
        if len(ciphertext) < _NONCE_BYTES + 16:
            raise SealVerificationError("truncated sealed ciphertext")
        key = self._load_key()
        nonce = ciphertext[:_NONCE_BYTES]
        try:
            return AESGCM(key).decrypt(nonce, ciphertext[_NONCE_BYTES:], aad)
        except Exception as exc:
            raise SealVerificationError("sealed payload failed authentication") from exc

    def _load_key(self) -> bytes:
        try:
            key = self._key_provider.get_key()
        except KeyProviderUnavailable:
            raise
        except OSError as exc:
            raise KeyProviderUnavailable(
                "secure key storage is temporarily unavailable"
            ) from exc
        if len(key) != _KEY_BYTES:
            raise ValueError("key provider must return a 32-byte AES-256 key")
        return key


@dataclass(frozen=True, slots=True)
class SealedArtifact:
    """A published sealed container on disk."""

    path: Path
    header: Mapping[str, Any]
    payload_sha256: str
    byte_count: int


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _build_container(
    plaintext: bytes, header: Mapping[str, Any], encryptor: SealEncryptor
) -> tuple[bytes, bytes, str]:
    header_bytes = _canonical_json(header)
    ciphertext = encryptor.encrypt(plaintext, aad=header_bytes)
    digest = hashlib.sha256(ciphertext).hexdigest()
    container = (
        _MAGIC
        + len(header_bytes).to_bytes(4, "big")
        + header_bytes
        + len(ciphertext).to_bytes(8, "big")
        + ciphertext
        + bytes.fromhex(digest)
        + _TAIL
    )
    return container, header_bytes, digest


def _parse_container(data: bytes, *, source: Path) -> tuple[dict[str, Any], bytes, bytes]:
    """Return (header, header_bytes, ciphertext); raise on any structural fault."""

    def fail(reason: str) -> SealVerificationError:
        return SealVerificationError(f"{source}: {reason}")

    if len(data) < len(_MAGIC) + 4 or not data.startswith(_MAGIC):
        raise fail("missing seal magic")
    header_length = int.from_bytes(data[len(_MAGIC) : len(_MAGIC) + 4], "big")
    header_start = len(_MAGIC) + 4
    header_end = header_start + header_length
    if len(data) < header_end + 8 + 32 + len(_TAIL):
        raise fail("truncated sealed container")
    header_bytes = data[header_start:header_end]
    ciphertext_length = int.from_bytes(data[header_end : header_end + 8], "big")
    ciphertext_start = header_end + 8
    ciphertext_end = ciphertext_start + ciphertext_length
    if len(data) != ciphertext_end + 32 + len(_TAIL):
        raise fail("sealed container length mismatch")
    ciphertext = data[ciphertext_start:ciphertext_end]
    recorded_digest = data[ciphertext_end : ciphertext_end + 32]
    if data[ciphertext_end + 32 :] != _TAIL:
        raise fail("missing seal tail")
    if hashlib.sha256(ciphertext).digest() != recorded_digest:
        raise fail("ciphertext digest mismatch")
    try:
        header = json.loads(header_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise fail("unreadable sealed header") from exc
    if not isinstance(header, dict):
        raise fail("sealed header must be a JSON object")
    return header, header_bytes, ciphertext


def write_sealed(
    destination: str | Path,
    plaintext: bytes,
    *,
    header: Mapping[str, Any],
    encryptor: SealEncryptor,
    quarantine_dir: str | Path | None = None,
) -> SealedArtifact:
    """Publish one sealed container atomically and verify it after writing.

    A container that fails its own read-back is *quarantined*, not deleted.
    This used to ``unlink`` it, contradicting the promise at the top of this
    module and destroying the only copy of the evidence.  A container that
    was written successfully and then failed verification is the signature of
    a failing disk, a filesystem that lied about a flush, or something
    modifying files underneath the process -- and the bytes are what
    distinguish those. The failure is not the caller's payload, so deleting
    it does not even recover the caller's position.

    ``quarantine_dir`` defaults to a ``.quarantine`` directory beside the
    destination, which keeps the move on one filesystem. The raised
    :class:`SealVerificationError` names where the file went.
    """

    target = Path(destination)
    container, _, digest = _build_container(plaintext, header, encryptor)
    writer = StagedAtomicFileWriter(target)
    try:
        writer.write(container)
        writer.commit()
    except BaseException:
        writer.abort()
        raise
    try:
        verify_sealed(target)
    except SealVerificationError as exc:
        raise _quarantine_unverifiable(target, quarantine_dir, exc) from exc
    return SealedArtifact(target, dict(header), digest, len(container))


def _quarantine_unverifiable(
    target: Path, quarantine_dir: str | Path | None, failure: SealVerificationError
) -> SealVerificationError:
    """Move a published-but-unverifiable container aside; report where."""

    root = Path(quarantine_dir) if quarantine_dir is not None else target.parent / _QUARANTINE_DIRNAME
    try:
        quarantined = quarantine_file(target, root)
    except (OSError, SealAtomicityUnsupported) as move_failure:
        return SealVerificationError(
            f"{failure}; it could not be quarantined either ({move_failure}), so it is "
            f"left in place at {target} for inspection"
        )
    return SealVerificationError(
        f"{failure}; the artifact was quarantined at {quarantined} rather than deleted"
    )


def verify_sealed(path: str | Path) -> tuple[Mapping[str, Any], str]:
    """Structurally verify a sealed container; return (header, payload sha256)."""

    source = Path(path)
    header, _, ciphertext = _parse_container(source.read_bytes(), source=source)
    return header, hashlib.sha256(ciphertext).hexdigest()


def read_sealed(path: str | Path, encryptor: SealEncryptor) -> tuple[Mapping[str, Any], bytes]:
    """Verify then decrypt a sealed container; return (header, plaintext)."""

    source = Path(path)
    header, header_bytes, ciphertext = _parse_container(source.read_bytes(), source=source)
    return header, encryptor.decrypt(ciphertext, aad=header_bytes)


def _claim(source: Path, destination: Path) -> bool:
    """Give ``source``'s content a second name at ``destination``.

    ``os.link`` either creates the name or fails because it exists, in one
    step the kernel resolves.  The pattern it replaces --
    ``if destination.exists(): <pick another> ... os.replace(...)`` -- left a
    window between the two calls in which a second process could take the
    name it had just found free, and ``os.replace`` overwrites silently.  In
    a quarantine or trash directory the thing overwritten is the evidence
    that something already went wrong there.
    """

    try:
        os.link(source, destination)
    except FileExistsError:
        return False
    except OSError as exc:
        if exc.errno not in _LINK_UNSUPPORTED_ERRNOS:
            raise
        raise SealAtomicityUnsupported(
            f"cannot move {source.name} aside without risking an overwrite: "
            f"{destination.parent} does not support hard links ({exc.strerror}). "
            "Place it on a filesystem that does, and on the same filesystem as "
            "the files it receives."
        ) from exc
    return True


def _move_to_first_free_name(source: Path, candidates: Iterable[Path]) -> Path:
    """Move ``source`` to the first candidate name no one else holds."""

    attempted: Path | None = None
    for destination in candidates:
        attempted = destination
        if not _claim(source, destination):
            continue
        source.unlink()
        fsync_directory(destination.parent)
        if source.parent != destination.parent:
            fsync_directory(source.parent)
        return destination
    raise SealAtomicityUnsupported(
        f"could not find a free name for {source.name} in {attempted.parent if attempted else '?'}"
    )


def _suffixed_names(target_dir: Path, stem: str, suffix: str) -> Iterator[Path]:
    """The preferred name, then randomly disambiguated ones."""

    yield target_dir / f"{stem}{suffix}"
    for _ in range(_NAME_ATTEMPTS):
        yield target_dir / f"{stem}.{secrets.token_hex(8)}{suffix}"


def quarantine_file(path: str | Path, quarantine_dir: str | Path) -> Path:
    """Move an unreadable or tampered artifact aside, never silently delete it."""

    source = Path(path)
    target_dir = Path(quarantine_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    return _move_to_first_free_name(
        source, _suffixed_names(target_dir, source.name, ".corrupt")
    )


@dataclass(frozen=True, slots=True)
class Marker:
    """A pending registration marker found during recovery."""

    marker_id: str
    payload: Mapping[str, Any]
    path: Path


class MarkerRegistry:
    """Exactly-once coupling between a filesystem action and bookkeeping.

    ``begin`` durably writes a marker *before* the risky action;
    ``complete`` removes it after bookkeeping lands.  Markers still present
    at startup (``pending``) identify actions whose bookkeeping must be
    replayed exactly once.
    """

    def __init__(self, marker_dir: str | Path) -> None:
        self._dir = Path(marker_dir)
        self._dir.mkdir(parents=True, exist_ok=True)

    def begin(self, marker_id: str, payload: Mapping[str, Any]) -> Path:
        """Durably record a marker before the action it makes recoverable.

        ``marker_id`` becomes a filename, so it is validated against a
        whitelist rather than a list of things to exclude. The blacklist it
        replaces -- ``"/" in marker_id or ".." in marker_id`` -- missed three
        kinds of input:

        * ``a\\..\\b`` and other backslash paths, which escape the marker
          directory on Windows exactly as ``/`` does elsewhere;
        * a leading dot, which writes a marker that :meth:`pending` never
          returns, because ``glob`` does not match hidden files with ``*`` --
          the marker exists, so its action is never replayed, and the whole
          point of a marker is that it is found again;
        * NUL bytes and other characters the filesystem refuses, which turned
          a caller's mistake into an ``OSError`` from deep inside a write.
        """

        if not _MARKER_ID.match(marker_id):
            raise ValueError(
                f"invalid marker id {marker_id!r}: expected letters, digits, dot, hyphen "
                "or underscore, starting with a letter or digit"
            )
        return atomic_write(self._dir / f"{marker_id}.marker.json", _canonical_json(payload))

    def complete(self, marker_id: str) -> None:
        (self._dir / f"{marker_id}.marker.json").unlink(missing_ok=True)
        fsync_directory(self._dir)

    def pending(self) -> tuple[Marker, ...]:
        markers: list[Marker] = []
        for path in sorted(self._dir.glob("*.marker.json")):
            try:
                payload = json.loads(path.read_bytes().decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SealVerificationError(f"unreadable registration marker: {path}") from exc
            markers.append(Marker(path.name[: -len(".marker.json")], payload, path))
        return tuple(markers)


def reversible_delete(path: str | Path, trash_dir: str | Path) -> Path:
    """Move a file into a trash window instead of deleting it outright."""

    source = Path(path)
    target_dir = Path(trash_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    candidates = _suffixed_names(target_dir, source.stem, source.suffix)
    return _move_to_first_free_name(source, candidates)


def restore_delete(trash_path: str | Path, destination: str | Path) -> Path:
    """Bring a file back out of the trash window."""

    source = Path(trash_path)
    target = Path(destination)
    if not _claim(source, target):
        raise FileExistsError(f"restore destination already exists: {target}")
    source.unlink()
    fsync_directory(target.parent)
    if source.parent != target.parent:
        fsync_directory(source.parent)
    return target


def finalize_delete(trash_path: str | Path) -> None:
    """Permanently remove a file from the trash window."""

    source = Path(trash_path)
    parent = source.parent
    source.unlink(missing_ok=True)
    fsync_directory(parent)
