"""At-rest key boundary for local-first storage.

Keys live behind the ``KeyProvider`` protocol — implemented by an OS
secure-storage adapter or a file — and never inside databases or logs.
``AesGcmBlobCodec`` encrypts small sensitive blobs with AES-256-GCM,
binding each envelope to a caller-supplied context string as AAD so a
ciphertext copied to a different purpose fails to decrypt.  Nothing here
knows about any application's data schema.

Provisioning a key is a deliberate act, never a side effect of reading one:
a provider that invents a key when it cannot find one converts a missing
backup into unreadable data.  See :class:`FileKeyProvider`.
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
import secrets
from typing import Protocol

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .durability import fsync_directory, set_private_file_mode, write_all

_KEY_BYTES = 32
# errno values meaning "this filesystem cannot hard-link", as distinct from a
# transient or unrelated failure.
_LINK_UNSUPPORTED_ERRNOS = frozenset(
    value
    for value in (
        getattr(errno, name, None)
        for name in ("EPERM", "EOPNOTSUPP", "ENOTSUP", "EXDEV", "ENOSYS", "EMLINK")
    )
    if value is not None
)
_NONCE_BYTES = 12
_ENVELOPE_VERSION = 1


class KeyProvider(Protocol):
    """Key handle boundary implemented by an OS secure-storage adapter."""

    def get_key(self) -> bytes: ...


class KeyProviderUnavailable(RuntimeError):
    """The key handle exists but cannot be reached at this moment."""


class KeyNotProvisioned(KeyProviderUnavailable):
    """No key has been provisioned at this handle.

    Distinct from its parent because the remedy differs: a transient
    ``KeyProviderUnavailable`` is worth retrying, while this one is not --
    either the key was never created, or it has been lost and the restore
    that should have brought it back did not.  Callers that cannot tell
    those apart are the reason this used to be silently self-healing.
    """


class BlobDecryptionError(ValueError):
    """Authenticated decryption failed: wrong key, wrong context, or tampering.

    ``cryptography``'s ``InvalidTag`` used to escape from
    :meth:`AesGcmBlobCodec.decrypt` while ``sealed_store`` wrapped the same
    failure as ``SealVerificationError``, so one library reported one kind of
    failure two ways and a caller handling both had to import from
    ``cryptography`` to catch half of them.  Both are ``ValueError``
    subclasses, so ``except ValueError`` covers either.
    """


class FileKeyProvider:
    """Local 32-byte key file with owner-only permissions.

    Provisioning is explicit.  :meth:`create_key` writes a key; :meth:`get_key`
    only reads one.  ``get_key`` used to generate a key whenever the file was
    absent, which turned the worst recoverable failure in a local-first system
    into a silent one: a restore that missed the key file left the application
    running normally on a brand-new key, and every existing ciphertext became
    an undiagnosable authentication failure.  Refusing to read a key that was
    never created is the difference between an outage and data loss.
    """

    def __init__(self, key_file: str | Path) -> None:
        self._key_file = Path(key_file)

    @property
    def key_file(self) -> Path:
        return self._key_file

    def get_key(self) -> bytes:
        """Read the provisioned key, or raise ``KeyNotProvisioned``."""

        try:
            key = self._key_file.read_bytes()
        except FileNotFoundError as exc:
            raise KeyNotProvisioned(
                f"no key has been provisioned at {self._key_file}; call "
                "create_key() to provision one, or restore the key file. A "
                "new key would not recover existing ciphertext."
            ) from exc
        if len(key) != _KEY_BYTES:
            raise ValueError("key file must contain exactly 32 bytes")
        return key

    def create_key(self) -> bytes:
        """Provision a key once, returning the existing one if there is one.

        Concurrent first use is ordinary rather than exceptional: whoever
        loses returns the winner's key instead of the uncaught
        ``FileExistsError`` this used to raise.

        The key is staged and published with :func:`os.link` rather than
        written in place, so a loser never reads a file the winner has
        created but not yet filled -- that race reports a 32-byte key as
        truncated, which reads like corruption rather than timing.  The
        parent directory is fsynced afterwards, without which the key file's
        directory entry can be lost to power failure while the key's own
        bytes are safely on disk.
        """

        directory = self._key_file.parent
        if not directory.is_dir():
            raise KeyProviderUnavailable("key file directory does not exist")
        key = os.urandom(_KEY_BYTES)
        staging = directory / f".{self._key_file.name}.{secrets.token_hex(16)}.tmp"
        # O_BINARY: without it Windows text mode would rewrite \n bytes in
        # the random key as \r\n and corrupt the key length.
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        descriptor = os.open(staging, flags, 0o600)
        try:
            try:
                set_private_file_mode(staging, descriptor)
                write_all(descriptor, key)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if not self._publish(staging, self._key_file):
                return self.get_key()
        finally:
            staging.unlink(missing_ok=True)
        fsync_directory(directory)
        return key

    @staticmethod
    def _publish(staging: Path, key_file: Path) -> bool:
        try:
            os.link(staging, key_file)
        except FileExistsError:
            return False
        except OSError as exc:
            if exc.errno not in _LINK_UNSUPPORTED_ERRNOS:
                raise
            raise KeyProviderUnavailable(
                f"cannot provision {key_file.name} atomically: its directory is "
                f"on a filesystem without hard links ({exc.strerror}). Place the "
                "key file on one that has them."
            ) from exc
        return True


class AesGcmBlobCodec:
    """AES-256-GCM envelope whose key is fetched per use, never persisted."""

    def __init__(self, key_provider: KeyProvider) -> None:
        self._key_provider = key_provider

    def encrypt(self, plaintext: bytes, *, context: str) -> bytes:
        key = self._load_key()
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, context.encode("utf-8"))
        return bytes([_ENVELOPE_VERSION]) + nonce + ciphertext

    def decrypt(self, envelope: bytes, *, context: str) -> bytes:
        if len(envelope) < 1 + _NONCE_BYTES + 16 or envelope[0] != _ENVELOPE_VERSION:
            raise ValueError("unsupported or truncated blob envelope")
        key = self._load_key()
        nonce = envelope[1 : 1 + _NONCE_BYTES]
        try:
            return AESGCM(key).decrypt(
                nonce, envelope[1 + _NONCE_BYTES :], context.encode("utf-8")
            )
        except InvalidTag as exc:
            raise BlobDecryptionError(
                f"blob failed authentication for context {context!r}"
            ) from exc

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
