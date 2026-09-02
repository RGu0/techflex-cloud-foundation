"""At-rest key boundary for local-first storage.

Keys live behind the ``KeyProvider`` protocol — implemented by an OS
secure-storage adapter or a file — and never inside databases or logs.
``AesGcmBlobCodec`` encrypts small sensitive blobs with AES-256-GCM,
binding each envelope to a caller-supplied context string as AAD so a
ciphertext copied to a different purpose fails to decrypt.  Nothing here
knows about any application's data schema.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .durability import set_private_file_mode, write_all

_KEY_BYTES = 32
_NONCE_BYTES = 12
_ENVELOPE_VERSION = 1


class KeyProvider(Protocol):
    """Key handle boundary implemented by an OS secure-storage adapter."""

    def get_key(self) -> bytes: ...


class KeyProviderUnavailable(RuntimeError):
    """The key handle exists but cannot be reached at this moment."""


class FileKeyProvider:
    """Local 32-byte key file, created atomically with owner-only permissions."""

    def __init__(self, key_file: str | Path) -> None:
        self._key_file = Path(key_file)

    def get_key(self) -> bytes:
        if self._key_file.exists():
            key = self._key_file.read_bytes()
            if len(key) != _KEY_BYTES:
                raise ValueError("key file must contain exactly 32 bytes")
            return key
        if not self._key_file.parent.is_dir():
            raise KeyProviderUnavailable("key file directory does not exist")
        key = os.urandom(_KEY_BYTES)
        # O_BINARY: without it Windows text mode would rewrite \n bytes in
        # the random key as \r\n and corrupt the key length.
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
        descriptor = os.open(self._key_file, flags, 0o600)
        try:
            set_private_file_mode(self._key_file, descriptor)
            write_all(descriptor, key)
            os.fsync(descriptor)
        except BaseException:
            try:
                os.close(descriptor)
            finally:
                self._key_file.unlink(missing_ok=True)
            raise
        else:
            os.close(descriptor)
        return key


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
        return AESGCM(key).decrypt(
            nonce, envelope[1 + _NONCE_BYTES :], context.encode("utf-8")
        )

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
