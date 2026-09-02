"""Public contract tests for sealed artifacts, key boundary, and recovery."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    AesGcmBlobCodec,
    AesGcmSealEncryptor,
    FileKeyProvider,
    KeyProviderUnavailable,
    MarkerRegistry,
    SealVerificationError,
    finalize_delete,
    quarantine_file,
    read_sealed,
    restore_delete,
    reversible_delete,
    verify_sealed,
    write_sealed,
)


@pytest.fixture()
def key_provider(tmp_path: Path) -> FileKeyProvider:
    (tmp_path / "keys").mkdir()
    return FileKeyProvider(tmp_path / "keys" / "k.bin")


class TestKeyBoundary:
    def test_file_key_provider_creates_stable_32_byte_key(self, key_provider: FileKeyProvider) -> None:
        key = key_provider.get_key()
        assert len(key) == 32
        assert key_provider.get_key() == key

    @pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
    def test_key_file_is_owner_only(self, key_provider: FileKeyProvider) -> None:
        key_provider.get_key()
        assert ((key_provider._key_file).stat().st_mode & 0o777) == 0o600

    def test_key_file_with_wrong_length_is_rejected(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.bin"
        bad.write_bytes(b"short")
        with pytest.raises(ValueError, match="32 bytes"):
            FileKeyProvider(bad).get_key()

    def test_missing_key_directory_is_unavailable_not_corrupt(self, tmp_path: Path) -> None:
        with pytest.raises(KeyProviderUnavailable):
            FileKeyProvider(tmp_path / "missing" / "k.bin").get_key()

    def test_blob_codec_roundtrip_and_context_binding(self, key_provider: FileKeyProvider) -> None:
        codec = AesGcmBlobCodec(key_provider)
        envelope = codec.encrypt(b"sensitive", context="subject-name")

        assert codec.decrypt(envelope, context="subject-name") == b"sensitive"
        with pytest.raises(Exception):
            codec.decrypt(envelope, context="other-purpose")

    def test_blob_codec_rejects_truncated_envelope(self, key_provider: FileKeyProvider) -> None:
        codec = AesGcmBlobCodec(key_provider)
        with pytest.raises(ValueError, match="envelope"):
            codec.decrypt(b"\x01\x00", context="ctx")


class TestSealedContainers:
    def test_write_read_roundtrip(self, tmp_path: Path, key_provider: FileKeyProvider) -> None:
        encryptor = AesGcmSealEncryptor(key_provider)
        artifact = write_sealed(
            tmp_path / "artifact.bin",
            b"payload-bytes",
            header={"kind": "segment", "index": 1},
            encryptor=encryptor,
        )

        assert artifact.path.exists()
        header, plaintext = read_sealed(artifact.path, encryptor)
        assert plaintext == b"payload-bytes"
        assert header["kind"] == "segment"
        assert artifact.payload_sha256 == verify_sealed(artifact.path)[1]

    def test_verify_needs_no_key(self, tmp_path: Path, key_provider: FileKeyProvider) -> None:
        artifact = write_sealed(
            tmp_path / "artifact.bin",
            b"payload",
            header={"kind": "segment"},
            encryptor=AesGcmSealEncryptor(key_provider),
        )

        header, digest = verify_sealed(artifact.path)
        assert header["kind"] == "segment"
        assert len(digest) == 64

    def test_tampered_ciphertext_is_detected(self, tmp_path: Path, key_provider: FileKeyProvider) -> None:
        encryptor = AesGcmSealEncryptor(key_provider)
        artifact = write_sealed(
            tmp_path / "artifact.bin", b"payload", header={"i": 1}, encryptor=encryptor
        )
        data = bytearray(artifact.path.read_bytes())
        data[len(data) // 2] ^= 0x01
        artifact.path.write_bytes(bytes(data))

        with pytest.raises(SealVerificationError):
            verify_sealed(artifact.path)

    def test_wrong_key_fails_decryption(self, tmp_path: Path) -> None:
        (tmp_path / "a").mkdir()
        (tmp_path / "b").mkdir()
        artifact = write_sealed(
            tmp_path / "artifact.bin",
            b"payload",
            header={"i": 1},
            encryptor=AesGcmSealEncryptor(FileKeyProvider(tmp_path / "a" / "k.bin")),
        )

        with pytest.raises(SealVerificationError, match="authentication"):
            read_sealed(artifact.path, AesGcmSealEncryptor(FileKeyProvider(tmp_path / "b" / "k.bin")))

    def test_header_is_authenticated(self, tmp_path: Path, key_provider: FileKeyProvider) -> None:
        import hashlib

        encryptor = AesGcmSealEncryptor(key_provider)
        artifact = write_sealed(
            tmp_path / "artifact.bin", b"payload", header={"i": 1}, encryptor=encryptor
        )
        raw = artifact.path.read_bytes()
        header_length = int.from_bytes(raw[8:12], "big")
        ciphertext_length = int.from_bytes(raw[12 + header_length : 20 + header_length], "big")
        ciphertext = raw[20 + header_length : 20 + header_length + ciphertext_length]

        # Rebuild a structurally valid container around a forged header so
        # only the AAD binding can catch it.
        forged_header = b'{"i":2}'
        forged = (
            raw[:8]
            + len(forged_header).to_bytes(4, "big")
            + forged_header
            + ciphertext_length.to_bytes(8, "big")
            + ciphertext
            + hashlib.sha256(ciphertext).digest()
            + b"TCFEND01"
        )
        forged_path = tmp_path / "forged.bin"
        forged_path.write_bytes(forged)

        verify_sealed(forged_path)
        with pytest.raises(SealVerificationError, match="authentication"):
            read_sealed(forged_path, encryptor)

    def test_write_cleans_up_when_disk_full(
        self, tmp_path: Path, key_provider: FileKeyProvider, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "artifact.bin"
        key_provider.get_key()  # materialise the key before fault injection

        def disk_full(descriptor: int, data: bytes | memoryview) -> int:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(os, "write", disk_full)
        with pytest.raises(OSError, match="No space left"):
            write_sealed(
                destination, b"payload", header={"i": 1}, encryptor=AesGcmSealEncryptor(key_provider)
            )

        assert not destination.exists()
        assert list(tmp_path.glob("*.tmp")) == []

    def test_write_cleans_up_when_fsync_fails(
        self, tmp_path: Path, key_provider: FileKeyProvider, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "artifact.bin"
        key_provider.get_key()  # materialise the key before fault injection

        def failing_fsync(descriptor: int) -> None:
            raise OSError(errno.EIO, "fsync failed")

        monkeypatch.setattr(os, "fsync", failing_fsync)
        with pytest.raises(OSError, match="fsync failed"):
            write_sealed(
                destination, b"payload", header={"i": 1}, encryptor=AesGcmSealEncryptor(key_provider)
            )

        assert not destination.exists()
        assert list(tmp_path.glob("*.tmp")) == []


class TestRecoveryPrimitives:
    def test_quarantine_moves_tampered_file_aside(self, tmp_path: Path) -> None:
        corrupt = tmp_path / "data.bin"
        corrupt.write_bytes(b"tampered")

        quarantined = quarantine_file(corrupt, tmp_path / "quarantine")

        assert not corrupt.exists()
        assert quarantined.read_bytes() == b"tampered"
        assert quarantined.name.endswith(".corrupt")

    def test_marker_registry_recovers_pending_registrations(self, tmp_path: Path) -> None:
        registry = MarkerRegistry(tmp_path / "markers")
        registry.begin("session-1", {"path": "sessions/1"})
        registry.begin("session-2", {"path": "sessions/2"})
        registry.complete("session-1")

        pending = registry.pending()

        assert [marker.marker_id for marker in pending] == ["session-2"]
        assert pending[0].payload["path"] == "sessions/2"

    def test_marker_ids_are_path_safe(self, tmp_path: Path) -> None:
        registry = MarkerRegistry(tmp_path / "markers")
        with pytest.raises(ValueError, match="invalid marker id"):
            registry.begin("../escape", {})

    def test_reversible_delete_window(self, tmp_path: Path) -> None:
        source = tmp_path / "report.bin"
        source.write_bytes(b"final-report")
        trash = tmp_path / "trash"

        trashed = reversible_delete(source, trash)
        assert not source.exists()

        source.write_bytes(b"occupied")
        with pytest.raises(FileExistsError, match="already exists"):
            restore_delete(trashed, source)
        source.unlink()

        restored = restore_delete(trashed, tmp_path / "restored.bin")
        assert restored.read_bytes() == b"final-report"

        trashed_again = reversible_delete(restored, trash)
        finalize_delete(trashed_again)
        assert not trashed_again.exists()
