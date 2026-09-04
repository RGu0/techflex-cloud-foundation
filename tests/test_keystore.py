"""Public contract tests for the at-rest key boundary.

``keystore`` had no test module of its own; its coverage came incidentally
from ``test_sealed_store.py``, which is why the provider's most consequential
behaviour -- inventing a key when it could not find one -- was never asserted
either way.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import errno
import os
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    AesGcmBlobCodec,
    BlobDecryptionError,
    FileKeyProvider,
    KeyNotProvisioned,
    KeyProviderUnavailable,
)


@pytest.fixture()
def key_file(tmp_path: Path) -> Path:
    (tmp_path / "keys").mkdir()
    return tmp_path / "keys" / "k.bin"


class TestExplicitProvisioning:
    """Reading a key never creates one."""

    def test_reading_an_unprovisioned_key_refuses_rather_than_inventing_one(
        self, key_file: Path
    ) -> None:
        """The defect, stated as a test.

        ``get_key`` used to generate a fresh key whenever the file was
        absent.  A restore that missed the key file therefore produced no
        error at all: the application came up on a new key and every existing
        ciphertext turned into an authentication failure with nothing to
        point at.  Refusing here is what makes that a recoverable outage.
        """

        provider = FileKeyProvider(key_file)

        with pytest.raises(KeyNotProvisioned):
            provider.get_key()

        assert not key_file.exists(), "reading a key must not create one"

    def test_the_refusal_is_a_key_provider_unavailable(self, key_file: Path) -> None:
        """Existing handlers keep working; the narrower type is additive."""

        assert issubclass(KeyNotProvisioned, KeyProviderUnavailable)
        with pytest.raises(KeyProviderUnavailable):
            FileKeyProvider(key_file).get_key()

    def test_a_created_key_is_stable_and_readable(self, key_file: Path) -> None:
        provider = FileKeyProvider(key_file)

        created = provider.create_key()

        assert len(created) == 32
        assert provider.get_key() == created
        assert FileKeyProvider(key_file).get_key() == created

    def test_creating_twice_returns_the_first_key(self, key_file: Path) -> None:
        """Provisioning is idempotent; it never rotates a live key."""

        provider = FileKeyProvider(key_file)
        first = provider.create_key()

        assert provider.create_key() == first

    def test_concurrent_first_use_agrees_on_one_key(self, tmp_path: Path) -> None:
        """The loser used to get an uncaught FileExistsError.

        It now reads the winner's key.  The staged-and-linked publish is what
        makes the re-read safe: a directly created key file is visible while
        still empty, and a loser reading it then reports a perfectly good
        32-byte key as truncated.
        """

        for round_number in range(25):
            directory = tmp_path / str(round_number)
            directory.mkdir()
            target = directory / "k.bin"

            with ThreadPoolExecutor(max_workers=4) as pool:
                keys = list(
                    pool.map(
                        # Bound as a default: the lambda outlives this loop
                        # iteration, and closing over ``target`` would race the
                        # next round's rebinding.
                        lambda _, path=target: FileKeyProvider(path).create_key(),
                        range(4),
                    )
                )

            assert len(set(keys)) == 1, f"round {round_number} provisioned {len(set(keys))} keys"
            assert keys[0] == target.read_bytes()
            assert list(directory.glob("*.tmp")) == []

    def test_a_missing_directory_is_unavailable_not_corrupt(self, tmp_path: Path) -> None:
        provider = FileKeyProvider(tmp_path / "missing" / "k.bin")

        with pytest.raises(KeyProviderUnavailable, match="directory"):
            provider.create_key()

    def test_a_wrong_length_key_file_is_rejected(self, key_file: Path) -> None:
        key_file.write_bytes(b"short")

        with pytest.raises(ValueError, match="32 bytes"):
            FileKeyProvider(key_file).get_key()

    @pytest.mark.skipif(os.name == "nt", reason="POSIX owner-only mode")
    def test_the_key_file_is_owner_only(self, key_file: Path) -> None:
        FileKeyProvider(key_file).create_key()

        assert (key_file.stat().st_mode & 0o777) == 0o600

    def test_the_directory_entry_is_fsynced(
        self, key_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Without this the key's bytes survive a power cut but its name may not."""

        synced: list[Path] = []
        from techflex_cloud_foundation import keystore

        def record(path: str | Path) -> None:
            synced.append(Path(path))

        monkeypatch.setattr(keystore, "fsync_directory", record)
        FileKeyProvider(key_file).create_key()

        assert key_file.parent in synced

    def test_a_root_without_hard_links_fails_loudly(
        self, key_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def unsupported(source: str | Path, destination: str | Path) -> None:
            raise OSError(errno.EOPNOTSUPP, "Operation not supported")

        monkeypatch.setattr(os, "link", unsupported)

        with pytest.raises(KeyProviderUnavailable, match="hard links"):
            FileKeyProvider(key_file).create_key()
        assert not key_file.exists()
        assert list(key_file.parent.glob("*.tmp")) == []

    def test_a_failed_write_leaves_no_key_behind(
        self, key_file: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A half-provisioned key is worse than none: it cannot be told apart."""

        def disk_full(descriptor: int, data: bytes | memoryview) -> int:
            raise OSError(errno.ENOSPC, "No space left on device")

        monkeypatch.setattr(os, "write", disk_full)

        with pytest.raises(OSError, match="No space left"):
            FileKeyProvider(key_file).create_key()

        assert not key_file.exists()
        assert list(key_file.parent.glob("*.tmp")) == []


class TestBlobCodec:
    @pytest.fixture()
    def codec(self, key_file: Path) -> AesGcmBlobCodec:
        provider = FileKeyProvider(key_file)
        provider.create_key()
        return AesGcmBlobCodec(provider)

    def test_roundtrip(self, codec: AesGcmBlobCodec) -> None:
        envelope = codec.encrypt(b"sensitive", context="subject-name")

        assert codec.decrypt(envelope, context="subject-name") == b"sensitive"

    def test_a_ciphertext_reused_in_another_context_raises_a_library_error(
        self, codec: AesGcmBlobCodec
    ) -> None:
        """``cryptography``'s ``InvalidTag`` used to escape here.

        ``sealed_store`` wrapped the identical failure as
        ``SealVerificationError``, so a caller of this library had to import
        from ``cryptography`` to handle one half of one failure mode.
        """

        envelope = codec.encrypt(b"sensitive", context="subject-name")

        with pytest.raises(BlobDecryptionError, match="other-purpose"):
            codec.decrypt(envelope, context="other-purpose")

    def test_a_tampered_envelope_raises_a_library_error(
        self, codec: AesGcmBlobCodec
    ) -> None:
        envelope = bytearray(codec.encrypt(b"sensitive", context="ctx"))
        envelope[-1] ^= 0xFF

        with pytest.raises(BlobDecryptionError):
            codec.decrypt(bytes(envelope), context="ctx")

    def test_a_wrong_key_raises_a_library_error(
        self, codec: AesGcmBlobCodec, tmp_path: Path
    ) -> None:
        envelope = codec.encrypt(b"sensitive", context="ctx")
        other = FileKeyProvider(tmp_path / "other.bin")
        other.create_key()

        with pytest.raises(BlobDecryptionError):
            AesGcmBlobCodec(other).decrypt(envelope, context="ctx")

    def test_a_truncated_envelope_is_rejected_before_the_key_is_touched(
        self, key_file: Path
    ) -> None:
        codec = AesGcmBlobCodec(FileKeyProvider(key_file))

        with pytest.raises(ValueError, match="envelope"):
            codec.decrypt(b"\x01\x00", context="ctx")

    def test_encrypting_without_a_provisioned_key_refuses(self, key_file: Path) -> None:
        codec = AesGcmBlobCodec(FileKeyProvider(key_file))

        with pytest.raises(KeyNotProvisioned):
            codec.encrypt(b"sensitive", context="ctx")
