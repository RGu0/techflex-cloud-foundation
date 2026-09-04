"""Public contract tests for sealed artifacts, key boundary, and recovery."""

from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    AesGcmSealEncryptor,
    FileKeyProvider,
    MarkerRegistry,
    SealAtomicityUnsupported,
    SealVerificationError,
    finalize_delete,
    quarantine_file,
    read_sealed,
    restore_delete,
    reversible_delete,
    verify_sealed,
    write_sealed,
)


def _provisioned(key_file: Path) -> FileKeyProvider:
    """A provider whose key already exists; provisioning is explicit now."""

    provider = FileKeyProvider(key_file)
    provider.create_key()
    return provider


@pytest.fixture()
def key_provider(tmp_path: Path) -> FileKeyProvider:
    (tmp_path / "keys").mkdir()
    provider = FileKeyProvider(tmp_path / "keys" / "k.bin")
    provider.create_key()
    return provider


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
            encryptor=AesGcmSealEncryptor(_provisioned(tmp_path / "a" / "k.bin")),
        )

        with pytest.raises(SealVerificationError, match="authentication"):
            read_sealed(artifact.path, AesGcmSealEncryptor(_provisioned(tmp_path / "b" / "k.bin")))

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
        key_provider.get_key()  # read the key before fault injection

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
        key_provider.get_key()  # read the key before fault injection

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


class TestUnverifiableArtifactsAreKept:
    """A container that fails its own read-back used to be deleted.

    The module's own docstring says corrupt artifacts are quarantined, not
    deleted, and ``write_sealed`` did the opposite.  The bytes it destroyed
    were the only evidence distinguishing a failing disk from a filesystem
    that lied about a flush from something modifying files underneath the
    process -- and since the failure is not in the caller's payload, deleting
    them does not recover the caller's position either.
    """

    @staticmethod
    def _corrupting(monkeypatch: pytest.MonkeyPatch) -> None:
        """Make the post-write verification fail without touching the write."""

        import techflex_cloud_foundation.sealed_store as sealed_store

        def unverifiable(path: str | Path) -> tuple[dict[str, object], str]:
            raise SealVerificationError(f"{path}: ciphertext digest mismatch")

        monkeypatch.setattr(sealed_store, "verify_sealed", unverifiable)

    def test_a_container_that_fails_read_back_is_quarantined_not_deleted(
        self, tmp_path: Path, key_provider: FileKeyProvider, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        destination = tmp_path / "artifact.sealed"
        self._corrupting(monkeypatch)

        with pytest.raises(SealVerificationError, match="quarantined at"):
            write_sealed(
                destination,
                b"payload",
                header={"i": 1},
                encryptor=AesGcmSealEncryptor(key_provider),
            )

        assert not destination.exists()
        quarantined = list((tmp_path / ".quarantine").glob("*.corrupt"))
        assert len(quarantined) == 1
        assert quarantined[0].read_bytes().startswith(b"TCFSEAL1")

    def test_the_quarantine_directory_can_be_chosen(
        self, tmp_path: Path, key_provider: FileKeyProvider, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        holding = tmp_path / "holding"
        self._corrupting(monkeypatch)

        with pytest.raises(SealVerificationError) as raised:
            write_sealed(
                tmp_path / "artifact.sealed",
                b"payload",
                header={"i": 1},
                encryptor=AesGcmSealEncryptor(key_provider),
                quarantine_dir=holding,
            )

        assert str(holding) in str(raised.value)
        assert len(list(holding.glob("*.corrupt"))) == 1

    def test_a_failed_quarantine_leaves_the_file_in_place_rather_than_losing_it(
        self, tmp_path: Path, key_provider: FileKeyProvider, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The fallback still never deletes.

        If the artifact cannot even be moved aside, the caller is told where
        it is; the one outcome ruled out everywhere on this path is that the
        bytes stop existing.
        """

        import techflex_cloud_foundation.sealed_store as sealed_store

        destination = tmp_path / "artifact.sealed"
        self._corrupting(monkeypatch)

        def cannot_move(path: str | Path, quarantine_dir: str | Path) -> Path:
            raise OSError(errno.EROFS, "Read-only file system")

        monkeypatch.setattr(sealed_store, "quarantine_file", cannot_move)

        with pytest.raises(SealVerificationError, match="left in place"):
            write_sealed(
                destination,
                b"payload",
                header={"i": 1},
                encryptor=AesGcmSealEncryptor(key_provider),
            )

        assert destination.read_bytes().startswith(b"TCFSEAL1")


class TestMovingAsideNeverOverwrites:
    """``exists()`` then ``os.replace`` is a check and a write, not one step.

    Between them a second process can take the name that was just found free,
    and ``os.replace`` overwrites without a word.  In a quarantine or trash
    directory the thing overwritten is the evidence that something already
    went wrong there, which is the one file in the system that should be
    hardest to lose.
    """

    def test_a_second_quarantine_of_the_same_name_keeps_both(self, tmp_path: Path) -> None:
        quarantine = tmp_path / "quarantine"
        first = tmp_path / "a" / "data.bin"
        second = tmp_path / "b" / "data.bin"
        for path, payload in ((first, b"first"), (second, b"second")):
            path.parent.mkdir()
            path.write_bytes(payload)

        one = quarantine_file(first, quarantine)
        two = quarantine_file(second, quarantine)

        assert one != two
        assert {one.read_bytes(), two.read_bytes()} == {b"first", b"second"}

    def test_a_quarantined_file_is_not_left_behind_at_its_old_name(
        self, tmp_path: Path
    ) -> None:
        source = tmp_path / "data.bin"
        source.write_bytes(b"tampered")

        quarantined = quarantine_file(source, tmp_path / "quarantine")

        assert not source.exists()
        assert quarantined.stat().st_nlink == 1

    def test_trashing_two_files_with_one_name_keeps_both(self, tmp_path: Path) -> None:
        trash = tmp_path / "trash"
        first = tmp_path / "x" / "report.bin"
        second = tmp_path / "y" / "report.bin"
        for path, payload in ((first, b"january"), (second, b"february")):
            path.parent.mkdir()
            path.write_bytes(payload)

        one = reversible_delete(first, trash)
        two = reversible_delete(second, trash)

        assert one != two
        assert {one.read_bytes(), two.read_bytes()} == {b"january", b"february"}
        assert one.suffix == two.suffix == ".bin"

    def test_restore_refuses_an_occupied_destination_without_a_prior_check(
        self, tmp_path: Path
    ) -> None:
        """Same guarantee, expressed as the claim itself rather than a look."""

        trash = tmp_path / "trash"
        source = tmp_path / "report.bin"
        source.write_bytes(b"final-report")
        trashed = reversible_delete(source, trash)
        source.write_bytes(b"occupied")

        with pytest.raises(FileExistsError, match="already exists"):
            restore_delete(trashed, source)

        assert source.read_bytes() == b"occupied"
        assert trashed.read_bytes() == b"final-report"

    def test_a_filesystem_without_hard_links_refuses_rather_than_racing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """No silent fallback: the fallback is the bug this replaces."""

        source = tmp_path / "data.bin"
        source.write_bytes(b"tampered")

        def unsupported(src: object, dst: object) -> None:
            raise OSError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr(os, "link", unsupported)

        with pytest.raises(SealAtomicityUnsupported, match="hard links"):
            quarantine_file(source, tmp_path / "quarantine")

        assert source.read_bytes() == b"tampered"


class TestMarkerIdsAreValidatedByWhitelist:
    @pytest.mark.parametrize(
        "marker_id",
        [
            "../escape",
            "a/b",
            "..\\escape",
            "a\\b",
            ".hidden",
            "",
            ".",
            "..",
            "with space",
            "nul\x00byte",
            "unicode⁄slash",
        ],
    )
    def test_a_dangerous_marker_id_is_refused(self, tmp_path: Path, marker_id: str) -> None:
        registry = MarkerRegistry(tmp_path / "markers")

        with pytest.raises(ValueError, match="invalid marker id"):
            registry.begin(marker_id, {})

    @pytest.mark.parametrize(
        "marker_id",
        ["session-1", "a", "0", "run.2024-01-01", "under_score", "3f9c2b1e4a", "A1"],
    )
    def test_an_ordinary_marker_id_is_accepted(self, tmp_path: Path, marker_id: str) -> None:
        registry = MarkerRegistry(tmp_path / "markers")

        registry.begin(marker_id, {"path": "sessions/1"})

        assert [marker.marker_id for marker in registry.pending()] == [marker_id]

    def test_a_backslash_id_cannot_escape_the_marker_directory(self, tmp_path: Path) -> None:
        """The blacklist checked ``/`` and ``..`` -- neither catches this.

        On Windows ``markers\\..\\escape`` leaves the directory exactly as
        ``../escape`` does elsewhere, and ``"..\\escape"`` contains ``..`` so
        the old check did stop that one; ``"a\\b"`` does not, and wrote into
        a subdirectory that :meth:`pending` never scans.
        """

        registry = MarkerRegistry(tmp_path / "markers")

        with pytest.raises(ValueError, match="invalid marker id"):
            registry.begin("a\\b", {})

    def test_a_hidden_marker_id_is_refused_because_recovery_would_miss_it(
        self, tmp_path: Path
    ) -> None:
        """A marker nobody finds is worse than no marker at all.

        ``pending()`` globs ``*.marker.json``, and ``*`` does not match a
        leading dot.  A marker written as ``.session`` exists on disk, so
        nothing looks incomplete, and its action is never replayed -- the
        exactly-once coupling silently becomes at-most-once.
        """

        registry = MarkerRegistry(tmp_path / "markers")

        with pytest.raises(ValueError, match="invalid marker id"):
            registry.begin(".session", {})

        assert registry.pending() == ()
