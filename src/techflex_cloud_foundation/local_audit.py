"""Hash-chained local audit log.

A tamper-evident, append-only JSONL log for local-first applications:
every record links to the previous record's digest, appends are fsynced
with owner-only permissions, generations rotate with bounded retention,
and startup recovery truncates a torn final line left by a crash.  A
cross-process lock serializes concurrent writers.  Payloads are opaque
canonical-JSON mappings; nothing here knows about any application's
event schema.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
import errno
import hashlib
import json
import os
from pathlib import Path
import time

from .durability import fsync_directory, set_private_file_mode, write_all

_ACTIVE_FILENAME = "events.jsonl"
_LOCK_FILENAME = ".events.lock"
_TAIL_CHUNK_BYTES = 8192


def _canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _record_digest(payload: Mapping[str, object], previous_sha256: str | None) -> str:
    previous = bytes.fromhex(previous_sha256) if previous_sha256 else b""
    return hashlib.sha256(_canonical_json_bytes(payload) + previous).hexdigest()


def _read_last_nonempty_line(path: Path) -> bytes | None:
    """Return the final non-empty line, reading only the end of the file."""

    with path.open("rb") as handle:
        position = handle.seek(0, os.SEEK_END)
        buffer = b""
        while position > 0:
            step = min(_TAIL_CHUNK_BYTES, position)
            position -= step
            handle.seek(position)
            buffer = handle.read(step) + buffer
            lines = buffer.splitlines()
            # Until the read reaches byte 0 the first element may be the tail
            # of a line whose start has not been read yet, so it is not a
            # candidate.  It stays in ``buffer`` and is reconsidered whole on
            # the next iteration.
            candidates = lines if position == 0 else lines[1:]
            for raw_line in reversed(candidates):
                if raw_line:
                    return raw_line
    return None


@dataclass(frozen=True, slots=True)
class ChainedRecord:
    """One verified log entry: opaque payload plus its chain position."""

    payload: Mapping[str, object]
    sha256: str
    previous_sha256: str | None


class ChainedAppendLog:
    """Append-only hash-chained log with rotation and crash recovery."""

    def __init__(
        self,
        root: str | Path,
        *,
        max_generation_bytes: int = 1_048_576,
        generations: int = 3,
    ) -> None:
        if max_generation_bytes < 1:
            raise ValueError("max_generation_bytes must be positive")
        if generations < 1:
            raise ValueError("generations must be positive")
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            os.chmod(self._root, 0o700)
        self._max_generation_bytes = max_generation_bytes
        self._generations = generations
        # (identity of the active file, digest of its final record).  Another
        # process holding the lock between two of our appends invalidates it,
        # so the identity is compared before the digest is trusted.
        self._tail_cache: tuple[tuple[int, int], str | None] | None = None
        with self._exclusive_process_lock():
            self._recover_incomplete_final_line()

    @property
    def _active_path(self) -> Path:
        return self._root / _ACTIVE_FILENAME

    @property
    def _lock_path(self) -> Path:
        return self._root / _LOCK_FILENAME

    def append(self, payload: Mapping[str, object]) -> ChainedRecord:
        """Append one payload as a chained record; returns the stored record."""

        encoded_payload = _canonical_json_bytes(payload)  # validates JSON-safety early
        with self._exclusive_process_lock():
            # Anchor the chain before rotation: afterwards the active file is
            # empty and its digest would be lost.
            previous_sha256 = self._last_digest()
            self._rotate_if_needed()
            record = ChainedRecord(
                payload=json.loads(encoded_payload),
                sha256=_record_digest(json.loads(encoded_payload), previous_sha256),
                previous_sha256=previous_sha256,
            )
            line = _canonical_json_bytes(
                {
                    "payload": record.payload,
                    "previous_sha256": record.previous_sha256,
                    "sha256": record.sha256,
                }
            ) + b"\n"
            descriptor = os.open(
                self._active_path,
                os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                set_private_file_mode(self._active_path, descriptor)
                write_all(descriptor, line)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            identity = self._active_identity()
            self._tail_cache = None if identity is None else (identity, record.sha256)
            return record

    def verified_records(self) -> tuple[ChainedRecord, ...]:
        """Read every generation and verify the digest chain end to end.

        Raises ``ValueError`` on the first broken link, invalid digest, or
        malformed line.
        """

        records: list[ChainedRecord] = []
        previous_sha256: str | None = None
        with self._exclusive_process_lock():
            for path in self._generation_paths_oldest_first():
                for line_number, raw_line in enumerate(
                    path.read_bytes().splitlines(), start=1
                ):
                    if not raw_line:
                        continue
                    record = self._parse_line(raw_line, path, line_number)
                    # Rotation drops the oldest generation, so the first
                    # surviving record anchors a new chain segment; its own
                    # stored previous digest still feeds its digest check.
                    if previous_sha256 is not None and record.previous_sha256 != previous_sha256:
                        raise ValueError(f"broken record chain at {path}:{line_number}")
                    if record.sha256 != _record_digest(record.payload, record.previous_sha256):
                        raise ValueError(f"invalid record digest at {path}:{line_number}")
                    records.append(record)
                    previous_sha256 = record.sha256
        return tuple(records)

    def head_digest(self) -> str | None:
        """Digest of the oldest surviving record, or None when the log is empty.

        This is the anchor a caller stores outside the log directory.  Nothing
        inside the directory can detect its wholesale replacement by a
        self-consistent forgery: :meth:`verified_records` checks that each
        record links to the one before it, and a forged chain satisfies that
        as readily as the real one.  Comparing this value against a copy held
        elsewhere is what closes that gap.

        The anchor is stable only within the retention window.  Rotation drops
        the oldest generation, which legitimately advances the head, so a
        caller re-anchors after rotation and treats records before the new head
        as no longer verifiable from this directory.  See
        ``docs/boundaries-and-troubleshooting.md``.
        """

        with self._exclusive_process_lock():
            for path in self._generation_paths_oldest_first():
                for line_number, raw_line in enumerate(
                    path.read_bytes().splitlines(), start=1
                ):
                    if raw_line:
                        return self._parse_line(raw_line, path, line_number).sha256
        return None

    # -- internals ---------------------------------------------------------

    @staticmethod
    def _parse_line(raw_line: bytes, path: Path, line_number: int) -> ChainedRecord:
        try:
            decoded = json.loads(raw_line.decode("utf-8"))
            record = ChainedRecord(
                payload=decoded["payload"],
                sha256=decoded["sha256"],
                previous_sha256=decoded["previous_sha256"],
            )
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise ValueError(f"invalid log record at {path}:{line_number}") from exc
        return record

    def _generation_paths_oldest_first(self) -> tuple[Path, ...]:
        archived = [
            self._root / f"events.{index}.jsonl"
            for index in range(self._generations - 1, 0, -1)
        ]
        candidates = [path for path in archived if path.exists()]
        if self._active_path.exists():
            candidates.append(self._active_path)
        return tuple(candidates)

    def _active_identity(self) -> tuple[int, int] | None:
        """(inode, size) of the active file, or None when there is none.

        Appends only grow the file and rotation replaces it, so a change to
        either component means the cached tail digest is stale.  Neither can
        return to an earlier value while this object holds the process lock.
        """

        try:
            status = os.stat(self._active_path)
        except FileNotFoundError:
            return None
        return (status.st_ino, status.st_size)

    def _last_digest(self) -> str | None:
        """Digest of the final record, cached across appends.

        Reading and splitting the whole active file on every append made
        appending O(n) in the length of the generation: a log filling its
        default one-megabyte generation re-read up to a megabyte per record.
        The cache reduces the steady-state cost to one ``stat``, and a miss
        reads only the end of the file rather than all of it.
        """

        identity = self._active_identity()
        if identity is None:
            self._tail_cache = None
            return None
        if self._tail_cache is not None and self._tail_cache[0] == identity:
            return self._tail_cache[1]

        raw_line = _read_last_nonempty_line(self._active_path)
        digest: str | None = None
        if raw_line is not None:
            try:
                digest = json.loads(raw_line.decode("utf-8"))["sha256"]
            except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
                raise ValueError("active log tail is not a complete record") from exc
        self._tail_cache = (identity, digest)
        return digest

    def _rotate_if_needed(self) -> None:
        if not self._active_path.exists():
            return
        if self._active_path.stat().st_size < self._max_generation_bytes:
            return
        oldest = self._root / f"events.{self._generations - 1}.jsonl"
        oldest.unlink(missing_ok=True)
        for index in range(self._generations - 1, 1, -1):
            source = self._root / f"events.{index - 1}.jsonl"
            if source.exists():
                os.replace(source, self._root / f"events.{index}.jsonl")
        os.replace(self._active_path, self._root / "events.1.jsonl")
        fsync_directory(self._root)
        self._tail_cache = None

    def _recover_incomplete_final_line(self) -> None:
        """Repair or drop a final line left without its newline by a crash.

        A missing newline alone used to be left in place whenever the line
        still parsed as JSON, and the next append then concatenated onto it,
        producing one unreadable line and taking the whole generation with it:
        ``verified_records`` fails at that line and every later record sits
        behind the failure.

        The two cases need different repairs, so the record is checked rather
        than assumed.  A line that is a complete record with a correct digest
        was fully written and only lost its terminator, so it is completed --
        discarding it would drop a record whose append had already returned.
        Anything else is a torn write and is truncated away.
        """

        path = self._active_path
        if not path.exists() or not path.stat().st_size:
            return
        data = path.read_bytes()
        if data.endswith(b"\n"):
            return
        line_start = data.rfind(b"\n") + 1
        if self._final_line_is_whole_record(data, line_start):
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_APPEND | getattr(os, "O_BINARY", 0),
                0o600,
            )
            try:
                write_all(descriptor, b"\n")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return
        descriptor = os.open(
            path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
        )
        try:
            write_all(descriptor, data[:line_start])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    @staticmethod
    def _final_line_is_whole_record(data: bytes, line_start: int) -> bool:
        """Whether the unterminated final line is an intact, chained record.

        Parsing alone is not enough: a torn write can leave bytes that still
        decode.  The record's own digest has to recompute, and it has to link
        to the line before it when there is one.
        """

        try:
            decoded = json.loads(data[line_start:].decode("utf-8"))
            payload = decoded["payload"]
            sha256 = decoded["sha256"]
            previous_sha256 = decoded["previous_sha256"]
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError):
            return False
        if not isinstance(payload, dict):
            return False
        try:
            if sha256 != _record_digest(payload, previous_sha256):
                return False
        except (TypeError, ValueError):
            return False
        preceding = data[:line_start].splitlines()
        for raw_line in reversed(preceding):
            if raw_line:
                try:
                    return json.loads(raw_line.decode("utf-8"))["sha256"] == previous_sha256
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError):
                    return False
        return True

    @contextmanager
    def _exclusive_process_lock(self) -> Iterator[None]:
        """Serialize reads and writes across processes on this machine."""

        descriptor = os.open(
            self._lock_path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600
        )
        try:
            set_private_file_mode(self._lock_path, descriptor)
            if os.name == "nt":
                # msvcrt locks bytes at the file position; an empty file has
                # none, so materialise one byte and rewind before locking.
                if os.lseek(descriptor, 0, os.SEEK_END) == 0:
                    write_all(descriptor, b"\0")
                    os.fsync(descriptor)
                os.lseek(descriptor, 0, os.SEEK_SET)
                unlock = _acquire_windows_lock(descriptor)
            else:
                import fcntl

                # getattr: fcntl attributes are POSIX-only in type stubs, so
                # direct attribute access fails type checking on Windows.
                flock = getattr(fcntl, "flock")
                flock(descriptor, getattr(fcntl, "LOCK_EX"))
                unlock = lambda: flock(descriptor, getattr(fcntl, "LOCK_UN"))  # noqa: E731
            try:
                yield
            finally:
                unlock()
        finally:
            os.close(descriptor)


def _acquire_windows_lock(descriptor: int) -> Callable[[], None]:
    """Wait through transient Windows sharing contention."""

    import msvcrt

    locking = getattr(msvcrt, "locking")
    nonblocking_lock = getattr(msvcrt, "LK_NBLCK")
    unlock_code = getattr(msvcrt, "LK_UNLCK")
    while True:
        try:
            locking(descriptor, nonblocking_lock, 1)
            break
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                raise
            time.sleep(0.05)
    return lambda: locking(descriptor, unlock_code, 1)
