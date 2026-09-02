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


def _canonical_json_bytes(payload: Mapping[str, object]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def _record_digest(payload: Mapping[str, object], previous_sha256: str | None) -> str:
    previous = bytes.fromhex(previous_sha256) if previous_sha256 else b""
    return hashlib.sha256(_canonical_json_bytes(payload) + previous).hexdigest()


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
                self._active_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600
            )
            try:
                set_private_file_mode(self._active_path, descriptor)
                write_all(descriptor, line)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
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

    def _last_digest(self) -> str | None:
        if not self._active_path.exists():
            return None
        lines = self._active_path.read_bytes().splitlines()
        for raw_line in reversed(lines):
            if raw_line:
                try:
                    return json.loads(raw_line.decode("utf-8"))["sha256"]
                except (UnicodeDecodeError, json.JSONDecodeError, KeyError) as exc:
                    raise ValueError("active log tail is not a complete record") from exc
        return None

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

    def _recover_incomplete_final_line(self) -> None:
        path = self._active_path
        if not path.exists() or not path.stat().st_size:
            return
        data = path.read_bytes()
        if data.endswith(b"\n"):
            return
        line_start = data.rfind(b"\n") + 1
        try:
            json.loads(data[line_start:].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            descriptor = os.open(path, os.O_WRONLY | os.O_TRUNC, 0o600)
            try:
                write_all(descriptor, data[:line_start])
                os.fsync(descriptor)
            finally:
                os.close(descriptor)

    @contextmanager
    def _exclusive_process_lock(self) -> Iterator[None]:
        """Serialize reads and writes across processes on this machine."""

        descriptor = os.open(self._lock_path, os.O_RDWR | os.O_CREAT, 0o600)
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
