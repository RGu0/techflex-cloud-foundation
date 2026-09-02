"""Fault-injection building blocks for durability tests.

Each fault patches one ``os`` primitive for the duration of a ``with``
block and always restores it, so adversarial tests compose without a
framework dependency.  These fixtures exist so every consumer of the
durability modules tests the same failure modes — power loss mid-write,
torn atomic renames, fsync failure, and disk full — instead of each
application inventing its own subset.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
import errno
import os
import subprocess
import time


class FaultInjection:
    """Context manager patching ``holder.name`` with a failing replacement."""

    def __init__(self, holder: object, name: str, replacement: Callable[..., object]) -> None:
        self._holder = holder
        self._name = name
        self._replacement = replacement
        self._original: Callable[..., object] | None = None

    def install(self) -> None:
        if self._original is not None:
            raise ValueError("fault already installed")
        original = getattr(self._holder, self._name)
        self._original = original
        setattr(self._holder, self._name, self._replacement)

    def restore(self) -> None:
        if self._original is None:
            return
        setattr(self._holder, self._name, self._original)
        self._original = None

    def __enter__(self) -> "FaultInjection":
        self.install()
        return self

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None:
        self.restore()


def short_write_os(max_chunk: int) -> FaultInjection:
    """Patch ``os.write`` so every call writes at most ``max_chunk`` bytes."""

    if max_chunk < 1:
        raise ValueError("max_chunk must be positive")
    real_write = os.write

    def short_write(descriptor: int, data: bytes | memoryview) -> int:
        return real_write(descriptor, data[:max_chunk])

    return FaultInjection(os, "write", short_write)


def interrupted_replace(
    *, exception_factory: Callable[[], BaseException] | None = None
) -> FaultInjection:
    """Patch ``os.replace`` to fail, simulating an interrupted atomic rename."""

    factory = exception_factory or (lambda: OSError(errno.EIO, "simulated rename interruption"))

    def failing_replace(source: object, destination: object) -> None:
        raise factory()

    return FaultInjection(os, "replace", failing_replace)


def fsync_failure(
    *, exception_factory: Callable[[], BaseException] | None = None
) -> FaultInjection:
    """Patch ``os.fsync`` to fail, simulating a flush that never persisted."""

    factory = exception_factory or (lambda: OSError(errno.EIO, "simulated fsync failure"))

    def failing_fsync(descriptor: int) -> None:
        raise factory()

    return FaultInjection(os, "fsync", failing_fsync)


def disk_full(
    *, exception_factory: Callable[[], BaseException] | None = None
) -> FaultInjection:
    """Patch ``os.write`` to raise ENOSPC, simulating a full device."""

    factory = exception_factory or (
        lambda: OSError(errno.ENOSPC, "No space left on device (simulated)")
    )

    def full_write(descriptor: int, data: bytes | memoryview) -> int:
        raise factory()

    return FaultInjection(os, "write", full_write)


class SimulatedPowerLoss(FaultInjection):
    """Raise on the Nth call of any function, simulating power loss there.

    Wraps a chosen boundary — for example a store's commit method — and
    raises ``exception_factory()`` (default ``SystemExit``) when the Nth
    call arrives, leaving whatever was written before that point on disk.
    """

    def __init__(
        self,
        holder: object,
        name: str,
        *,
        on_call: int = 1,
        exception_factory: Callable[[], BaseException] | None = None,
    ) -> None:
        if on_call < 1:
            raise ValueError("on_call must be positive")
        factory = exception_factory or (lambda: SystemExit("simulated power loss"))
        original = getattr(holder, name)
        calls = {"count": 0}

        def boundary(*args: object, **kwargs: object) -> object:
            calls["count"] += 1
            if calls["count"] == on_call:
                raise factory()
            return original(*args, **kwargs)

        super().__init__(holder, name, boundary)
        self._call_count = calls

    @property
    def calls(self) -> int:
        return self._call_count["count"]


@dataclass(frozen=True, slots=True)
class KillAndRecoverResult:
    """Outcome of one kill-and-recover run, for caller assertions."""

    child_returncode: int
    recovery_completed: bool


class KillAndRecoverHarness:
    """Kill a child process mid-flight, then run the recovery path.

    ``spawn`` starts the child; ``ready`` polls until the child has reached
    the state worth interrupting; the harness then kills the child
    (SIGKILL semantics), waits for it, and invokes ``recover``.  The caller
    asserts on whatever invariants the recovery path must restore.
    """

    def __init__(
        self,
        spawn: Callable[[], subprocess.Popen[bytes]],
        ready: Callable[[], bool],
        recover: Callable[[], None],
        *,
        ready_timeout_seconds: float = 30.0,
        poll_interval_seconds: float = 0.05,
    ) -> None:
        self._spawn = spawn
        self._ready = ready
        self._recover = recover
        self._ready_timeout = ready_timeout_seconds
        self._poll_interval = poll_interval_seconds

    def run(self) -> KillAndRecoverResult:
        process = self._spawn()
        try:
            deadline = time.monotonic() + self._ready_timeout
            while not self._ready():
                if time.monotonic() > deadline:
                    raise TimeoutError("child process never reached the ready state")
                if process.poll() is not None:
                    raise RuntimeError(
                        f"child process exited early with {process.returncode}"
                    )
                time.sleep(self._poll_interval)
            process.kill()
            process.wait()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        self._recover()
        return KillAndRecoverResult(process.returncode or 0, True)


def run_child_command(command: Sequence[str]) -> subprocess.Popen[bytes]:
    """Spawn a child process for the kill-and-recover harness."""

    if not command:
        raise ValueError("command must not be empty")
    return subprocess.Popen(list(command))
