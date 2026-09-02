"""Fault-injection fixtures for durability testing.

Shared, pytest-free building blocks for adversarial tests of local-first
persistence: simulated power loss at a chosen call boundary, short writes,
interrupted atomic renames, fsync failure, disk-full, and a
kill-and-recover harness that terminates a child process mid-flight and
then runs the recovery path.  Each fault is a context manager that
restores the patched function on exit, so tests compose them without a
framework dependency.
"""

from .durability import (
    FaultInjection,
    KillAndRecoverHarness,
    KillAndRecoverResult,
    SimulatedPowerLoss,
    disk_full,
    fsync_failure,
    interrupted_replace,
    run_child_command,
    short_write_os,
)

__all__ = [
    "FaultInjection",
    "KillAndRecoverHarness",
    "KillAndRecoverResult",
    "SimulatedPowerLoss",
    "disk_full",
    "fsync_failure",
    "interrupted_replace",
    "run_child_command",
    "short_write_os",
]
