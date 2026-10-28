"""Database schema delivery: the ordered migration plan and its runner.

The SQL under ``sql/`` is the FeetForcePlate cloud schema (0001-0016) carried
over byte for byte; ``0017`` adds the ledger that records what was applied.
"""

from .plan import (
    DEFAULT_PLAN,
    MigrationPlanError,
    MigrationStep,
    Probe,
    load_step_sql,
)
from .runner import (
    ChecksumMismatch,
    MigrationError,
    MigrationReport,
    RoleMissing,
    apply_migrations,
    migration_status,
)

__all__ = [
    "DEFAULT_PLAN",
    "ChecksumMismatch",
    "MigrationError",
    "MigrationPlanError",
    "MigrationReport",
    "MigrationStep",
    "Probe",
    "RoleMissing",
    "apply_migrations",
    "load_step_sql",
    "migration_status",
]
