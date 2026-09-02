"""Stable, business-neutral cloud foundation interfaces.

Only symbols imported here are part of the v1 public API.
"""

from .database import DatabaseRuntime, HealthProbe, TransactionScope
from .diagnostics import AuditSink, MetricsSink
from .entitlement import (
    EntitlementDecision,
    EntitlementResolver,
    LicenseLifecycle,
    LicenseRecord,
    LicenseState,
    SignedTrustBundle,
    TrustBundle,
    TrustBundleVerifier,
)
from .local_sqlite import (
    DurableConnection,
    LocalSqlitePolicy,
    LocalSqliteStatus,
    Migration,
    UserVersionMigrator,
    connect_durable,
    inspect_durability,
)
from .reliability import (
    OperationHandler,
    OperationState,
    OperationStore,
    ReliableOperation,
    RetryPolicy,
    SqliteOperationStore,
)
from .transport import AuthorizedTransport, CredentialVault, SecureTransport, TokenProvider

__all__ = [
    "AuditSink",
    "AuthorizedTransport",
    "CredentialVault",
    "DatabaseRuntime",
    "DurableConnection",
    "EntitlementDecision",
    "EntitlementResolver",
    "HealthProbe",
    "LicenseLifecycle",
    "LicenseRecord",
    "LicenseState",
    "LocalSqlitePolicy",
    "LocalSqliteStatus",
    "MetricsSink",
    "Migration",
    "OperationHandler",
    "OperationState",
    "OperationStore",
    "ReliableOperation",
    "RetryPolicy",
    "SecureTransport",
    "SignedTrustBundle",
    "SqliteOperationStore",
    "TokenProvider",
    "TransactionScope",
    "TrustBundle",
    "TrustBundleVerifier",
    "UserVersionMigrator",
    "connect_durable",
    "inspect_durability",
]
