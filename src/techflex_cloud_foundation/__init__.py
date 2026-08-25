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
    "EntitlementDecision",
    "EntitlementResolver",
    "HealthProbe",
    "LicenseLifecycle",
    "LicenseRecord",
    "LicenseState",
    "MetricsSink",
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
]
