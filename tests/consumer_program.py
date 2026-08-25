from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import sys

from techflex_cloud_foundation import (
    EntitlementDecision,
    ReliableOperation,
    RetryPolicy,
    SecureTransport,
    SqliteOperationStore,
    TrustBundle,
)


assert SecureTransport and ReliableOperation and RetryPolicy
assert SqliteOperationStore and TrustBundle and EntitlementDecision
assert importlib.util.find_spec("client") is None
assert str(Path(os.environ["FOUNDATION_SOURCE_ROOT"]).resolve()) not in {
    str(Path(path).resolve()) for path in sys.path if path
}
