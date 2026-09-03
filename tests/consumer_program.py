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
    load_default_cloud_config,
)


assert SecureTransport and ReliableOperation and RetryPolicy
assert SqliteOperationStore and TrustBundle and EntitlementDecision
default = load_default_cloud_config()
assert default.channel == "integration"
assert default.api_base_url.startswith("https://")
assert default.ca_bundle_pem.startswith(b"-----BEGIN CERTIFICATE-----")
assert len(default.license_public_key) == 32
assert importlib.util.find_spec("client") is None
assert str(Path(os.environ["FOUNDATION_SOURCE_ROOT"]).resolve()) not in {
    str(Path(path).resolve()) for path in sys.path if path
}
