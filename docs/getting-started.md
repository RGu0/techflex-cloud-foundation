# Getting Started

Audience: an engineer or agent integrating `techflex-cloud-foundation` into a
new application for the first time. Everything on this page is executable —
the example below is `docs/examples/getting_started.py`, which CI runs
against the built wheel (`tests/test_wheel_consumer.py`).

## Install

Applications consume the released, versioned wheel; they never vendor or
patch the source tree.

```toml
# pyproject.toml of the consuming application
[project]
dependencies = [
  "techflex-cloud-foundation @ https://github.com/RGu0/techflex-cloud-foundation/releases/download/<release>/techflex_cloud_foundation-<version>-py3-none-any.whl",
]
```

Rules:

- Pin an exact version; upgrade deliberately after reading `CHANGELOG.md`.
- The v1 public API is exactly the symbols in
  `techflex_cloud_foundation/__init__.py::__all__`. Anything reachable only
  via submodule attributes is private and may change without notice.
- Requires Python >= 3.11. Optional extra `server` pulls the async PostgreSQL
  driver for service-side deployments.

## Zero-config development: the vendored integration default

The wheel carries one public default cloud configuration — the `integration`
channel — so development, testing, and seed-stage runs need no local setup:

```python
from techflex_cloud_foundation import load_default_cloud_config

config = load_default_cloud_config()      # channel="integration"
config.api_base_url                       # integration entrypoint
config.ca_bundle_pem                      # PEM bytes for TLS verification
config.license_public_key                 # raw 32-byte license verification key
```

Semantics that are enforced in code, not just documented:

- `load_default_cloud_config(channel=...)` only resolves channels vendored in
  the wheel. Any other channel raises `CloudConfigChannelUnknown`; the
  library never guesses an endpoint.
- The integration default is **not** production ingress (integration IP,
  private CA, nonstandard port — RAY-341 invariants).
- To use your own environment, validate your own document through
  `parse_cloud_default_config()` — the same validator the vendored bundle
  passes through — and supply your own resource bytes:

```python
import json
from techflex_cloud_foundation import parse_cloud_default_config

meta = parse_cloud_default_config(json.loads(my_config_path.read_text()))
config = meta.resolve(lambda name: (my_config_dir / name).read_bytes())
```

- Production material (private keys, production endpoints, production CAs) is
  never vendored into this library.

## Minimal end-to-end pass (offline)

The example walks the exact path an application takes before its first real
upload. Run it from a checkout with `./dev test` coverage, or standalone:

```bash
uv run --locked python docs/examples/getting_started.py
# quickstart ok: https://39.105.216.113:7443 654e356d9cc0
```

```python
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile

from techflex_cloud_foundation import (
    AesGcmSealEncryptor,
    ArtifactEntry,
    ArtifactManifest,
    FileKeyProvider,
    ReliableOperation,
    SqliteOperationStore,
    atomic_write,
    load_default_cloud_config,
    read_sealed,
    verify_entry_payload,
    write_sealed,
)


def main() -> None:
    workspace = Path(tempfile.mkdtemp(prefix="foundation-quickstart-"))

    # 1. Default cloud configuration — the vendored integration channel.
    config = load_default_cloud_config()
    assert config.channel == "integration"
    assert config.api_base_url.startswith("https://")
    assert config.ca_bundle_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert len(config.license_public_key) == 32

    # 2. Stage a payload crash-safely; a crash never leaves a partial file.
    payload = b"example measurement bytes"
    staged = workspace / "payload.bin"
    atomic_write(staged, payload)

    # 3. Describe the payload with a content-addressed manifest.
    manifest = ArtifactManifest(
        entries=(
            ArtifactEntry(
                path="payload.bin",
                size=len(payload),
                sha256=hashlib.sha256(payload).hexdigest(),
            ),
        ),
        artifact_kind="example.measurement",
    )
    verify_entry_payload(manifest.entries[0], [staged.read_bytes()])
    assert len(manifest.digest()) == 64

    # 4. Seal the payload at rest with a locally held key.  Provisioning is
    #    explicit: get_key() reads, create_key() writes.  A provider that
    #    invented a key when it could not find one would turn a missed backup
    #    into unreadable data instead of a visible failure.
    key_provider = FileKeyProvider(workspace / "local.key")
    key_provider.create_key()
    encryptor = AesGcmSealEncryptor(key_provider)
    sealed = workspace / "payload.sealed"
    write_sealed(
        sealed,
        staged.read_bytes(),
        header={"artifact_digest": manifest.digest()},
        encryptor=encryptor,
    )
    _, plaintext = read_sealed(sealed, encryptor)
    assert plaintext == payload

    # 5. Queue the upload as a reliable operation; recovery replays it
    #    idempotently after any interruption.
    store = SqliteOperationStore(workspace / "operations.sqlite3")
    operation = ReliableOperation.create(
        kind="example.upload",
        payload_ref=str(sealed),
        payload_digest=manifest.digest(),
        idempotency_key=f"example:{manifest.digest()}",
    )
    store.enqueue(operation)
    assert store.lease_due(now=operation.created_at) == operation

    print("quickstart ok:", config.api_base_url, manifest.digest()[:12])


if __name__ == "__main__":
    main()
```

The file `docs/examples/getting_started.py` is the source of truth for this
listing and is executed in CI; the listing above is a copy. If they ever
disagree, trust the file.

What each step establishes:

1. **Default config** — which channel, entrypoint, CA, and license key this
   build trusts.
2. **Crash-safe staging** — `atomic_write` never leaves a partial payload
   file after a crash.
3. **Content-addressed manifest** — `ArtifactManifest` commits to every byte
   via complete SHA-256 digests; `manifest.digest()` is the artifact's own
   address and its idempotency anchor.
4. **At-rest sealing** — `write_sealed`/`read_sealed` encrypt the staged
   payload with a locally held 32-byte key (`FileKeyProvider`), provisioned
   once with `create_key()`; afterwards a missing key file raises
   `KeyNotProvisioned` rather than silently becoming a different key.
5. **Reliable upload queue** — `SqliteOperationStore` persists the operation;
   after any interruption, recovery replays it idempotently under the same
   `idempotency_key`.

## What this page deliberately omits

Real uploads (server begin/put/complete), License activation, and tenant
context require the cloud side and a product profile; they are covered by the
[integration guides](guides/) (RAY-367 scope `docs-integration-guides`).
The error catalogue and application/library boundary are covered by the
boundaries & troubleshooting guide (scope
`docs-boundaries-troubleshooting`).
