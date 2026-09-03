"""Getting-started example: a complete offline pass through the foundation.

This file is the executable companion to docs/getting-started.md.  It runs
against the installed wheel with no network and no source tree, which is what
makes the quickstart trustworthy: CI executes exactly these lines.

The flow mirrors what an application does before its first real upload:
resolve the default cloud configuration, stage a payload crash-safely,
describe it with a content-addressed manifest, seal it at rest, and queue the
upload as a reliable operation.
"""

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
