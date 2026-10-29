#!/usr/bin/env python3
"""Export referenced OSS objects into a backup staging directory (RAY-405).

The deployment's RAM role grants per-object reads but not bucket listing
(least privilege), so the object keys are enumerated from the database — every
segment and manifest records its object key — and each key is downloaded with
the same credentials and settings the service uses.  Manifest lines are
``sha256  key`` so the encrypted backup bundle keeps covering objects after
the storage backend moved off the local disk.  No identifier is printed;
secrets never leave the environment.
"""

from __future__ import annotations

import argparse
import asyncio
from collections.abc import Iterable
import hashlib
import os
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from cloud.api.seed import SeedSettings  # noqa: E402
from cloud.ingestion.aliyun_oss import build_aliyun_oss_sdk  # noqa: E402

_CHUNK = 1024 * 1024


async def referenced_object_keys(backup_dsn: str) -> tuple[list[str], frozenset[str]]:
    import asyncpg

    connection = await asyncpg.connect(backup_dsn)
    try:
        rows = await connection.fetch(
            """
            SELECT object_key FROM screening.session_segments
            UNION
            SELECT object_key FROM screening.session_manifests
            """
        )
        report_rows = await connection.fetch(
            "SELECT pdf_object_key FROM reporting.local_basic_report_copies"
        )
    finally:
        await connection.close()
    required_report_keys = frozenset(row["pdf_object_key"] for row in report_rows)
    return sorted({row["object_key"] for row in rows} | required_report_keys), required_report_keys


def _read_chunks(stream: object) -> Iterable[bytes]:
    read = getattr(stream, "read", None)
    if callable(read):
        try:
            data = read(_CHUNK)
        except TypeError:
            # OSS SDK v2 StreamBodyReader.read() takes no size argument.
            data = read()
        if not data:
            return
        yield data
        return
    yield from stream


def export_bucket_objects(client: object, sdk: object, bucket: str, keys: Iterable[str],
                          output_dir: Path, manifest_path: Path,
                          required_oss_keys: frozenset[str] = frozenset()) -> int:
    count = 0
    with manifest_path.open("a", encoding="utf-8") as manifest:
        for key in keys:
            target = output_dir / key
            if (
                not key
                or key.startswith(("/", "\\"))
                or ".." in Path(key).parts
                or "\\" in key
            ):
                raise RuntimeError(f"object key escapes staging root: {key!r}")
            try:
                result = client.get_object(sdk.GetObjectRequest(bucket=bucket, key=key))
            except Exception as exc:  # noqa: BLE001 - classified below
                if "NoSuchKey" in str(exc):
                    if key in required_oss_keys:
                        raise RuntimeError("referenced report PDF is absent from OSS") from exc
                    # Pre-OSS-era objects live in the legacy local tree, which
                    # the backup already includes; keys absent from OSS are
                    # simply not fetched from here.
                    continue
                raise
            target.parent.mkdir(parents=True, exist_ok=True)
            target.parent.chmod(0o700)
            digest = hashlib.sha256()
            flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
            descriptor = os.open(target, flags, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                for chunk in _read_chunks(result.body):
                    handle.write(chunk)
                    digest.update(chunk)
            manifest.write(f"{digest.hexdigest()}  {key}\n")
            count += 1
    return count


def export_objects(output_dir: Path, manifest_path: Path) -> int:
    settings = SeedSettings.from_env()
    if settings.object_backend != "aliyun-oss":
        raise RuntimeError("oss backup export requires the aliyun-oss backend")
    backup_dsn = os.environ["FEETFORCEPLATE_BACKUP_DSN"]
    keys, required_report_keys = asyncio.run(referenced_object_keys(backup_dsn))
    client, sdk = build_aliyun_oss_sdk(settings)
    return export_bucket_objects(client, sdk, settings.oss_bucket, keys,
                                 output_dir, manifest_path,
                                 required_oss_keys=required_report_keys)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    arguments = parser.parse_args()
    count = export_objects(arguments.output_dir, arguments.manifest)
    print(f"oss_backup_objects_exported={count}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
