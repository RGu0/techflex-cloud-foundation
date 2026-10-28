# Alibaba Cloud OSS object store

RAY-830 R3 (`object-storage`) moves the FeetForcePlate cloud's OSS adapter into
`techflex_cloud_foundation.aliyun_oss`. It is not exported from the package
root; import it from the module. It needs the `server` extra
(`alibabacloud-oss-v2`, `alibabacloud-credentials`), imported only when
`build_aliyun_oss_sdk` runs.

## What it is

`AliyunOSSObjectStore` implements `ImmutableObjectStore` on a bucket with
server-side encryption (`KMS` or `AES256`), the same boundary the filesystem and
in-memory stores implement, and it runs the same shared contract tests:

- `put_verified` checks the payload against the declared SHA-256 and size
  (`ObjectSizeMismatch`, `ObjectDigestMismatch`), then publishes only if the key
  is absent (`forbid_overwrite`). A key that already holds the same size, digest
  and encryption is an idempotent replay; anything else is `ObjectConflict`. A
  create that loses a race is validated against the winner.
- `read` returns the whole object after checking its encryption, size and the
  `sha256` metadata (`ObjectDigestMismatch`); a missing key raises
  `OSSObjectNotFound`, a `KeyError`, as the in-memory store does. `max_read_bytes`
  bounds a read. `read_chunks` yields the verified body in 1 MiB pieces; the
  gateway reads whole objects, so it bounds what the caller holds, not the
  adapter.
- `put_verified` also takes `content_type` (default `application/octet-stream`)
  and `extra_metadata`; the `sha256` entry is always the verified digest.
- Keys are opaque and caller-chosen. Empty, absolute, NUL-bearing and `..` keys
  are refused.

`AliyunOSSSDKGateway` is the one place that touches the SDK;
`build_aliyun_oss_object_store(settings)` composes it with refreshable ECS
RAM-role credentials. `settings` needs `oss_bucket`, `oss_region`,
`oss_endpoint`, `oss_ecs_ram_role` and `oss_server_side_encryption`.

## What did not move

- `put_segment`, `put_manifest` and `put_report_pdf`, and the
  `tenants/<id>/sessions/<id>/segments|manifests/...` key layout: product-aware
  wrappers over this boundary, moving with `ingestion-repository`.
- ffp's own `InMemoryObjectStore` and `FileSystemObjectStore`: the library's
  generic stores replace them.
- `S3ObjectStore`: not used by the seed or integration deployments (only shown in
  an example), so it is not carried over and `boto3` is not added.
- `LocalBasicPdfStore` (`report_copy`): moves with `access-plane-services`; it
  passes `max_read_bytes=8 MiB`, the limit the old OSS `read` hard-coded.
- `scripts/verify_aliyun_oss_live.py` and its tests: deployment scope.

An object written by the old adapter stays valid: validation compares size,
`sha256` metadata and encryption, which the old adapter set. New objects carry
the content type the caller passes (the old adapter chose one per kind of
object) and no longer carry the `schema-version` metadata entry unless the caller
adds it through `extra_metadata`.
