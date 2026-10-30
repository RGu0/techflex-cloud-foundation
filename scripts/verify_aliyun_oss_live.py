#!/usr/bin/env python3
"""Run redacted live checks against the private Aliyun OSS raw-object bucket."""

from __future__ import annotations

import argparse
from collections.abc import Callable
import hashlib
import json
import os
from pathlib import Path
import tempfile
from urllib.parse import urlparse
from uuid import uuid4

import httpx

from techflex_cloud_foundation.aliyun_oss import build_aliyun_oss_sdk
from techflex_cloud_foundation.server.seed import SeedSettings


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def _service_error(sdk: object, exc: Exception) -> object | None:
    if isinstance(exc, sdk.exceptions.ServiceError):
        return exc
    unwrapped = exc.unwrap()
    if isinstance(unwrapped, sdk.exceptions.ServiceError):
        return unwrapped
    return None


def _default_public_probe(url: str) -> int:
    try:
        return httpx.get(url, timeout=10.0, follow_redirects=False).status_code
    except httpx.HTTPError as exc:
        raise RuntimeError("anonymous OSS access probe failed") from exc


def audit_aliyun_oss(
    client: object,
    sdk: object,
    settings: object,
    *,
    public_probe: Callable[[str], int] = _default_public_probe,
    payload: bytes | None = None,
) -> dict[str, bool | int]:
    """Verify policy and a versioned round trip without returning identifiers."""

    bucket = settings.oss_bucket
    encryption = settings.oss_server_side_encryption
    acl = client.get_bucket_acl(sdk.GetBucketAclRequest(bucket=bucket)).acl
    _require(acl == "private", "OSS bucket must be private")

    versioning = client.get_bucket_versioning(
        sdk.GetBucketVersioningRequest(bucket=bucket)
    ).version_status
    _require(versioning == "Enabled", "OSS bucket versioning must be enabled")

    encryption_result = client.get_bucket_encryption(
        sdk.GetBucketEncryptionRequest(bucket=bucket)
    )
    encryption_rule = encryption_result.server_side_encryption_rule
    default_encryption = (
        encryption_rule.apply_server_side_encryption_by_default.sse_algorithm
        if encryption_rule is not None
        and encryption_rule.apply_server_side_encryption_by_default is not None
        else None
    )
    _require(
        default_encryption == encryption,
        "OSS bucket default encryption does not match service encryption",
    )

    lifecycle_result = client.get_bucket_lifecycle(
        sdk.GetBucketLifecycleRequest(bucket=bucket)
    )
    configuration = lifecycle_result.lifecycle_configuration
    rules = list(configuration.rules or []) if configuration is not None else []
    enabled_rules = [rule for rule in rules if rule.status == "Enabled"]
    tenant_rules = [
        rule
        for rule in enabled_rules
        if (rule.prefix or "") in {"", "tenants/"}
        and (rule.expiration is not None or rule.transitions)
    ]
    noncurrent_rules = [
        rule
        for rule in tenant_rules
        if rule.noncurrent_version_expiration is not None
        or rule.noncurrent_version_transitions
    ]
    _require(bool(tenant_rules), "OSS lifecycle must manage tenant objects")
    _require(
        bool(noncurrent_rules),
        "OSS lifecycle must manage noncurrent object versions",
    )

    value = payload if payload is not None else os.urandom(64)
    digest = hashlib.sha256(value).hexdigest()
    key = f"tenants/{uuid4()}/acceptance/{uuid4()}.bin"
    request = sdk.PutObjectRequest(
        bucket=bucket,
        key=key,
        body=value,
        content_type="application/octet-stream",
        metadata={"sha256": digest, "schema-version": "acceptance/1"},
        forbid_overwrite=True,
        server_side_encryption=encryption,
    )
    first_upload = client.put_object(request)
    first_version_id = getattr(first_upload, "version_id", None)

    object_listing_denied = False
    object_digest_verified = False
    public_object_access_denied = False
    synthetic_delete_marker_created = False
    versioned_overwrite_preserved = False
    try:
        _require(bool(first_version_id), "OSS initial upload did not create a version")
        second_upload = client.put_object(request)
        second_version_id = getattr(second_upload, "version_id", None)
        versioned_overwrite_preserved = bool(
            second_version_id and second_version_id != first_version_id
        )
        _require(
            versioned_overwrite_preserved,
            "OSS versioned replay did not preserve a distinct object version",
        )

        head = client.head_object(sdk.HeadObjectRequest(bucket=bucket, key=key))
        _require(head.content_length == len(value), "OSS object size mismatch")
        _require(
            dict(head.metadata or {}).get("sha256") == digest,
            "OSS object digest metadata mismatch",
        )
        _require(
            head.server_side_encryption == encryption,
            "OSS object encryption mismatch",
        )

        result = client.get_object(sdk.GetObjectRequest(bucket=bucket, key=key))
        _require(result.body is not None, "OSS object response body is missing")
        try:
            downloaded = result.body.read()
        finally:
            result.body.close()
        object_digest_verified = hashlib.sha256(downloaded).hexdigest() == digest
        _require(object_digest_verified, "OSS object body digest mismatch")

        endpoint_host = urlparse(settings.oss_endpoint).hostname
        _require(endpoint_host is not None, "OSS endpoint host is missing")
        unsigned_url = f"https://{bucket}.{endpoint_host}/{key}"
        public_object_access_denied = public_probe(unsigned_url) == 403
        _require(public_object_access_denied, "public OSS object access was not denied")

        try:
            client.list_objects_v2(
                sdk.ListObjectsV2Request(bucket=bucket, prefix="tenants/", max_keys=1)
            )
        except (sdk.exceptions.ServiceError, sdk.exceptions.OperationError) as exc:
            service_error = _service_error(sdk, exc)
            object_listing_denied = (
                service_error is not None
                and service_error.status_code == 403
                and service_error.code == "AccessDenied"
            )
        _require(object_listing_denied, "OSS service role can list tenant objects")
    finally:
        deletion = client.delete_object(sdk.DeleteObjectRequest(bucket=bucket, key=key))
        synthetic_delete_marker_created = bool(
            getattr(deletion, "delete_marker", False)
            and getattr(deletion, "version_id", None)
        )

    _require(
        synthetic_delete_marker_created,
        "OSS versioned delete did not create a delete marker",
    )
    return {
        "bucket_acl_private": True,
        "bucket_default_encryption_verified": True,
        "bucket_versioning_enabled": True,
        "lifecycle_noncurrent_versions_managed": True,
        "lifecycle_rule_count": len(enabled_rules),
        "lifecycle_tenant_objects_managed": True,
        "object_digest_verified": object_digest_verified,
        "object_listing_denied": object_listing_denied,
        "public_object_access_denied": public_object_access_denied,
        "synthetic_delete_marker_created": synthetic_delete_marker_created,
        "versioned_overwrite_preserved": versioned_overwrite_preserved,
    }


def _write_evidence(path: Path, evidence: dict[str, bool | int]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}."
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(evidence, stream, indent=2, sort_keys=True)
            stream.write("\n")
        temporary_path.chmod(0o600)
        temporary_path.replace(path)
    finally:
        temporary_path.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    settings = SeedSettings.from_env()
    if settings.object_backend != "aliyun-oss":
        raise RuntimeError("live OSS acceptance requires the aliyun-oss backend")
    client, sdk = build_aliyun_oss_sdk(settings)
    evidence = audit_aliyun_oss(client, sdk, settings)
    _write_evidence(args.output, evidence)
    print(f"aliyun_oss_acceptance=passed evidence={args.output} secrets=not-printed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
