from __future__ import annotations

import hashlib
from types import SimpleNamespace

import pytest

from scripts.verify_aliyun_oss_live import audit_aliyun_oss


class _Body:
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.closed = False

    def read(self) -> bytes:
        return self.payload

    def close(self) -> None:
        self.closed = True


class _SDK:
    class GetBucketAclRequest(SimpleNamespace):
        pass

    class GetBucketVersioningRequest(SimpleNamespace):
        pass

    class GetBucketEncryptionRequest(SimpleNamespace):
        pass

    class GetBucketLifecycleRequest(SimpleNamespace):
        pass

    class PutObjectRequest(SimpleNamespace):
        pass

    class HeadObjectRequest(SimpleNamespace):
        pass

    class GetObjectRequest(SimpleNamespace):
        pass

    class DeleteObjectRequest(SimpleNamespace):
        pass

    class ListObjectsV2Request(SimpleNamespace):
        pass

    class ServiceError(Exception):
        def __init__(self, status_code: int, code: str) -> None:
            self.status_code = status_code
            self.code = code

    class OperationError(Exception):
        def __init__(self, error: Exception) -> None:
            self._error = error

        def unwrap(self) -> Exception:
            return self._error


class _Client:
    def __init__(self) -> None:
        self.payload: bytes | None = None
        self.metadata: dict[str, str] = {}
        self.encryption = "KMS"
        self.body: _Body | None = None
        self.version_ids: list[str] = []

    def get_bucket_acl(self, _request):
        return SimpleNamespace(acl="private")

    def get_bucket_versioning(self, _request):
        return SimpleNamespace(version_status="Enabled")

    def get_bucket_encryption(self, _request):
        default = SimpleNamespace(sse_algorithm="KMS")
        rule = SimpleNamespace(apply_server_side_encryption_by_default=default)
        return SimpleNamespace(server_side_encryption_rule=rule)

    def get_bucket_lifecycle(self, _request):
        rule = SimpleNamespace(
            status="Enabled",
            prefix="tenants/",
            expiration=SimpleNamespace(days=365),
            transitions=None,
            noncurrent_version_expiration=SimpleNamespace(noncurrent_days=30),
            noncurrent_version_transitions=None,
        )
        configuration = SimpleNamespace(rules=[rule])
        return SimpleNamespace(lifecycle_configuration=configuration)

    def put_object(self, request):
        self.payload = request.body
        self.metadata = request.metadata
        self.encryption = request.server_side_encryption
        version_id = f"version-{len(self.version_ids) + 1}"
        self.version_ids.append(version_id)
        return SimpleNamespace(version_id=version_id)

    def head_object(self, _request):
        return SimpleNamespace(
            content_length=len(self.payload or b""),
            metadata=self.metadata,
            server_side_encryption=self.encryption,
        )

    def get_object(self, _request):
        self.body = _Body(self.payload or b"")
        return SimpleNamespace(body=self.body)

    def list_objects_v2(self, _request):
        raise _SDK.OperationError(_SDK.ServiceError(403, "AccessDenied"))

    def delete_object(self, _request):
        return SimpleNamespace(version_id="delete-marker-1", delete_marker=True)


_SDK.exceptions = SimpleNamespace(
    OperationError=_SDK.OperationError,
    ServiceError=_SDK.ServiceError,
)


def _settings() -> SimpleNamespace:
    return SimpleNamespace(
        oss_bucket="private-raw",
        oss_endpoint="https://oss-us-west-1-internal.aliyuncs.com",
        oss_server_side_encryption="KMS",
    )


def test_live_audit_proves_private_lifecycle_integrity_and_least_privilege() -> None:
    client = _Client()

    evidence = audit_aliyun_oss(
        client,
        _SDK,
        _settings(),
        public_probe=lambda _url: 403,
        payload=b"ray-97-live-integrity",
    )

    assert evidence == {
        "bucket_acl_private": True,
        "bucket_default_encryption_verified": True,
        "bucket_versioning_enabled": True,
        "lifecycle_noncurrent_versions_managed": True,
        "lifecycle_rule_count": 1,
        "lifecycle_tenant_objects_managed": True,
        "object_digest_verified": True,
        "object_listing_denied": True,
        "public_object_access_denied": True,
        "synthetic_delete_marker_created": True,
        "versioned_overwrite_preserved": True,
    }
    assert client.version_ids == ["version-1", "version-2"]
    assert client.body is not None and client.body.closed is True


@pytest.mark.parametrize(
    ("attribute", "value", "message"),
    [
        ("acl", "public-read", "private"),
        ("version_status", "Suspended", "versioning"),
        ("sse_algorithm", "AES256", "encryption"),
    ],
)
def test_live_audit_rejects_unsafe_bucket_policy(
    attribute: str, value: str, message: str
) -> None:
    client = _Client()
    if attribute == "acl":
        client.get_bucket_acl = lambda _request: SimpleNamespace(acl=value)
    elif attribute == "version_status":
        client.get_bucket_versioning = lambda _request: SimpleNamespace(
            version_status=value
        )
    else:
        client.get_bucket_encryption = lambda _request: SimpleNamespace(
            server_side_encryption_rule=SimpleNamespace(
                apply_server_side_encryption_by_default=SimpleNamespace(
                    sse_algorithm=value
                )
            )
        )

    with pytest.raises(RuntimeError, match=message):
        audit_aliyun_oss(
            client,
            _SDK,
            _settings(),
            public_probe=lambda _url: 403,
            payload=b"payload",
        )


def test_live_audit_does_not_accept_digest_metadata_without_matching_body() -> None:
    client = _Client()
    original_get_object = client.get_object

    def corrupted_get_object(request):
        result = original_get_object(request)
        result.body.payload = b"corrupted"
        return result

    client.get_object = corrupted_get_object

    with pytest.raises(RuntimeError, match="digest"):
        audit_aliyun_oss(
            client,
            _SDK,
            _settings(),
            public_probe=lambda _url: 403,
            payload=b"payload",
        )


def test_payload_digest_is_not_exposed_in_public_evidence() -> None:
    payload = b"sensitive synthetic payload"
    evidence = audit_aliyun_oss(
        _Client(),
        _SDK,
        _settings(),
        public_probe=lambda _url: 403,
        payload=payload,
    )

    assert hashlib.sha256(payload).hexdigest() not in repr(evidence)
    assert "private-raw" not in repr(evidence)
    assert "aliyuncs.com" not in repr(evidence)
