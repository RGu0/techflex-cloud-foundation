"""Alibaba Cloud OSS store and gateway.

The SDK-gateway tests below ``_SDK`` are the FeetForcePlate cloud tests as they
were. The store tests exercise the generic ``put_verified`` boundary that
replaces ``put_segment``/``put_manifest`` (RAY-830 ``object-storage``); the
product key layout and manifest canonicalisation move with ingestion.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
from types import SimpleNamespace

import pytest

from techflex_cloud_foundation.aliyun_oss import (
    AliyunOSSObjectStore,
    AliyunOSSSDKGateway,
    OSSHead,
    OSSObjectAlreadyExists,
    OSSObjectNotFound,
    build_aliyun_oss_object_store,
)
from techflex_cloud_foundation.object_store import (
    ObjectConflict,
    ObjectDigestMismatch,
    ObjectSizeMismatch,
    ObjectStoreError,
)


@dataclass(frozen=True)
class _Object:
    body: bytes
    content_type: str
    metadata: dict[str, str]
    server_side_encryption: str


class _Gateway:
    def __init__(self) -> None:
        self.objects: dict[str, _Object] = {}
        self.put_attempts = 0
        self.ready_checks = 0

    def put_immutable(
        self,
        *,
        key: str,
        body: bytes,
        content_type: str,
        metadata: dict[str, str],
        server_side_encryption: str,
    ) -> None:
        self.put_attempts += 1
        if key in self.objects:
            raise OSSObjectAlreadyExists(key)
        self.objects[key] = _Object(
            body=body,
            content_type=content_type,
            metadata=dict(metadata),
            server_side_encryption=server_side_encryption,
        )

    def head(self, key: str) -> OSSHead:
        if key not in self.objects:
            raise OSSObjectNotFound(key)
        value = self.objects[key]
        return OSSHead(
            size_bytes=len(value.body),
            metadata=value.metadata,
            server_side_encryption=value.server_side_encryption,
        )

    def delete(self, key: str) -> None:
        self.objects.pop(key, None)

    def get(self, key: str) -> bytes:
        return self.objects[key].body

    def check_ready(self) -> None:
        self.ready_checks += 1


async def _chunks(payload: bytes):  # type: ignore[no-untyped-def]
    yield payload[:2]
    yield payload[2:]


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _put(store: AliyunOSSObjectStore, key: str, payload: bytes, **kwargs):  # type: ignore[no-untyped-def]
    return store.put_verified(
        key, _chunks(payload), expected_sha256=_sha(payload), expected_size=len(payload), **kwargs
    )


def test_oss_object_is_immutable_and_kms_encrypted() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        payload = b"raw-segment"
        key = "tenants/t/sessions/s/segments/0-x.bin"

        stored = await _put(store, key, payload)

        assert (stored.object_key, stored.sha256, stored.size_bytes) == (
            key,
            _sha(payload),
            len(payload),
        )
        uploaded = gateway.objects[key]
        assert uploaded.body == payload
        assert uploaded.metadata == {"sha256": _sha(payload)}
        assert uploaded.content_type == "application/octet-stream"
        assert uploaded.server_side_encryption == "KMS"

    asyncio.run(exercise())


def test_oss_content_type_and_extra_metadata_never_replace_the_digest() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="AES256")
        payload = b"{}"

        await _put(
            store,
            "m/1.json",
            payload,
            content_type="application/json",
            extra_metadata={"schema-version": "session-manifest/1", "sha256": "f" * 64},
        )

        uploaded = gateway.objects["m/1.json"]
        assert uploaded.content_type == "application/json"
        assert uploaded.metadata == {
            "schema-version": "session-manifest/1",
            "sha256": _sha(payload),
        }

    asyncio.run(exercise())


def test_oss_same_digest_replay_is_idempotent() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        payload = b"same-segment"

        first = await _put(store, "k/1", payload)
        second = await _put(store, "k/1", payload)

        assert second == first
        assert len(gateway.objects) == 1
        assert gateway.put_attempts == 1

    asyncio.run(exercise())


def test_oss_existing_key_with_wrong_integrity_metadata_is_rejected() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        payload = b"expected"
        gateway.objects["k/1"] = _Object(
            body=b"different",
            content_type="application/octet-stream",
            metadata={"sha256": "0" * 64},
            server_side_encryption="KMS",
        )

        with pytest.raises(ObjectConflict):
            await _put(store, "k/1", payload)
        assert gateway.put_attempts == 0

    asyncio.run(exercise())


def test_oss_existing_key_with_other_encryption_is_rejected() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        payload = b"expected"
        gateway.objects["k/1"] = _Object(
            body=payload,
            content_type="application/octet-stream",
            metadata={"sha256": _sha(payload)},
            server_side_encryption="AES256",
        )

        with pytest.raises(ObjectConflict):
            await _put(store, "k/1", payload)

    asyncio.run(exercise())


def test_oss_race_on_create_is_validated_against_the_winner() -> None:
    async def exercise() -> None:
        payload = b"racing"

        class Racing(_Gateway):
            def head(self, key: str) -> OSSHead:
                if self.put_attempts == 0:
                    raise OSSObjectNotFound(key)
                return super().head(key)

            def put_immutable(self, **kwargs):  # type: ignore[no-untyped-def]
                self.objects[kwargs["key"]] = _Object(
                    body=payload,
                    content_type="x",
                    metadata={"sha256": _sha(payload)},
                    server_side_encryption="KMS",
                )
                self.put_attempts += 1
                raise OSSObjectAlreadyExists(kwargs["key"])

        store = AliyunOSSObjectStore(Racing(), server_side_encryption="KMS")
        stored = await _put(store, "k/1", payload)
        assert stored.sha256 == _sha(payload)

    asyncio.run(exercise())


def test_oss_payload_is_verified_before_anything_is_written() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        payload = b"payload"
        with pytest.raises(ObjectSizeMismatch):
            await store.put_verified(
                "k/1", _chunks(payload), expected_sha256=_sha(payload), expected_size=1
            )
        with pytest.raises(ObjectDigestMismatch):
            await store.put_verified(
                "k/2", _chunks(payload), expected_sha256="0" * 64, expected_size=len(payload)
            )
        assert gateway.put_attempts == 0 and not gateway.objects

    asyncio.run(exercise())


def test_oss_read_verifies_encryption_size_and_digest() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        payload = b"x" * 10
        await _put(store, "k/1", payload)
        assert await store.read("k/1") == payload
        assert b"".join([c async for c in store.read_chunks("k/1")]) == payload

        gateway.objects["bad"] = _Object(payload, "x", {"sha256": "0" * 64}, "KMS")
        with pytest.raises(ObjectDigestMismatch):
            await store.read("bad")
        gateway.objects["plain"] = _Object(payload, "x", {"sha256": _sha(payload)}, "AES256")
        with pytest.raises(ObjectStoreError):
            await store.read("plain")
        with pytest.raises(OSSObjectNotFound):
            await store.read("missing")
        with pytest.raises(KeyError):  # the same exception a missing in-memory key raises
            await store.read("missing")

        limited = AliyunOSSObjectStore(gateway, server_side_encryption="KMS", max_read_bytes=5)
        with pytest.raises(ObjectStoreError):
            await limited.read("k/1")

    asyncio.run(exercise())


def test_oss_delete_and_readiness_delegate_to_the_gateway() -> None:
    async def exercise() -> None:
        gateway = _Gateway()
        store = AliyunOSSObjectStore(gateway, server_side_encryption="KMS")
        await _put(store, "k/1", b"abc")
        await store.delete("k/1")
        await store.delete("k/1")  # deleting an absent key is not an error
        assert not gateway.objects

        await store.check_ready()

        assert gateway.ready_checks == 1

    asyncio.run(exercise())


@pytest.mark.parametrize("key", ["", "/abs", "a/../b", "a\x00b"])
def test_oss_refuses_unsafe_keys(key: str) -> None:
    async def exercise() -> None:
        store = AliyunOSSObjectStore(_Gateway(), server_side_encryption="KMS")
        with pytest.raises(ValueError):
            await _put(store, key, b"abc")
        with pytest.raises(ValueError):
            await store.read(key)

    asyncio.run(exercise())


def test_oss_store_requires_a_known_encryption_mode() -> None:
    with pytest.raises(ValueError):
        AliyunOSSObjectStore(_Gateway(), server_side_encryption="NONE")


class _SDK:
    class PutObjectRequest(SimpleNamespace):
        pass

    class HeadObjectRequest(SimpleNamespace):
        pass

    class DeleteObjectRequest(SimpleNamespace):
        pass

    class GetBucketInfoRequest(SimpleNamespace):
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


class _SDKClient:
    def __init__(self) -> None:
        self.put_requests: list[SimpleNamespace] = []
        self.head_result = SimpleNamespace(
            content_length=7,
            metadata={"sha256": "a" * 64},
            server_side_encryption="KMS",
        )
        self.bucket_checks = 0

    def put_object(self, request: SimpleNamespace) -> None:
        self.put_requests.append(request)

    def head_object(self, request: SimpleNamespace) -> SimpleNamespace:
        return self.head_result

    def delete_object(self, request: SimpleNamespace) -> None:
        return None

    def get_bucket_info(self, request: SimpleNamespace) -> None:
        self.bucket_checks += 1


def test_sdk_gateway_requests_atomic_kms_encrypted_private_object() -> None:
    client = _SDKClient()
    gateway = AliyunOSSSDKGateway(client, _SDK, bucket="private-raw")

    gateway.put_immutable(
        key="tenants/t/sessions/s/segments/0.ffps",
        body=b"payload",
        content_type="application/octet-stream",
        metadata={"sha256": "a" * 64},
        server_side_encryption="KMS",
    )

    request = client.put_requests[0]
    assert request.bucket == "private-raw"
    assert request.forbid_overwrite is True
    assert request.server_side_encryption == "KMS"
    assert request.metadata == {"sha256": "a" * 64}
    assert request.body == b"payload"


def test_sdk_gateway_converts_only_oss_existing_object_conflict() -> None:
    class ExistingClient(_SDKClient):
        def put_object(self, request: SimpleNamespace) -> None:
            raise _SDK.ServiceError(409, "FileAlreadyExists")

    gateway = AliyunOSSSDKGateway(ExistingClient(), _SDK, bucket="private-raw")

    with pytest.raises(OSSObjectAlreadyExists):
        gateway.put_immutable(
            key="tenants/t/sessions/s/segments/0.ffps",
            body=b"payload",
            content_type="application/octet-stream",
            metadata={"sha256": "a" * 64},
            server_side_encryption="KMS",
        )


def test_sdk_gateway_converts_wrapped_existing_object_conflict() -> None:
    class ExistingClient(_SDKClient):
        def put_object(self, request: SimpleNamespace) -> None:
            raise _SDK.OperationError(_SDK.ServiceError(409, "ObjectAlreadyExists"))

    gateway = AliyunOSSSDKGateway(ExistingClient(), _SDK, bucket="private-raw")

    with pytest.raises(OSSObjectAlreadyExists):
        gateway.put_immutable(
            key="tenants/t/sessions/s/segments/0.ffps",
            body=b"payload",
            content_type="application/octet-stream",
            metadata={"sha256": "a" * 64},
            server_side_encryption="KMS",
        )


def test_sdk_gateway_converts_wrapped_missing_head() -> None:
    class MissingClient(_SDKClient):
        def head_object(self, request: SimpleNamespace) -> SimpleNamespace:
            raise _SDK.OperationError(_SDK.ServiceError(404, "NoSuchKey"))

    gateway = AliyunOSSSDKGateway(MissingClient(), _SDK, bucket="private-raw")

    with pytest.raises(OSSObjectNotFound):
        gateway.head("tenants/t/sessions/s/segments/0.ffps")


def test_sdk_gateway_readiness_uses_bucket_info_without_listing_objects() -> None:
    client = _SDKClient()
    gateway = AliyunOSSSDKGateway(client, _SDK, bucket="private-raw")

    gateway.check_ready()

    assert client.bucket_checks == 1


def test_store_factory_uses_rotating_ecs_role_and_internal_https_endpoint() -> None:
    credential_configs: list[object] = []
    oss_configs: list[object] = []
    client = _SDKClient()

    class CredentialClient:
        def __init__(self, config: object) -> None:
            credential_configs.append(config)

        def get_credential(self) -> SimpleNamespace:
            return SimpleNamespace(
                access_key_id="STS.test",
                access_key_secret="not-printed",
                security_token="not-printed",
            )

    def client_factory(config: object) -> _SDKClient:
        oss_configs.append(config)
        credentials = config.credentials_provider.get_credentials()
        assert credentials.access_key_id == "STS.test"
        return client

    settings = SimpleNamespace(
        oss_region="us-west-1",
        oss_endpoint="https://oss-us-west-1-internal.aliyuncs.com",
        oss_bucket="private-raw",
        oss_server_side_encryption="KMS",
        oss_ecs_ram_role="feetforceplate-oss",
    )

    store = build_aliyun_oss_object_store(
        settings,
        credential_client_cls=CredentialClient,
        client_factory=client_factory,
    )
    asyncio.run(store.check_ready())

    assert credential_configs[0].type == "ecs_ram_role"
    assert credential_configs[0].role_name == "feetforceplate-oss"
    assert credential_configs[0].enable_imds_v2 is True
    assert credential_configs[0].disable_imds_v1 is True
    assert oss_configs[0].region == "us-west-1"
    assert oss_configs[0].endpoint.endswith("-internal.aliyuncs.com")
    assert client.bucket_checks == 1
