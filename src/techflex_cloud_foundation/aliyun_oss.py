"""Alibaba Cloud OSS adapter for the immutable object store boundary.

``AliyunOSSObjectStore`` implements ``ImmutableObjectStore`` on a bucket with
server-side encryption: a payload is verified against its declared SHA-256 and
size, published only if the key is absent (``forbid_overwrite``), and replayed
idempotently when the key already holds the same content. Key layout is the
caller's; nothing here knows an application's naming scheme.

The gateway classes are the FeetForcePlate cloud ``aliyun_oss`` module as it
was (RAY-830 ``object-storage``); the store on top of them takes the generic
``put_verified`` signature instead of ``put_segment``/``put_manifest``.
``alibabacloud-oss-v2`` is imported only when ``build_aliyun_oss_sdk`` runs, so
the module imports without it (``server`` extra).
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterable, Callable, Mapping
from dataclasses import dataclass
import hashlib
import importlib
from types import SimpleNamespace
from typing import Any, Protocol

from .object_store import (
    ObjectConflict,
    ObjectDigestMismatch,
    ObjectStoreError,
    StoredObject,
    _verified_payload,
)

_READ_CHUNK_BYTES = 1 << 20
_DEFAULT_CONTENT_TYPE = "application/octet-stream"
_SSE_MODES = frozenset({"KMS", "AES256"})



@dataclass(frozen=True, slots=True)
class OSSHead:
    size_bytes: int
    metadata: dict[str, str]
    server_side_encryption: str | None


class OSSObjectAlreadyExists(Exception):
    """Raised when an atomic OSS create finds an existing immutable key."""


class OSSObjectNotFound(KeyError):
    """Raised when an OSS object head request finds no current object."""


class OSSGateway(Protocol):
    def put_immutable(
        self,
        *,
        key: str,
        body: bytes,
        content_type: str,
        metadata: dict[str, str],
        server_side_encryption: str,
    ) -> None: ...

    def head(self, key: str) -> OSSHead: ...

    def get(self, key: str) -> bytes: ...

    def delete(self, key: str) -> None: ...

    def check_ready(self) -> None: ...


class AliyunOSSSDKGateway:
    """Small synchronous boundary around OSS SDK V2 request objects."""

    def __init__(self, client: Any, sdk: Any, *, bucket: str) -> None:
        if not bucket.strip():
            raise ValueError("OSS bucket is required")
        self._client = client
        self._sdk = sdk
        self._bucket = bucket

    def put_immutable(
        self,
        *,
        key: str,
        body: bytes,
        content_type: str,
        metadata: dict[str, str],
        server_side_encryption: str,
    ) -> None:
        request = self._sdk.PutObjectRequest(
            bucket=self._bucket,
            key=key,
            body=body,
            content_type=content_type,
            metadata=metadata,
            forbid_overwrite=True,
            server_side_encryption=server_side_encryption,
        )
        try:
            self._client.put_object(request)
        except (self._sdk.ServiceError, self._sdk.OperationError) as exc:
            service_error = self._service_error(exc)
            if (
                service_error is not None
                and service_error.status_code == 409
                and service_error.code in {"FileAlreadyExists", "ObjectAlreadyExists"}
            ):
                raise OSSObjectAlreadyExists(key) from exc
            raise

    def head(self, key: str) -> OSSHead:
        try:
            result = self._client.head_object(
                self._sdk.HeadObjectRequest(bucket=self._bucket, key=key)
            )
        except (self._sdk.ServiceError, self._sdk.OperationError) as exc:
            service_error = self._service_error(exc)
            if (
                service_error is not None
                and service_error.status_code == 404
                and service_error.code in {"NoSuchKey", "NoSuchObject"}
            ):
                raise OSSObjectNotFound(key) from exc
            raise
        return OSSHead(
            size_bytes=result.content_length,
            metadata=dict(result.metadata or {}),
            server_side_encryption=result.server_side_encryption,
        )

    def delete(self, key: str) -> None:
        self._client.delete_object(
            self._sdk.DeleteObjectRequest(bucket=self._bucket, key=key)
        )

    def get(self, key: str) -> bytes:
        result = self._client.get_object(
            self._sdk.GetObjectRequest(bucket=self._bucket, key=key)
        )
        try:
            body: bytes = result.body.read()
            return body
        finally:
            result.body.close()

    def check_ready(self) -> None:
        self._client.get_bucket_info(
            self._sdk.GetBucketInfoRequest(bucket=self._bucket)
        )

    def _service_error(self, exc: Any) -> Any:
        if isinstance(exc, self._sdk.ServiceError):
            return exc
        unwrapped = exc.unwrap()
        if isinstance(unwrapped, self._sdk.ServiceError):
            return unwrapped
        return None


class AliyunOSSObjectStore:
    """Immutable OSS store: verified payloads, publish-once keys, idempotent replay."""

    def __init__(
        self,
        gateway: OSSGateway,
        *,
        server_side_encryption: str,
        max_read_bytes: int | None = None,
    ) -> None:
        if server_side_encryption not in _SSE_MODES:
            raise ValueError("OSS server-side encryption must be KMS or AES256")
        if max_read_bytes is not None and max_read_bytes < 1:
            raise ValueError("max_read_bytes must be positive")
        self._gateway = gateway
        self._server_side_encryption = server_side_encryption
        self._max_read_bytes = max_read_bytes

    async def put_verified(
        self,
        object_key: str,
        chunks: AsyncIterable[bytes],
        *,
        expected_sha256: str,
        expected_size: int,
        content_type: str = _DEFAULT_CONTENT_TYPE,
        extra_metadata: Mapping[str, str] | None = None,
    ) -> StoredObject:
        """Publish verified bytes under ``object_key``.

        ``content_type`` and ``extra_metadata`` are stored with the object; the
        ``sha256`` metadata entry is always the verified digest, and
        ``extra_metadata`` may not name it in any letter case. A replay compares
        size, ``sha256`` and encryption only.
        """
        _check_key(object_key)
        payload = await _verified_payload(
            chunks, expected_sha256=expected_sha256, expected_size=expected_size
        )
        if any(name.lower() == "sha256" for name in extra_metadata or ()):
            # OSS user metadata names are case-insensitive headers.
            raise ValueError("extra_metadata cannot name sha256; the verified digest is stored")
        metadata = {**(extra_metadata or {}), "sha256": expected_sha256}
        await self._put_immutable(
            object_key, payload, content_type=content_type, metadata=metadata
        )
        return StoredObject(object_key, expected_sha256, expected_size)

    async def _put_immutable(
        self,
        object_key: str,
        payload: bytes,
        *,
        content_type: str,
        metadata: dict[str, str],
    ) -> None:
        try:
            head = await asyncio.to_thread(self._gateway.head, object_key)
        except OSSObjectNotFound:
            pass
        else:
            self._validate_existing(object_key, payload, metadata, head)
            return

        try:
            await asyncio.to_thread(
                self._gateway.put_immutable,
                key=object_key,
                body=payload,
                content_type=content_type,
                metadata=metadata,
                server_side_encryption=self._server_side_encryption,
            )
        except OSSObjectAlreadyExists:
            head = await asyncio.to_thread(self._gateway.head, object_key)
            self._validate_existing(object_key, payload, metadata, head)

    def _validate_existing(
        self,
        object_key: str,
        payload: bytes,
        metadata: dict[str, str],
        head: OSSHead,
    ) -> None:
        if (
            head.size_bytes != len(payload)
            or head.metadata.get("sha256") != metadata["sha256"]
            or head.server_side_encryption != self._server_side_encryption
        ):
            raise ObjectConflict(
                f"immutable OSS key {object_key!r} holds different content or security attributes"
            ) from None

    async def read(self, object_key: str, *, max_bytes: int | None = None) -> bytes:
        """Return the verified object; raises ``OSSObjectNotFound`` when absent.

        ``max_bytes`` bounds this read and takes precedence over the store's
        ``max_read_bytes``.
        """
        _check_key(object_key)
        limit = max_bytes if max_bytes is not None else self._max_read_bytes
        head = await asyncio.to_thread(self._gateway.head, object_key)
        if head.server_side_encryption != self._server_side_encryption:
            raise ObjectStoreError(f"OSS object {object_key!r} is not encrypted as required")
        if limit is not None and head.size_bytes > limit:
            raise ObjectStoreError(
                f"OSS object {object_key!r} is larger than the read limit"
            )
        payload = await asyncio.to_thread(self._gateway.get, object_key)
        if (
            len(payload) != head.size_bytes
            or hashlib.sha256(payload).hexdigest() != head.metadata.get("sha256")
        ):
            raise ObjectDigestMismatch(f"OSS object {object_key!r} fails digest verification")
        return payload

    async def read_chunks(self, object_key: str) -> AsyncIterable[bytes]:
        # The gateway reads whole objects, so this bounds what a caller holds
        # at once, not what the adapter does; verification needs the whole body.
        payload = await self.read(object_key)
        for offset in range(0, len(payload), _READ_CHUNK_BYTES):
            yield payload[offset : offset + _READ_CHUNK_BYTES]

    async def delete(self, object_key: str) -> None:
        _check_key(object_key)
        await asyncio.to_thread(self._gateway.delete, object_key)

    async def check_ready(self) -> None:
        await asyncio.to_thread(self._gateway.check_ready)


def _check_key(object_key: str) -> None:
    if (
        not object_key
        or object_key.startswith("/")
        or "\x00" in object_key
        or ".." in object_key.split("/")
    ):
        raise ValueError(f"invalid object key {object_key!r}")


def build_aliyun_oss_object_store(
    settings: Any,
    *,
    credential_client_cls: type | None = None,
    client_factory: Callable[[object], object] | None = None,
    max_read_bytes: int | None = None,
) -> AliyunOSSObjectStore:
    """Compose OSS SDK V2 with refreshable ECS RAM-role credentials."""

    client, oss = build_aliyun_oss_sdk(
        settings,
        credential_client_cls=credential_client_cls,
        client_factory=client_factory,
    )
    bindings = SimpleNamespace(
        PutObjectRequest=oss.PutObjectRequest,
        HeadObjectRequest=oss.HeadObjectRequest,
        GetObjectRequest=oss.GetObjectRequest,
        DeleteObjectRequest=oss.DeleteObjectRequest,
        GetBucketInfoRequest=oss.GetBucketInfoRequest,
        OperationError=oss.exceptions.OperationError,
        ServiceError=oss.exceptions.ServiceError,
    )
    gateway = AliyunOSSSDKGateway(client, bindings, bucket=settings.oss_bucket)
    return AliyunOSSObjectStore(
        gateway,
        server_side_encryption=settings.oss_server_side_encryption,
        max_read_bytes=max_read_bytes,
    )


def build_aliyun_oss_sdk(
    settings: Any,
    *,
    credential_client_cls: type | None = None,
    client_factory: Callable[[object], object] | None = None,
) -> tuple[Any, Any]:
    """Build the native SDK client with refreshable ECS RAM-role credentials."""

    oss = importlib.import_module("alibabacloud_oss_v2")
    credential_client_module = importlib.import_module("alibabacloud_credentials.client")
    credential_models = importlib.import_module("alibabacloud_credentials.models")

    credential_config = credential_models.Config(
        type="ecs_ram_role",
        role_name=settings.oss_ecs_ram_role,
        enable_imds_v2=True,
        disable_imds_v1=True,
        metadata_token_duration=3600,
    )
    credential_client = (credential_client_cls or credential_client_module.Client)(
        credential_config
    )

    def credentials() -> object:
        value = credential_client.get_credential()
        return oss.credentials.Credentials(
            access_key_id=value.access_key_id,
            access_key_secret=value.access_key_secret,
            security_token=value.security_token,
        )

    config = oss.config.load_default()
    config.credentials_provider = oss.credentials.CredentialsProviderFunc(func=credentials)
    config.region = settings.oss_region
    config.endpoint = settings.oss_endpoint
    client = (client_factory or oss.Client)(config)
    return client, oss


__all__ = [
    "AliyunOSSObjectStore",
    "AliyunOSSSDKGateway",
    "OSSGateway",
    "OSSHead",
    "OSSObjectAlreadyExists",
    "OSSObjectNotFound",
    "build_aliyun_oss_object_store",
    "build_aliyun_oss_sdk",
]
