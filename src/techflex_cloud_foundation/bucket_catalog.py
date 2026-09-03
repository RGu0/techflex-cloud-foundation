"""Logical bucket catalog and narrow presigned upload grants (CP-07).

The execution layer over the deployment profile's logical-bucket mappings:
a `BucketCatalog` resolves each `BucketRole` binding into a queryable
catalog, derives object keys server-side, and routes immutable publishes
through the content-verified `ImmutableObjectStore`.  A
`PresignedGrantAuthority` issues and consumes single-artifact upload grants
so a client can be narrowed to exactly one object without ever holding
long-term bucket credentials.  No cloud SDK is bound — provider adapters
(Aliyun OSS, S3) live in the application layer.

Invariants carried over from RAY-341 and the reference implementation:

- Unknown bucket roles are refused, never guessed; logical roles map to
  physical buckets only through the validated profile bindings.
- Object keys are derived server-side from the trusted tenant context; the
  client never chooses bucket, tenant, or final key.
- Keys carry opaque identifiers and complete digests only — names, archive
  numbers, and other guessable business identifiers never appear in a key.
- Publication is immutable: the same key with different content is a
  conflict, and originals are never silently overwritten.
- Presigned upload grants are narrow: one artifact, bound to digest, size,
  and purpose, short-lived, single-use; expiry, mismatch, or replay is
  refused.
- Grant signatures are compared before any claim is trusted, with
  constant-time comparison.
"""

from __future__ import annotations

from collections.abc import AsyncIterable, Iterable
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
import json
import re
from typing import Any, Protocol
from uuid import uuid4

from .manifest import _require_digest, _require_text
from .object_store import ImmutableObjectStore, StoredObject
from .platform_config import BucketBinding, BucketRole, DeploymentProfile

_OPAQUE_ID_RE = re.compile(r"[0-9A-Za-z][0-9A-Za-z-]{7,127}")
_DEFAULT_MAX_GRANT_TTL = timedelta(minutes=15)
_MIN_SECRET_BYTES = 32


class BucketCatalogError(Exception):
    """Base class for bucket catalog and grant failures."""


class BucketCatalogMalformed(BucketCatalogError):
    """A catalog construction or a field value is structurally invalid."""


class BucketRoleUnknown(BucketCatalogError):
    """The requested role is not a declared `BucketRole` bound in this catalog."""


class PresignedGrantError(BucketCatalogError):
    """Base class for presigned upload grant failures."""


class PresignedGrantMalformed(PresignedGrantError):
    """The grant or an issue/consume argument is structurally invalid."""


class PresignedGrantSignatureInvalid(PresignedGrantError):
    """The grant signature does not match the signed claims."""


class PresignedGrantExpired(PresignedGrantError):
    """The grant's expiry is in the past."""


class PresignedGrantConstraintViolation(PresignedGrantError):
    """The presented digest, size, or purpose disagrees with the grant."""


class PresignedGrantReplayed(PresignedGrantError):
    """The grant was already consumed; presigned grants are single-use."""


def _require_opaque_id(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_ID_RE.fullmatch(value):
        raise BucketCatalogMalformed(
            f"{field_name} must be an opaque identifier (8-128 characters of "
            "[0-9A-Za-z-]); names, archive numbers, and other guessable "
            "business identifiers never appear in object keys"
        )
    return value


def _require_size(value: int, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise BucketCatalogMalformed(f"{field_name} must be a non-negative integer")
    return value


def _require_aware(value: datetime, *, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise BucketCatalogMalformed(f"{field_name} must be a timezone-aware datetime")


@dataclass(frozen=True)
class PublishedObject:
    """Receipt for one immutable, role-routed publication."""

    role: BucketRole
    physical_bucket: str
    object_key: str
    sha256: str
    size_bytes: int

    def __post_init__(self) -> None:
        if not isinstance(self.role, BucketRole):
            raise BucketCatalogMalformed("published role must be a BucketRole")
        _require_text(self.physical_bucket, field_name="physical bucket")
        _require_text(self.object_key, field_name="object key")
        _require_digest(self.sha256, field_name="published sha256")
        _require_size(self.size_bytes, field_name="published size")


class BucketCatalog:
    """Resolves profile bucket bindings into a queryable, routing catalog."""

    def __init__(
        self, bindings: Iterable[BucketBinding], objects: ImmutableObjectStore
    ) -> None:
        catalog: dict[BucketRole, BucketBinding] = {}
        for binding in tuple(bindings):
            if not isinstance(binding, BucketBinding):
                raise BucketCatalogMalformed("catalog entries must be BucketBinding")
            if binding.role in catalog:
                raise BucketCatalogMalformed(
                    f"bucket role {binding.role!r} is bound twice; roles are "
                    "unique within a catalog"
                )
            catalog[binding.role] = binding
        if not catalog:
            raise BucketCatalogMalformed("at least one bucket binding is required")
        self._bindings = catalog
        self._objects = objects

    @classmethod
    def from_profile(
        cls, profile: DeploymentProfile, objects: ImmutableObjectStore
    ) -> BucketCatalog:
        """Build the catalog from a validated deployment profile."""
        if not isinstance(profile, DeploymentProfile):
            raise BucketCatalogMalformed("profile must be a DeploymentProfile")
        return cls(profile.buckets, objects)

    @property
    def roles(self) -> tuple[BucketRole, ...]:
        return tuple(sorted(self._bindings, key=str))

    def binding_for(self, role: BucketRole | str) -> BucketBinding:
        """Return the binding for a role; unknown roles are refused."""
        try:
            resolved = BucketRole(role)
        except ValueError:
            raise BucketRoleUnknown(
                f"bucket role {role!r} is not a declared BucketRole; unknown "
                "roles are refused, never guessed"
            ) from None
        try:
            return self._bindings[resolved]
        except KeyError:
            raise BucketRoleUnknown(
                f"no binding for bucket role {resolved!r} in this catalog"
            ) from None

    def derive_object_key(
        self,
        *,
        tenant_id: str,
        role: BucketRole | str,
        artifact_id: str,
        content_sha256: str,
    ) -> str:
        """Derive the server-side object key; callers never choose it.

        ``tenant_id`` must come from the authenticated, trusted context —
        never from a request payload.  Both identifiers are opaque; the
        content digest tail makes the key content-addressed.
        """
        binding = self.binding_for(role)
        tenant = _require_opaque_id(tenant_id, field_name="tenant id")
        artifact = _require_opaque_id(artifact_id, field_name="artifact id")
        digest = _require_digest(content_sha256, field_name="content sha256")
        return f"{binding.role}/{tenant}/{artifact}/{digest}"

    async def publish(
        self,
        *,
        tenant_id: str,
        role: BucketRole | str,
        artifact_id: str,
        content_sha256: str,
        size_bytes: int,
        chunks: AsyncIterable[bytes],
    ) -> PublishedObject:
        """Route one immutable, verified publication through the catalog."""
        binding = self.binding_for(role)
        size = _require_size(size_bytes, field_name="size bytes")
        object_key = self.derive_object_key(
            tenant_id=tenant_id,
            role=binding.role,
            artifact_id=artifact_id,
            content_sha256=content_sha256,
        )
        stored: StoredObject = await self._objects.put_verified(
            object_key,
            chunks,
            expected_sha256=content_sha256,
            expected_size=size,
        )
        return PublishedObject(
            role=binding.role,
            physical_bucket=binding.physical_bucket,
            object_key=stored.object_key,
            sha256=stored.sha256,
            size_bytes=stored.size_bytes,
        )


@dataclass(frozen=True)
class PresignedUploadGrant:
    """One signed, single-use authorization to upload exactly one artifact.

    The claims pin tenant, role, artifact, content digest, size, purpose,
    target bucket/key, and expiry; the signature commits to every claim.
    """

    grant_id: str
    tenant_id: str
    role: BucketRole
    artifact_id: str
    content_sha256: str
    size_bytes: int
    purpose: str
    physical_bucket: str
    object_key: str
    issued_at: datetime
    expires_at: datetime
    signature: str

    def __post_init__(self) -> None:
        _require_opaque_id(self.grant_id, field_name="grant id")
        _require_opaque_id(self.tenant_id, field_name="tenant id")
        if not isinstance(self.role, BucketRole):
            raise PresignedGrantMalformed("grant role must be a BucketRole")
        _require_opaque_id(self.artifact_id, field_name="artifact id")
        _require_digest(self.content_sha256, field_name="content sha256")
        _require_size(self.size_bytes, field_name="size bytes")
        _require_text(self.purpose, field_name="purpose")
        _require_text(self.physical_bucket, field_name="physical bucket")
        _require_text(self.object_key, field_name="object key")
        _require_aware(self.issued_at, field_name="issued_at")
        _require_aware(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.issued_at:
            raise PresignedGrantMalformed("grant expiry must follow its issue time")
        _require_digest(self.signature, field_name="grant signature")

    def claims_document(self) -> dict[str, Any]:
        """The signed claims; the signature itself is never signed."""
        return {
            "artifact_id": self.artifact_id,
            "content_sha256": self.content_sha256,
            "expires_at": self.expires_at.isoformat(),
            "grant_id": self.grant_id,
            "issued_at": self.issued_at.isoformat(),
            "object_key": self.object_key,
            "physical_bucket": self.physical_bucket,
            "purpose": self.purpose,
            "role": str(self.role),
            "size_bytes": self.size_bytes,
            "tenant_id": self.tenant_id,
        }

    def canonical_bytes(self) -> bytes:
        """Reproducible byte form the signature commits to."""
        return json.dumps(
            self.claims_document(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


class PresignedGrantStore(Protocol):
    """Single-use consumption boundary; production binds durable storage."""

    def claim(self, grant_id: str) -> None: ...


class InMemoryPresignedGrantStore:
    """Volatile reference store, suitable for tests and integration runs."""

    def __init__(self) -> None:
        self._consumed: set[str] = set()

    def claim(self, grant_id: str) -> None:
        if grant_id in self._consumed:
            raise PresignedGrantReplayed(
                f"grant {grant_id!r} was already consumed; presigned grants "
                "are single-use"
            )
        self._consumed.add(grant_id)


class PresignedGrantAuthority:
    """Issues and consumes narrow, signed, single-use upload grants."""

    def __init__(
        self,
        *,
        catalog: BucketCatalog,
        store: PresignedGrantStore,
        secret: bytes,
        max_ttl: timedelta = _DEFAULT_MAX_GRANT_TTL,
    ) -> None:
        if not isinstance(catalog, BucketCatalog):
            raise BucketCatalogMalformed("catalog must be a BucketCatalog")
        if not isinstance(secret, bytes) or len(secret) < _MIN_SECRET_BYTES:
            raise BucketCatalogMalformed(
                f"grant signing secret must be at least {_MIN_SECRET_BYTES} bytes"
            )
        if not isinstance(max_ttl, timedelta) or max_ttl <= timedelta(0):
            raise BucketCatalogMalformed("max_ttl must be a positive duration")
        self._catalog = catalog
        self._store = store
        self._secret = secret
        self._max_ttl = max_ttl

    def _sign(self, canonical: bytes) -> str:
        return hmac.new(self._secret, canonical, hashlib.sha256).hexdigest()

    def issue_upload_grant(
        self,
        *,
        tenant_id: str,
        role: BucketRole | str,
        artifact_id: str,
        content_sha256: str,
        size_bytes: int,
        purpose: str,
        now: datetime,
        expires_at: datetime,
    ) -> PresignedUploadGrant:
        """Issue one short-lived grant bound to a single derived object key."""
        _require_aware(now, field_name="now")
        _require_aware(expires_at, field_name="expires_at")
        if expires_at <= now:
            raise PresignedGrantMalformed("grant expiry must be in the future")
        if expires_at - now > self._max_ttl:
            raise PresignedGrantMalformed(
                f"grant lifetime exceeds the maximum {self._max_ttl}; presigned "
                "uploads are short-lived"
            )
        binding = self._catalog.binding_for(role)
        object_key = self._catalog.derive_object_key(
            tenant_id=tenant_id,
            role=binding.role,
            artifact_id=artifact_id,
            content_sha256=content_sha256,
        )
        unsigned = PresignedUploadGrant(
            grant_id=uuid4().hex,
            tenant_id=tenant_id,
            role=binding.role,
            artifact_id=artifact_id,
            content_sha256=content_sha256,
            size_bytes=size_bytes,
            purpose=purpose,
            physical_bucket=binding.physical_bucket,
            object_key=object_key,
            issued_at=now,
            expires_at=expires_at,
            signature="0" * 64,
        )
        return replace(unsigned, signature=self._sign(unsigned.canonical_bytes()))

    def consume_upload_grant(
        self,
        grant: PresignedUploadGrant,
        *,
        purpose: str,
        content_sha256: str,
        size_bytes: int,
        now: datetime,
    ) -> PresignedUploadGrant:
        """Verify and consume a grant; any mismatch or replay is refused.

        The signature is compared before any claim is trusted.  On success
        the grant is marked consumed and returned; the caller may presign
        exactly the pinned bucket/key for the pinned digest and size.
        """
        if not isinstance(grant, PresignedUploadGrant):
            raise PresignedGrantMalformed("grant must be a PresignedUploadGrant")
        _require_aware(now, field_name="now")
        if not hmac.compare_digest(self._sign(grant.canonical_bytes()), grant.signature):
            raise PresignedGrantSignatureInvalid(
                "grant signature does not match the signed claims"
            )
        if grant.expires_at <= now:
            raise PresignedGrantExpired("grant has expired")
        binding = self._catalog.binding_for(grant.role)
        expected_key = self._catalog.derive_object_key(
            tenant_id=grant.tenant_id,
            role=grant.role,
            artifact_id=grant.artifact_id,
            content_sha256=grant.content_sha256,
        )
        if grant.physical_bucket != binding.physical_bucket or grant.object_key != expected_key:
            raise PresignedGrantConstraintViolation(
                "grant target no longer matches this catalog's binding"
            )
        if grant.content_sha256 != content_sha256:
            raise PresignedGrantConstraintViolation(
                "presented digest differs from the digest the grant commits to"
            )
        if grant.size_bytes != size_bytes:
            raise PresignedGrantConstraintViolation(
                "presented size differs from the size the grant commits to"
            )
        if grant.purpose != purpose:
            raise PresignedGrantConstraintViolation(
                "presented purpose differs from the purpose the grant commits to"
            )
        self._store.claim(grant.grant_id)
        return grant
