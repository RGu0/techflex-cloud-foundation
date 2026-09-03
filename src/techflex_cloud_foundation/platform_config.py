"""Versioned platform deployment profile schema and validator (CP-01).

A deployment profile declares *how* a Cloud Platform Foundation deployment is
shaped: environment, region, public ingress, database roles, KMS reference,
logical-bucket mappings, retention tiers, and registered products.  It never
carries secret material — databases, signing keys, and cloud credentials are
named through `SecretRef` (provider + locator), so a profile document can live
in a repository without a single key byte in it.

Invariants carried over from RAY-341 and the reference seed composition:

- Configuration values and secret bytes are separated: any field whose name
  implies secret material (``*secret*``, ``*password*``, ``*token*``,
  ``*_key``) is refused unless it sits inside a declared ``SecretRef``.
- Placeholder values (``todo``, ``changeme``, ``example``…) are refused; a
  profile that cannot be real cannot pass.
- Unknown versions and unknown fields are refused, never guessed.
- Production ingress is a public-CA hostname on 443; an IP literal, a private
  CA, or a temporary port is an integration channel, never production ingress.
- Logical bucket roles may share a physical bucket only when their policies
  (encryption, versioning, retention) are identical.
- The schema validates structure only; concrete deployment values — cloud
  account, domain, certificate, KMS key, physical bucket names — stay with the
  deploying application.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import hashlib
import ipaddress
import json
import re
from typing import Any, Mapping
from urllib.parse import urlparse

from .lifecycle import RetentionClass

PLATFORM_CONFIG_SCHEMA_VERSION = "techflex-platform-deployment/1"

_ENV_VAR_RE = re.compile(r"[A-Z_][A-Z0-9_]*")
_SECRETISH_KEY_RE = re.compile(r"secret|password|token|private_key|access_key")
_PLACEHOLDER_VALUES = frozenset(
    {"todo", "changeme", "change-me", "placeholder", "example", "example.com", "xxx", "tbd"}
)


class PlatformConfigError(Exception):
    """Base class for platform deployment profile failures."""


class PlatformConfigMalformed(PlatformConfigError):
    """The document or a field value is structurally invalid."""


class PlatformConfigVersionUnsupported(PlatformConfigError):
    """The document declares a schema version this build refuses."""


def _require_str(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PlatformConfigMalformed(f"{field_name} must be a non-empty string")
    if value.strip().lower() in _PLACEHOLDER_VALUES:
        raise PlatformConfigMalformed(
            f"{field_name} holds the placeholder {value!r}; a profile that "
            "cannot be real cannot pass"
        )
    return value


def _require_bool(value: Any, *, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise PlatformConfigMalformed(f"{field_name} must be a boolean")
    return value


def _require_port(value: Any, *, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
        raise PlatformConfigMalformed(f"{field_name} must be an integer in 1..65535")
    return value


def _reject_unknown_keys(
    document: Mapping[str, Any], allowed: frozenset[str], *, context: str
) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise PlatformConfigMalformed(
            f"{context} declares unknown field(s) {unknown}; unknown fields are "
            "refused, never guessed"
        )


class Environment(StrEnum):
    DEVELOPMENT = "development"
    INTEGRATION = "integration"
    STAGING = "staging"
    PRODUCTION = "production"


class SecretProvider(StrEnum):
    """Where a secret's bytes live; the profile names only the location."""

    ENVIRONMENT_VARIABLE = "env"
    FILE = "file"
    KMS = "kms"


class BucketRole(StrEnum):
    """Logical bucket roles; physical bucket names stay deployment values."""

    RAW_IMMUTABLE = "raw-immutable"
    DERIVED = "derived"
    REPORTS_EXPORTS = "reports-exports"
    OPS_AUDIT = "ops-audit"
    BACKUP_RECOVERY = "backup-recovery"


class BucketEncryption(StrEnum):
    SSE_KMS = "sse-kms"
    SSE_AES256 = "sse-aes256"


@dataclass(frozen=True)
class SecretRef:
    """A reference to secret material held elsewhere; never the material."""

    provider: SecretProvider
    locator: str

    def __post_init__(self) -> None:
        if not isinstance(self.provider, SecretProvider):
            raise PlatformConfigMalformed("secret ref provider must be a SecretProvider")
        locator = _require_str(self.locator, field_name="secret ref locator")
        if any(ch.isspace() for ch in locator):
            raise PlatformConfigMalformed(
                "secret ref locator must be a name or path, never material"
            )
        if self.provider is SecretProvider.ENVIRONMENT_VARIABLE and not _ENV_VAR_RE.fullmatch(
            locator
        ):
            raise PlatformConfigMalformed(
                f"env secret ref locator {locator!r} must be an environment variable name"
            )

    def to_document(self) -> dict[str, str]:
        return {"provider": str(self.provider), "locator": self.locator}

    @staticmethod
    def from_document(document: Any, *, field_name: str) -> SecretRef:
        if not isinstance(document, Mapping):
            raise PlatformConfigMalformed(f"{field_name} must be a secret ref object")
        _reject_unknown_keys(
            document, frozenset({"provider", "locator"}), context=field_name
        )
        try:
            provider = SecretProvider(
                _require_str(document.get("provider"), field_name=f"{field_name}.provider")
            )
        except ValueError as exc:
            raise PlatformConfigMalformed(
                f"{field_name}.provider must be one of {[str(p) for p in SecretProvider]}"
            ) from exc
        return SecretRef(
            provider=provider,
            locator=_require_str(document.get("locator"), field_name=f"{field_name}.locator"),
        )


@dataclass(frozen=True)
class IngressProfile:
    """Public entrypoint shape; production rules are enforced by the profile."""

    public_base_url: str
    port: int
    public_ca: bool

    def __post_init__(self) -> None:
        url = _require_str(self.public_base_url, field_name="ingress.public_base_url")
        parsed = urlparse(url)
        if parsed.scheme != "https" or not parsed.hostname:
            raise PlatformConfigMalformed(
                "ingress.public_base_url must be an absolute https:// URL"
            )
        if (
            not isinstance(self.port, int)
            or isinstance(self.port, bool)
            or not 1 <= self.port <= 65535
        ):
            raise PlatformConfigMalformed("ingress.port must be an integer in 1..65535")
        _require_bool(self.public_ca, field_name="ingress.public_ca")
        _require_port(self.port, field_name="ingress.port")

    @property
    def hostname(self) -> str:
        return urlparse(self.public_base_url).hostname or ""

    @property
    def host_is_ip_literal(self) -> bool:
        try:
            ipaddress.ip_address(self.hostname)
        except ValueError:
            return False
        return True

    def to_document(self) -> dict[str, Any]:
        return {
            "public_base_url": self.public_base_url,
            "port": self.port,
            "public_ca": self.public_ca,
        }


@dataclass(frozen=True)
class BucketPolicy:
    """Access/shape constraints one physical bucket binding must satisfy."""

    encryption: BucketEncryption
    versioning: bool
    retention: RetentionClass

    def __post_init__(self) -> None:
        if not isinstance(self.encryption, BucketEncryption):
            raise PlatformConfigMalformed("bucket encryption must be a BucketEncryption")
        _require_bool(self.versioning, field_name="bucket versioning")
        if not isinstance(self.retention, RetentionClass):
            raise PlatformConfigMalformed("bucket retention must be a RetentionClass")

    def to_document(self) -> dict[str, Any]:
        return {
            "encryption": str(self.encryption),
            "versioning": self.versioning,
            "retention": str(self.retention),
        }


@dataclass(frozen=True)
class BucketBinding:
    """One logical role mapped to one physical bucket under one policy."""

    role: BucketRole
    physical_bucket: str
    policy: BucketPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.role, BucketRole):
            raise PlatformConfigMalformed("bucket role must be a BucketRole")
        _require_str(self.physical_bucket, field_name=f"bucket {self.role} physical name")
        if not isinstance(self.policy, BucketPolicy):
            raise PlatformConfigMalformed("bucket policy must be a BucketPolicy")
        if self.role is BucketRole.RAW_IMMUTABLE and not self.policy.versioning:
            raise PlatformConfigMalformed(
                "raw-immutable buckets must keep versioning on; originals are "
                "never silently overwritten"
            )

    def to_document(self) -> dict[str, Any]:
        return {
            "role": str(self.role),
            "physical_bucket": self.physical_bucket,
            "policy": self.policy.to_document(),
        }


@dataclass(frozen=True)
class ProductRegistration:
    """One registered product and the schema versions this deployment serves."""

    product_id: str
    supported_schema_versions: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_str(self.product_id, field_name="product id")
        if not self.supported_schema_versions:
            raise PlatformConfigMalformed(
                f"product {self.product_id!r} must declare at least one schema version"
            )
        for version in self.supported_schema_versions:
            _require_str(version, field_name=f"product {self.product_id!r} schema version")
        if len(set(self.supported_schema_versions)) != len(self.supported_schema_versions):
            raise PlatformConfigMalformed(
                f"product {self.product_id!r} schema versions must be unique"
            )

    def to_document(self) -> dict[str, Any]:
        return {
            "product_id": self.product_id,
            "supported_schema_versions": list(self.supported_schema_versions),
        }


@dataclass(frozen=True)
class DeploymentProfile:
    """A validated, immutable deployment profile."""

    environment: Environment
    region: str
    ingress: IngressProfile
    kms: SecretRef
    databases: Mapping[str, SecretRef]
    buckets: tuple[BucketBinding, ...]
    products: tuple[ProductRegistration, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.environment, Environment):
            raise PlatformConfigMalformed("environment must be an Environment")
        _require_str(self.region, field_name="region")
        if not isinstance(self.ingress, IngressProfile):
            raise PlatformConfigMalformed("ingress must be an IngressProfile")
        if not isinstance(self.kms, SecretRef):
            raise PlatformConfigMalformed("kms must be a SecretRef")
        if not self.databases:
            raise PlatformConfigMalformed("at least one database role is required")
        locators: list[str] = []
        for role, ref in self.databases.items():
            _require_str(role, field_name="database role")
            if not isinstance(ref, SecretRef):
                raise PlatformConfigMalformed(
                    f"database role {role!r} must be a SecretRef; DSNs carry "
                    "credentials and never appear inline"
                )
            locators.append(f"{ref.provider}:{ref.locator}")
        if len(set(locators)) != len(locators):
            raise PlatformConfigMalformed(
                "database roles must reference distinct secrets; shared DSNs "
                "blur migration, serving, and control-plane authority"
            )
        roles = [binding.role for binding in self.buckets]
        if len(set(roles)) != len(roles):
            raise PlatformConfigMalformed("bucket roles must be unique within a profile")
        by_bucket: dict[str, BucketPolicy] = {}
        for binding in self.buckets:
            existing = by_bucket.setdefault(binding.physical_bucket, binding.policy)
            if existing != binding.policy:
                raise PlatformConfigMalformed(
                    f"logical roles share physical bucket {binding.physical_bucket!r} "
                    "only when encryption, versioning, and retention are identical"
                )
        product_ids = [product.product_id for product in self.products]
        if len(set(product_ids)) != len(product_ids):
            raise PlatformConfigMalformed("product ids must be unique within a profile")
        if self.environment is Environment.PRODUCTION:
            if self.ingress.host_is_ip_literal:
                raise PlatformConfigMalformed(
                    "production ingress must be a hostname; an IP literal is an "
                    "integration channel, never production ingress"
                )
            if self.ingress.port != 443:
                raise PlatformConfigMalformed(
                    "production ingress must listen on 443"
                )
            if not self.ingress.public_ca:
                raise PlatformConfigMalformed(
                    "production ingress must use a publicly trusted CA"
                )

    def to_document(self) -> dict[str, Any]:
        """Return the profile as a schema-conformant document."""
        return {
            "schema_version": PLATFORM_CONFIG_SCHEMA_VERSION,
            "environment": str(self.environment),
            "region": self.region,
            "ingress": self.ingress.to_document(),
            "kms": self.kms.to_document(),
            "databases": {
                role: ref.to_document() for role, ref in sorted(self.databases.items())
            },
            "buckets": [binding.to_document() for binding in self.buckets],
            "products": [product.to_document() for product in self.products],
        }

    def canonical_bytes(self) -> bytes:
        """Reproducible byte form; two equal profiles serialize identically."""
        return json.dumps(
            self.to_document(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    def digest(self) -> str:
        """Complete SHA-256 over the canonical form, for snapshot receipts."""
        return hashlib.sha256(self.canonical_bytes()).hexdigest()


def _reject_inline_secrets(document: Mapping[str, Any], *, path: str) -> None:
    for key, value in document.items():
        key_path = f"{path}.{key}" if path else str(key)
        if _SECRETISH_KEY_RE.search(str(key).lower()):
            raise PlatformConfigMalformed(
                f"{key_path} implies secret material; secrets are named through "
                "SecretRef fields, never carried inline"
            )
        if isinstance(value, Mapping):
            _reject_inline_secrets(value, path=key_path)


def parse_deployment_profile(document: Mapping[str, Any]) -> DeploymentProfile:
    """Validate a deployment profile document against the supported schema.

    Application-supplied documents and any future vendored example go through
    the exact same path; real deployment values are never vendored.
    """
    if not isinstance(document, Mapping):
        raise PlatformConfigMalformed("deployment profile must be a mapping")
    schema_version = _require_str(
        document.get("schema_version"), field_name="schema_version"
    )
    if schema_version != PLATFORM_CONFIG_SCHEMA_VERSION:
        raise PlatformConfigVersionUnsupported(
            f"schema_version {schema_version!r} is not supported; this build "
            f"accepts only {PLATFORM_CONFIG_SCHEMA_VERSION!r}"
        )
    _reject_unknown_keys(
        document,
        frozenset(
            {
                "schema_version",
                "environment",
                "region",
                "ingress",
                "kms",
                "databases",
                "buckets",
                "products",
            }
        ),
        context="deployment profile",
    )
    _reject_inline_secrets(
        {k: v for k, v in document.items() if k not in {"kms", "databases"}},
        path="",
    )
    try:
        environment = Environment(
            _require_str(document.get("environment"), field_name="environment")
        )
    except ValueError as exc:
        raise PlatformConfigMalformed(
            f"environment must be one of {[str(e) for e in Environment]}"
        ) from exc

    ingress_doc = document.get("ingress")
    if not isinstance(ingress_doc, Mapping):
        raise PlatformConfigMalformed("ingress must be an object")
    _reject_unknown_keys(
        ingress_doc,
        frozenset({"public_base_url", "port", "public_ca"}),
        context="ingress",
    )
    ingress = IngressProfile(
        public_base_url=_require_str(
            ingress_doc.get("public_base_url"), field_name="ingress.public_base_url"
        ),
        port=_require_port(ingress_doc.get("port"), field_name="ingress.port"),
        public_ca=_require_bool(ingress_doc.get("public_ca"), field_name="ingress.public_ca"),
    )

    kms = SecretRef.from_document(document.get("kms"), field_name="kms")

    databases_doc = document.get("databases")
    if not isinstance(databases_doc, Mapping):
        raise PlatformConfigMalformed("databases must be an object of role to secret ref")
    databases = {
        _require_str(role, field_name="database role"): SecretRef.from_document(
            ref, field_name=f"databases.{role}"
        )
        for role, ref in databases_doc.items()
    }

    buckets_doc = document.get("buckets")
    if not isinstance(buckets_doc, list):
        raise PlatformConfigMalformed("buckets must be a list")
    buckets: list[BucketBinding] = []
    for index, binding_doc in enumerate(buckets_doc):
        context = f"buckets[{index}]"
        if not isinstance(binding_doc, Mapping):
            raise PlatformConfigMalformed(f"{context} must be an object")
        _reject_unknown_keys(
            binding_doc,
            frozenset({"role", "physical_bucket", "policy"}),
            context=context,
        )
        try:
            role = BucketRole(
                _require_str(binding_doc.get("role"), field_name=f"{context}.role")
            )
        except ValueError as exc:
            raise PlatformConfigMalformed(
                f"{context}.role must be one of {[str(r) for r in BucketRole]}"
            ) from exc
        policy_doc = binding_doc.get("policy")
        if not isinstance(policy_doc, Mapping):
            raise PlatformConfigMalformed(f"{context}.policy must be an object")
        _reject_unknown_keys(
            policy_doc,
            frozenset({"encryption", "versioning", "retention"}),
            context=f"{context}.policy",
        )
        try:
            encryption = BucketEncryption(
                _require_str(
                    policy_doc.get("encryption"), field_name=f"{context}.policy.encryption"
                )
            )
            retention = RetentionClass(
                _require_str(
                    policy_doc.get("retention"), field_name=f"{context}.policy.retention"
                )
            )
        except ValueError as exc:
            raise PlatformConfigMalformed(
                f"{context}.policy encryption/retention must be declared members"
            ) from exc
        buckets.append(
            BucketBinding(
                role=role,
                physical_bucket=_require_str(
                    binding_doc.get("physical_bucket"),
                    field_name=f"{context}.physical_bucket",
                ),
                policy=BucketPolicy(
                    encryption=encryption,
                    versioning=_require_bool(
                        policy_doc.get("versioning"),
                        field_name=f"{context}.policy.versioning",
                    ),
                    retention=retention,
                ),
            )
        )

    products_doc = document.get("products")
    if not isinstance(products_doc, list):
        raise PlatformConfigMalformed("products must be a list")
    products: list[ProductRegistration] = []
    for index, product_doc in enumerate(products_doc):
        context = f"products[{index}]"
        if not isinstance(product_doc, Mapping):
            raise PlatformConfigMalformed(f"{context} must be an object")
        _reject_unknown_keys(
            product_doc,
            frozenset({"product_id", "supported_schema_versions"}),
            context=context,
        )
        versions = product_doc.get("supported_schema_versions")
        if not isinstance(versions, list):
            raise PlatformConfigMalformed(
                f"{context}.supported_schema_versions must be a list"
            )
        products.append(
            ProductRegistration(
                product_id=_require_str(
                    product_doc.get("product_id"), field_name=f"{context}.product_id"
                ),
                supported_schema_versions=tuple(versions),
            )
        )

    return DeploymentProfile(
        environment=environment,
        region=_require_str(document.get("region"), field_name="region"),
        ingress=ingress,
        kms=kms,
        databases=databases,
        buckets=tuple(buckets),
        products=tuple(products),
    )
