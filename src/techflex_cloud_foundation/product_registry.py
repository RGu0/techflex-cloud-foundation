"""Versioned product registry and compatibility decisions (CP-12).

A product registry is the business-neutral directory of products a deployment
serves: each `ProductRecord` names the client/protocol/schema version sets it
supports, declares business adapter entrypoints by reference (the registry
hosts entrypoint names, never algorithms), and carries the migration order
and minimum versions that bound what a client may declare.  Version
*semantics* — whether one declared version is older than another, and whether
an unsupported version is refused or quarantined — are injected through a
`ProductCompatibilityPolicy`; the registry never hardcodes product rules.

Invariants carried over from the reference implementations:

- Unknown catalog schema versions are refused, never guessed.
- Unknown fields in a catalog document or a client declaration are refused,
  never guessed.
- Product ids are unique within a catalog.
- Every compatibility decision is explicit: unregistered products and
  unsupported versions are rejected (or quarantined when the injected policy
  says so); the registry never silently downgrades to another version.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Mapping, Protocol

from .manifest import ManifestMalformed
from .manifest import _require_text as _manifest_require_text

PRODUCT_CATALOG_SCHEMA_VERSION = "techflex-product-catalog/1"

_MINIMUM_VERSION_DIMENSIONS = frozenset({"client", "protocol", "schema", "config"})


class ProductRegistryError(Exception):
    """Base class for product registry and compatibility failures."""


class ProductRegistryMalformed(ProductRegistryError):
    """A catalog document, record, or declaration is structurally invalid."""


class ProductRegistryVersionUnsupported(ProductRegistryError):
    """A catalog document declares a schema version this build refuses."""


def _require_text(value: Any, *, field_name: str) -> str:
    try:
        text = _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise ProductRegistryMalformed(str(exc)) from exc
    if not text.strip():
        raise ProductRegistryMalformed(f"{field_name} must be non-empty text")
    return text


def _require_text_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ProductRegistryMalformed(f"{field_name} must be a list of non-empty text")
    items = tuple(
        _require_text(item, field_name=f"{field_name}[{index}]")
        for index, item in enumerate(value)
    )
    if len(set(items)) != len(items):
        raise ProductRegistryMalformed(f"{field_name} entries must be unique")
    return items


def _reject_unknown_keys(
    document: Mapping[str, Any], allowed: frozenset[str], *, context: str
) -> None:
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise ProductRegistryMalformed(
            f"{context} declares unknown field(s) {unknown}; unknown fields are "
            "refused, never guessed"
        )


class VersionRelation(StrEnum):
    """How one declared version relates to a registered version."""

    OLDER = "older"
    EQUAL = "equal"
    NEWER = "newer"


class CompatibilityDecisionKind(StrEnum):
    """The explicit outcome of a compatibility decision; none is implicit."""

    COMPATIBLE = "compatible"
    MIGRATION_REQUIRED = "migration-required"
    REJECTED = "rejected"
    QUARANTINED = "quarantined"


class ProductCompatibilityPolicy(Protocol):
    """Injected product version semantics; the registry never hardcodes them."""

    def compare(self, left: str, right: str) -> VersionRelation | None:
        """Relate two versions of one dimension; ``None`` means incomparable."""
        ...

    def unsupported_disposition(
        self, *, dimension: str, version: str
    ) -> CompatibilityDecisionKind:
        """Whether an unsupported version is REJECTED or QUARANTINED."""
        ...


@dataclass(frozen=True)
class ProductRecord:
    """One registered product: supported version sets, adapter entrypoints,
    migration order, and minimum versions.  Entrypoints are names/references
    only; the registry never hosts adapter algorithms."""

    product_id: str
    supported_client_versions: tuple[str, ...] = ()
    supported_protocol_versions: tuple[str, ...] = ()
    supported_schema_versions: tuple[str, ...] = ()
    adapter_entrypoints: tuple[str, ...] = ()
    migration_order: tuple[str, ...] = ()
    minimum_versions: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _require_text(self.product_id, field_name="product id")
        if not self.supported_schema_versions:
            raise ProductRegistryMalformed(
                f"product {self.product_id!r} must declare at least one schema version"
            )
        for name, versions in (
            ("client", self.supported_client_versions),
            ("protocol", self.supported_protocol_versions),
            ("schema", self.supported_schema_versions),
            ("adapter entrypoints", self.adapter_entrypoints),
            ("migration order", self.migration_order),
        ):
            for version in versions:
                _require_text(version, field_name=f"product {self.product_id!r} {name} entry")
            if len(set(versions)) != len(versions):
                raise ProductRegistryMalformed(
                    f"product {self.product_id!r} {name} entries must be unique"
                )
        for key, value in self.minimum_versions.items():
            if key not in _MINIMUM_VERSION_DIMENSIONS:
                raise ProductRegistryMalformed(
                    f"product {self.product_id!r} minimum_versions key {key!r} must be "
                    f"one of {sorted(_MINIMUM_VERSION_DIMENSIONS)}"
                )
            _require_text(
                value, field_name=f"product {self.product_id!r} minimum {key} version"
            )

    def minimum_version(self, dimension: str) -> str | None:
        return self.minimum_versions.get(dimension)


@dataclass(frozen=True)
class ProductCatalog:
    """A validated, immutable catalog of registered products."""

    products: tuple[ProductRecord, ...]
    schema_version: str = PRODUCT_CATALOG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        if self.schema_version != PRODUCT_CATALOG_SCHEMA_VERSION:
            raise ProductRegistryVersionUnsupported(
                f"catalog schema version {self.schema_version!r} is not supported; "
                f"this build accepts only {PRODUCT_CATALOG_SCHEMA_VERSION!r}"
            )
        product_ids = [product.product_id for product in self.products]
        if len(set(product_ids)) != len(product_ids):
            raise ProductRegistryMalformed("product ids must be unique within a catalog")


@dataclass(frozen=True)
class ClientDeclaration:
    """The versions a client declares; every field is required, never guessed."""

    product_id: str
    protocol_version: str
    schema_version: str
    config_version: str
    client_version: str

    def __post_init__(self) -> None:
        _require_text(self.product_id, field_name="declaration product_id")
        _require_text(self.protocol_version, field_name="declaration protocol_version")
        _require_text(self.schema_version, field_name="declaration schema_version")
        _require_text(self.config_version, field_name="declaration config_version")
        _require_text(self.client_version, field_name="declaration client_version")

    @staticmethod
    def from_document(document: Any) -> ClientDeclaration:
        """Parse a declaration, refusing unknown or missing fields."""
        if not isinstance(document, Mapping):
            raise ProductRegistryMalformed("client declaration must be an object")
        _reject_unknown_keys(
            document,
            frozenset(
                {
                    "product_id",
                    "protocol_version",
                    "schema_version",
                    "config_version",
                    "client_version",
                }
            ),
            context="client declaration",
        )
        missing = [
            key
            for key in (
                "product_id",
                "protocol_version",
                "schema_version",
                "config_version",
                "client_version",
            )
            if key not in document
        ]
        if missing:
            raise ProductRegistryMalformed(
                f"client declaration is missing field(s) {missing}; missing fields "
                "are refused, never guessed"
            )
        return ClientDeclaration(
            product_id=document["product_id"],
            protocol_version=document["protocol_version"],
            schema_version=document["schema_version"],
            config_version=document["config_version"],
            client_version=document["client_version"],
        )


@dataclass(frozen=True)
class CompatibilityDecision:
    """The registry's explicit answer for one declaration, with its reasoning."""

    kind: CompatibilityDecisionKind
    product_id: str
    reason: str
    migration_path: tuple[str, ...] = ()
    minimum_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, CompatibilityDecisionKind):
            raise ProductRegistryMalformed("decision kind must be a CompatibilityDecisionKind")
        _require_text(self.product_id, field_name="decision product_id")
        _require_text(self.reason, field_name="decision reason")
        if self.kind is CompatibilityDecisionKind.MIGRATION_REQUIRED:
            if not self.migration_path and self.minimum_version is None:
                raise ProductRegistryMalformed(
                    "a migration decision must carry a migration path or a minimum "
                    "version; migration is never implied"
                )
        else:
            if self.migration_path or self.minimum_version is not None:
                raise ProductRegistryMalformed(
                    f"a {self.kind} decision carries no migration path or minimum version"
                )


@dataclass(frozen=True)
class _DimensionVerdict:
    """Internal verdict for one declared version against one dimension."""

    status: str  # "ok" | "migration" | "unsupported"
    minimum_version: str | None = None
    migration_path: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProductRegistry:
    """Compatibility decisions over a catalog under an injected policy."""

    catalog: ProductCatalog
    policy: ProductCompatibilityPolicy

    def __post_init__(self) -> None:
        if not isinstance(self.catalog, ProductCatalog):
            raise ProductRegistryMalformed("catalog must be a ProductCatalog")

    def get(self, product_id: str) -> ProductRecord | None:
        """Return the record for a product id, or ``None`` when unregistered."""
        for product in self.catalog.products:
            if product.product_id == product_id:
                return product
        return None

    @property
    def product_ids(self) -> tuple[str, ...]:
        return tuple(product.product_id for product in self.catalog.products)

    def _unsupported(self, *, dimension: str, version: str) -> CompatibilityDecisionKind:
        disposition = self.policy.unsupported_disposition(dimension=dimension, version=version)
        if disposition not in (
            CompatibilityDecisionKind.REJECTED,
            CompatibilityDecisionKind.QUARANTINED,
        ):
            raise ProductRegistryMalformed(
                "unsupported_disposition must answer REJECTED or QUARANTINED; a "
                "policy may never silently accept an unsupported version"
            )
        return disposition

    def _set_verdict(self, record: ProductRecord, *, dimension: str, declared: str) -> _DimensionVerdict:
        supported = {
            "client": record.supported_client_versions,
            "protocol": record.supported_protocol_versions,
            "schema": record.supported_schema_versions,
        }[dimension]
        if declared in supported:
            return _DimensionVerdict(status="ok")
        minimum = record.minimum_version(dimension)
        if minimum is not None and self.policy.compare(declared, minimum) is VersionRelation.OLDER:
            return _DimensionVerdict(status="migration", minimum_version=minimum)
        return _DimensionVerdict(status="unsupported")

    def _schema_verdict(self, record: ProductRecord, *, declared: str) -> _DimensionVerdict:
        if declared in record.supported_schema_versions:
            return _DimensionVerdict(status="ok")
        if declared in record.migration_order:
            tail = record.migration_order[record.migration_order.index(declared) + 1 :]
            path: list[str] = []
            for version in tail:
                path.append(version)
                if version in record.supported_schema_versions:
                    return _DimensionVerdict(
                        status="migration",
                        migration_path=tuple(path),
                        minimum_version=path[-1],
                    )
            return _DimensionVerdict(status="unsupported")
        minimum = record.minimum_version("schema")
        if minimum is not None and self.policy.compare(declared, minimum) is VersionRelation.OLDER:
            return _DimensionVerdict(status="migration", minimum_version=minimum)
        return _DimensionVerdict(status="unsupported")

    def _config_verdict(self, record: ProductRecord, *, declared: str) -> _DimensionVerdict:
        minimum = record.minimum_version("config")
        if minimum is None:
            return _DimensionVerdict(status="ok")
        relation = self.policy.compare(declared, minimum)
        if relation is VersionRelation.OLDER:
            return _DimensionVerdict(status="migration", minimum_version=minimum)
        if relation in (VersionRelation.EQUAL, VersionRelation.NEWER):
            return _DimensionVerdict(status="ok")
        return _DimensionVerdict(status="unsupported")

    def decide(self, declaration: ClientDeclaration) -> CompatibilityDecision:
        """Decide for one declaration; unregistered products and unsupported
        versions are answered explicitly, never silently downgraded."""
        if not isinstance(declaration, ClientDeclaration):
            raise ProductRegistryMalformed("declaration must be a ClientDeclaration")
        record = self.get(declaration.product_id)
        if record is None:
            return CompatibilityDecision(
                kind=CompatibilityDecisionKind.REJECTED,
                product_id=declaration.product_id,
                reason=f"product {declaration.product_id!r} is not registered in this catalog",
            )
        verdicts = (
            ("client", declaration.client_version, self._set_verdict(record, dimension="client", declared=declaration.client_version)),
            ("protocol", declaration.protocol_version, self._set_verdict(record, dimension="protocol", declared=declaration.protocol_version)),
            ("schema", declaration.schema_version, self._schema_verdict(record, declared=declaration.schema_version)),
            ("config", declaration.config_version, self._config_verdict(record, declared=declaration.config_version)),
        )
        for dimension, declared, verdict in verdicts:
            if verdict.status == "migration":
                return CompatibilityDecision(
                    kind=CompatibilityDecisionKind.MIGRATION_REQUIRED,
                    product_id=declaration.product_id,
                    reason=(
                        f"declared {dimension} version {declared!r} predates the "
                        f"supported set; migrate to at least {verdict.minimum_version!r}"
                    ),
                    migration_path=verdict.migration_path,
                    minimum_version=verdict.minimum_version,
                )
            if verdict.status == "unsupported":
                kind = self._unsupported(dimension=dimension, version=declared)
                return CompatibilityDecision(
                    kind=kind,
                    product_id=declaration.product_id,
                    reason=(
                        f"declared {dimension} version {declared!r} is not supported "
                        f"by product {record.product_id!r}"
                    ),
                )
        return CompatibilityDecision(
            kind=CompatibilityDecisionKind.COMPATIBLE,
            product_id=declaration.product_id,
            reason="all declared versions are supported",
        )


def parse_product_catalog(document: Any) -> ProductCatalog:
    """Validate a versioned catalog document against the supported schema."""
    if not isinstance(document, Mapping):
        raise ProductRegistryMalformed("product catalog must be a mapping")
    schema_version = _require_text(document.get("schema_version"), field_name="schema_version")
    if schema_version != PRODUCT_CATALOG_SCHEMA_VERSION:
        raise ProductRegistryVersionUnsupported(
            f"schema_version {schema_version!r} is not supported; this build "
            f"accepts only {PRODUCT_CATALOG_SCHEMA_VERSION!r}"
        )
    _reject_unknown_keys(
        document, frozenset({"schema_version", "products"}), context="product catalog"
    )
    products_doc = document.get("products")
    if not isinstance(products_doc, list):
        raise ProductRegistryMalformed("products must be a list")
    products: list[ProductRecord] = []
    for index, product_doc in enumerate(products_doc):
        context = f"products[{index}]"
        if not isinstance(product_doc, Mapping):
            raise ProductRegistryMalformed(f"{context} must be an object")
        _reject_unknown_keys(
            product_doc,
            frozenset(
                {
                    "product_id",
                    "supported_client_versions",
                    "supported_protocol_versions",
                    "supported_schema_versions",
                    "adapter_entrypoints",
                    "migration_order",
                    "minimum_versions",
                }
            ),
            context=context,
        )
        minimum_versions_doc = product_doc.get("minimum_versions") or {}
        if not isinstance(minimum_versions_doc, Mapping):
            raise ProductRegistryMalformed(f"{context}.minimum_versions must be an object")
        _reject_unknown_keys(
            minimum_versions_doc,
            _MINIMUM_VERSION_DIMENSIONS,
            context=f"{context}.minimum_versions",
        )
        products.append(
            ProductRecord(
                product_id=_require_text(
                    product_doc.get("product_id"), field_name=f"{context}.product_id"
                ),
                supported_client_versions=_require_text_tuple(
                    product_doc.get("supported_client_versions") or (),
                    field_name=f"{context}.supported_client_versions",
                ),
                supported_protocol_versions=_require_text_tuple(
                    product_doc.get("supported_protocol_versions") or (),
                    field_name=f"{context}.supported_protocol_versions",
                ),
                supported_schema_versions=_require_text_tuple(
                    product_doc.get("supported_schema_versions") or (),
                    field_name=f"{context}.supported_schema_versions",
                ),
                adapter_entrypoints=_require_text_tuple(
                    product_doc.get("adapter_entrypoints") or (),
                    field_name=f"{context}.adapter_entrypoints",
                ),
                migration_order=_require_text_tuple(
                    product_doc.get("migration_order") or (),
                    field_name=f"{context}.migration_order",
                ),
                minimum_versions=dict(minimum_versions_doc),
            )
        )
    return ProductCatalog(products=tuple(products))
