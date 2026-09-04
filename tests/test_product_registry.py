from __future__ import annotations

import pytest

from techflex_cloud_foundation import (
    ClientDeclaration,
    CompatibilityDecision,
    CompatibilityDecisionKind,
    ProductCatalog,
    ProductRecord,
    ProductRegistry,
    ProductRegistryMalformed,
    ProductRegistryVersionUnsupported,
    VersionRelation,
    parse_product_catalog,
)
from techflex_cloud_foundation.product_registry import PRODUCT_CATALOG_SCHEMA_VERSION


class NumericPolicy:
    """Test policy: numeric version strings compare by integer value."""

    def compare(self, left: str, right: str) -> VersionRelation | None:
        if not left.isdigit() or not right.isdigit():
            return None
        if int(left) < int(right):
            return VersionRelation.OLDER
        if int(left) > int(right):
            return VersionRelation.NEWER
        return VersionRelation.EQUAL

    def unsupported_disposition(
        self, *, dimension: str, version: str
    ) -> CompatibilityDecisionKind:
        if dimension == "protocol":
            return CompatibilityDecisionKind.QUARANTINED
        return CompatibilityDecisionKind.REJECTED


def _catalog_document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": PRODUCT_CATALOG_SCHEMA_VERSION,
        "products": [
            {
                "product_id": "alpha",
                "supported_client_versions": ["7", "8"],
                "supported_protocol_versions": ["2", "3"],
                "supported_schema_versions": ["4", "5"],
                "adapter_entrypoints": ["alpha.adapter: ingest"],
                "migration_order": ["1", "2", "3", "4", "5"],
                "minimum_versions": {"client": "7", "protocol": "2", "schema": "4", "config": "10"},
            },
            {
                "product_id": "beta",
                "supported_client_versions": ["1"],
                "supported_protocol_versions": ["1"],
                "supported_schema_versions": ["9"],
            },
        ],
    }
    document.update(overrides)
    return document


def _registry() -> ProductRegistry:
    return ProductRegistry(
        catalog=parse_product_catalog(_catalog_document()), policy=NumericPolicy()
    )


def _declaration(**overrides: str) -> ClientDeclaration:
    fields = {
        "product_id": "alpha",
        "protocol_version": "3",
        "schema_version": "5",
        "config_version": "10",
        "client_version": "8",
    }
    fields.update(overrides)
    return ClientDeclaration(**fields)


def test_catalog_parses_and_registry_queries_products() -> None:
    registry = _registry()

    assert registry.product_ids == ("alpha", "beta")
    record = registry.get("alpha")
    assert record is not None
    assert record.supported_schema_versions == ("4", "5")
    assert record.adapter_entrypoints == ("alpha.adapter: ingest",)
    assert record.minimum_version("config") == "10"
    assert registry.get("missing") is None


def test_compatible_declaration_is_accepted() -> None:
    decision = _registry().decide(_declaration())

    assert decision.kind is CompatibilityDecisionKind.COMPATIBLE
    assert decision.reason
    assert decision.migration_path == ()
    assert decision.minimum_version is None


def test_unregistered_product_is_rejected() -> None:
    decision = _registry().decide(_declaration(product_id="gamma"))

    assert decision.kind is CompatibilityDecisionKind.REJECTED
    assert "not registered" in decision.reason


def test_unsupported_schema_version_is_rejected_explicitly() -> None:
    decision = _registry().decide(_declaration(schema_version="6"))

    assert decision.kind is CompatibilityDecisionKind.REJECTED
    assert "schema" in decision.reason
    assert "'6'" in decision.reason


def test_unsupported_protocol_version_follows_policy_quarantine() -> None:
    decision = _registry().decide(_declaration(protocol_version="9"))

    assert decision.kind is CompatibilityDecisionKind.QUARANTINED


def test_unknown_client_version_is_rejected() -> None:
    decision = _registry().decide(_declaration(client_version="99"))

    assert decision.kind is CompatibilityDecisionKind.REJECTED


def test_older_client_version_requires_migration_to_minimum() -> None:
    decision = _registry().decide(_declaration(client_version="6"))

    assert decision.kind is CompatibilityDecisionKind.MIGRATION_REQUIRED
    assert decision.minimum_version == "7"
    assert decision.migration_path == ()


def test_older_schema_version_in_migration_order_carries_path() -> None:
    decision = _registry().decide(_declaration(schema_version="2"))

    assert decision.kind is CompatibilityDecisionKind.MIGRATION_REQUIRED
    assert decision.migration_path == ("3", "4")
    assert decision.minimum_version == "4"


def test_older_config_version_requires_migration_to_minimum() -> None:
    decision = _registry().decide(_declaration(config_version="9"))

    assert decision.kind is CompatibilityDecisionKind.MIGRATION_REQUIRED
    assert decision.minimum_version == "10"


def test_schema_version_beyond_migration_order_is_rejected() -> None:
    registry = ProductRegistry(
        catalog=parse_product_catalog(_catalog_document()),
        policy=NumericPolicy(),
    )
    decision = registry.decide(_declaration(schema_version="6"))

    assert decision.kind is CompatibilityDecisionKind.REJECTED


def test_incomparable_config_version_is_rejected() -> None:
    decision = _registry().decide(_declaration(config_version="ten"))

    assert decision.kind is CompatibilityDecisionKind.REJECTED


def test_migration_order_without_later_supported_version_is_rejected() -> None:
    catalog = parse_product_catalog(
        {
            "schema_version": PRODUCT_CATALOG_SCHEMA_VERSION,
            "products": [
                {
                    "product_id": "alpha",
                    "supported_client_versions": ["8"],
                    "supported_protocol_versions": ["3"],
                    "supported_schema_versions": ["4"],
                    "migration_order": ["2", "3"],
                }
            ],
        }
    )
    registry = ProductRegistry(catalog=catalog, policy=NumericPolicy())

    decision = registry.decide(_declaration(schema_version="3", protocol_version="3"))

    assert decision.kind is CompatibilityDecisionKind.REJECTED


def test_unknown_catalog_schema_version_is_refused() -> None:
    with pytest.raises(ProductRegistryVersionUnsupported):
        parse_product_catalog(_catalog_document(schema_version="techflex-product-catalog/2"))


def test_unknown_catalog_field_is_refused() -> None:
    with pytest.raises(ProductRegistryMalformed):
        parse_product_catalog(_catalog_document(guess_me=True))


def test_unknown_product_field_is_refused() -> None:
    document = _catalog_document()
    products = list(document["products"])
    products[0] = {**products[0], "extra": "nope"}
    with pytest.raises(ProductRegistryMalformed):
        parse_product_catalog(
            {"schema_version": PRODUCT_CATALOG_SCHEMA_VERSION, "products": products}
        )


def test_duplicate_product_id_is_refused() -> None:
    products = list(_catalog_document()["products"])
    products.append(dict(products[0]))
    with pytest.raises(ProductRegistryMalformed, match="unique"):
        parse_product_catalog(
            {"schema_version": PRODUCT_CATALOG_SCHEMA_VERSION, "products": products}
        )


def test_unknown_minimum_version_dimension_is_refused() -> None:
    document = _catalog_document()
    products = list(document["products"])
    products[0] = {**products[0], "minimum_versions": {"shader": "1"}}
    with pytest.raises(ProductRegistryMalformed):
        parse_product_catalog(
            {"schema_version": PRODUCT_CATALOG_SCHEMA_VERSION, "products": products}
        )


def test_declaration_with_unknown_field_is_refused() -> None:
    with pytest.raises(ProductRegistryMalformed):
        ClientDeclaration.from_document(
            {
                "product_id": "alpha",
                "protocol_version": "3",
                "schema_version": "5",
                "config_version": "10",
                "client_version": "8",
                "firmware": "1",
            }
        )


def test_declaration_with_missing_field_is_refused() -> None:
    with pytest.raises(ProductRegistryMalformed, match="missing"):
        ClientDeclaration.from_document(
            {
                "product_id": "alpha",
                "protocol_version": "3",
                "schema_version": "5",
                "config_version": "10",
            }
        )


def test_declaration_with_blank_field_is_refused() -> None:
    with pytest.raises(ProductRegistryMalformed):
        _declaration(schema_version="")


def test_policy_may_never_silently_accept_an_unsupported_version() -> None:
    class PermissivePolicy(NumericPolicy):
        def unsupported_disposition(
            self, *, dimension: str, version: str
        ) -> CompatibilityDecisionKind:
            return CompatibilityDecisionKind.COMPATIBLE

    registry = ProductRegistry(
        catalog=parse_product_catalog(_catalog_document()), policy=PermissivePolicy()
    )

    with pytest.raises(ProductRegistryMalformed):
        registry.decide(_declaration(schema_version="6"))


def test_migration_decision_without_path_or_minimum_is_invalid() -> None:
    with pytest.raises(ProductRegistryMalformed):
        CompatibilityDecision(
            kind=CompatibilityDecisionKind.MIGRATION_REQUIRED,
            product_id="alpha",
            reason="implied migration",
        )


def test_decisions_are_immutable() -> None:
    decision = _registry().decide(_declaration())

    with pytest.raises(AttributeError):
        decision.kind = CompatibilityDecisionKind.REJECTED  # type: ignore[misc]


def test_direct_record_construction_validates() -> None:
    with pytest.raises(ProductRegistryMalformed):
        ProductRecord(product_id="alpha")
    with pytest.raises(ProductRegistryMalformed):
        ProductRecord(
            product_id="alpha",
            supported_schema_versions=("4", "4"),
        )
    with pytest.raises(ProductRegistryMalformed):
        ProductRecord(
            product_id="alpha",
            supported_schema_versions=("4",),
            minimum_versions={"config": "  "},
        )
    catalog = ProductCatalog(
        products=(ProductRecord(product_id="a", supported_schema_versions=("1",)),)
    )
    assert catalog.schema_version == PRODUCT_CATALOG_SCHEMA_VERSION
    with pytest.raises(ProductRegistryVersionUnsupported):
        ProductCatalog(
            products=(),
            schema_version="techflex-product-catalog/0",
        )
