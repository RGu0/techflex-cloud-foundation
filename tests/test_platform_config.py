from __future__ import annotations

import pytest

from techflex_cloud_foundation import (
    BucketRole,
    Environment,
    PlatformConfigMalformed,
    PlatformConfigVersionUnsupported,
    SecretProvider,
    parse_deployment_profile,
)
from techflex_cloud_foundation.platform_config import PLATFORM_CONFIG_SCHEMA_VERSION


def _document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": PLATFORM_CONFIG_SCHEMA_VERSION,
        "environment": "integration",
        "region": "cn-beijing",
        "ingress": {
            "public_base_url": "https://39.105.216.113:7443",
            "port": 7443,
            "public_ca": False,
        },
        "kms": {"provider": "kms", "locator": "alias/platform"},
        "databases": {
            "migration": {"provider": "env", "locator": "PLATFORM_MIGRATION_DSN"},
            "serving": {"provider": "env", "locator": "PLATFORM_SERVING_DSN"},
        },
        "buckets": [
            {
                "role": "raw-immutable",
                "physical_bucket": "raw-bucket",
                "policy": {
                    "encryption": "sse-kms",
                    "versioning": True,
                    "retention": "archival",
                },
            },
            {
                "role": "derived",
                "physical_bucket": "derived-bucket",
                "policy": {
                    "encryption": "sse-aes256",
                    "versioning": False,
                    "retention": "ephemeral",
                },
            },
        ],
        "products": [
            {
                "product_id": "feetforceplate",
                "supported_schema_versions": ["feetforceplate-client-cloud-default/1"],
            }
        ],
    }
    document.update(overrides)
    return document


def _production_document() -> dict[str, object]:
    document = _document(environment="production")
    document["ingress"] = {
        "public_base_url": "https://cloud.example.test",
        "port": 443,
        "public_ca": True,
    }
    return document


def test_valid_integration_profile_parses() -> None:
    profile = parse_deployment_profile(_document())

    assert profile.environment is Environment.INTEGRATION
    assert profile.region == "cn-beijing"
    assert profile.ingress.port == 7443
    assert profile.ingress.host_is_ip_literal
    assert profile.kms.provider is SecretProvider.KMS
    assert set(profile.databases) == {"migration", "serving"}
    assert [binding.role for binding in profile.buckets] == [
        BucketRole.RAW_IMMUTABLE,
        BucketRole.DERIVED,
    ]
    assert profile.products[0].product_id == "feetforceplate"


def test_round_trip_canonical_form_is_reproducible() -> None:
    profile = parse_deployment_profile(_document())
    reparsed = parse_deployment_profile(profile.to_document())

    assert reparsed == profile
    assert reparsed.canonical_bytes() == profile.canonical_bytes()
    assert reparsed.digest() == profile.digest()


def test_unknown_schema_version_is_refused() -> None:
    with pytest.raises(PlatformConfigVersionUnsupported, match="schema_version"):
        parse_deployment_profile(_document(schema_version="techflex-platform-deployment/9"))


def test_unknown_top_level_field_is_refused() -> None:
    with pytest.raises(PlatformConfigMalformed, match="unknown field"):
        parse_deployment_profile(_document(future_field="x"))


def test_placeholder_value_is_refused() -> None:
    with pytest.raises(PlatformConfigMalformed, match="placeholder"):
        parse_deployment_profile(_document(region="changeme"))


def test_inline_secret_field_is_refused() -> None:
    document = _document()
    document["ingress"]["tls_private_key"] = "-----BEGIN PRIVATE KEY-----"  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="SecretRef"):
        parse_deployment_profile(document)


def test_database_dsn_cannot_be_inline() -> None:
    document = _document()
    document["databases"] = {"serving": "postgresql://u:p@host/db"}  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="secret ref"):
        parse_deployment_profile(document)


def test_database_roles_must_reference_distinct_secrets() -> None:
    document = _document()
    document["databases"] = {  # type: ignore[index]
        "migration": {"provider": "env", "locator": "SHARED_DSN"},
        "serving": {"provider": "env", "locator": "SHARED_DSN"},
    }
    with pytest.raises(PlatformConfigMalformed, match="distinct"):
        parse_deployment_profile(document)


def test_env_secret_ref_locator_must_be_an_env_var_name() -> None:
    document = _document()
    document["databases"] = {  # type: ignore[index]
        "migration": {"provider": "env", "locator": "postgresql://u:p@host/db"},
        "serving": {"provider": "env", "locator": "PLATFORM_SERVING_DSN"},
    }
    with pytest.raises(PlatformConfigMalformed, match="environment variable name"):
        parse_deployment_profile(document)


def test_production_requires_hostname_port_443_and_public_ca() -> None:
    with pytest.raises(PlatformConfigMalformed, match="hostname"):
        parse_deployment_profile(_production_document() | {"ingress": {
            "public_base_url": "https://203.0.113.10",
            "port": 443,
            "public_ca": True,
        }})
    with pytest.raises(PlatformConfigMalformed, match="443"):
        parse_deployment_profile(_production_document() | {"ingress": {
            "public_base_url": "https://cloud.example.test",
            "port": 8443,
            "public_ca": True,
        }})
    with pytest.raises(PlatformConfigMalformed, match="publicly trusted CA"):
        parse_deployment_profile(_production_document() | {"ingress": {
            "public_base_url": "https://cloud.example.test",
            "port": 443,
            "public_ca": False,
        }})


def test_non_https_ingress_is_refused() -> None:
    document = _document()
    document["ingress"]["public_base_url"] = "http://cloud.example.test"  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="https"):
        parse_deployment_profile(document)


def test_raw_immutable_bucket_requires_versioning() -> None:
    document = _document()
    document["buckets"][0]["policy"]["versioning"] = False  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="versioning"):
        parse_deployment_profile(document)


def test_bucket_merge_requires_identical_policy() -> None:
    document = _document()
    merged = dict(document["buckets"][1])  # type: ignore[index]
    merged["physical_bucket"] = "raw-bucket"
    document["buckets"] = [document["buckets"][0], merged]  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="identical"):
        parse_deployment_profile(document)


def test_bucket_merge_with_identical_policy_is_allowed() -> None:
    document = _document()
    merged = {
        "role": "derived",
        "physical_bucket": "raw-bucket",
        "policy": {
            "encryption": "sse-kms",
            "versioning": True,
            "retention": "archival",
        },
    }
    document["buckets"] = [document["buckets"][0], merged]  # type: ignore[index]

    profile = parse_deployment_profile(document)

    assert {binding.physical_bucket for binding in profile.buckets} == {"raw-bucket"}


def test_duplicate_bucket_role_is_refused() -> None:
    document = _document()
    document["buckets"] = [document["buckets"][0], document["buckets"][0]]  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="unique"):
        parse_deployment_profile(document)


def test_duplicate_product_id_is_refused() -> None:
    document = _document()
    document["products"] = [document["products"][0], document["products"][0]]  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="unique"):
        parse_deployment_profile(document)


def test_unknown_bucket_role_is_refused() -> None:
    document = _document()
    document["buckets"][0]["role"] = "everything"  # type: ignore[index]
    with pytest.raises(PlatformConfigMalformed, match="role"):
        parse_deployment_profile(document)


def test_product_without_schema_version_is_refused() -> None:
    document = _document()
    document["products"] = [{"product_id": "gait-imu", "supported_schema_versions": []}]
    with pytest.raises(PlatformConfigMalformed, match="at least one schema version"):
        parse_deployment_profile(document)
