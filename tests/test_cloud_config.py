from __future__ import annotations

import pytest

from techflex_cloud_foundation import (
    CloudConfigChannelUnknown,
    CloudConfigMalformed,
    CloudConfigVersionUnsupported,
    load_default_cloud_config,
    parse_cloud_default_config,
)


def _document(**overrides: object) -> dict[str, object]:
    document: dict[str, object] = {
        "schema_version": "feetforceplate-client-cloud-default/1",
        "channel": "integration",
        "api_base_url": "https://39.105.216.113:7443",
        "license_key_id": "license/1",
        "ca_bundle_resource": "cloud-ca.pem",
        "license_public_key_resource": "license-public.key",
    }
    document.update(overrides)
    return document


def test_default_load_resolves_vendored_integration_bundle() -> None:
    config = load_default_cloud_config()

    assert config.channel == "integration"
    assert config.api_base_url == "https://39.105.216.113:7443"
    assert config.license_key_id == "license/1"
    assert config.ca_bundle_pem.startswith(b"-----BEGIN CERTIFICATE-----")
    assert len(config.license_public_key) == 32


def test_unknown_channel_is_refused_never_guessed() -> None:
    with pytest.raises(CloudConfigChannelUnknown, match="production"):
        load_default_cloud_config("production")


def test_parse_rejects_unsupported_schema_version() -> None:
    with pytest.raises(CloudConfigVersionUnsupported, match="schema_version"):
        parse_cloud_default_config(_document(schema_version="other/9"))


def test_parse_requires_https_base_url() -> None:
    with pytest.raises(CloudConfigMalformed, match="https"):
        parse_cloud_default_config(_document(api_base_url="http://example.test"))


def test_parse_requires_all_fields() -> None:
    document = _document()
    del document["license_key_id"]
    with pytest.raises(CloudConfigMalformed, match="license_key_id"):
        parse_cloud_default_config(document)


def test_application_supplied_document_uses_the_same_validation_path() -> None:
    meta = parse_cloud_default_config(
        _document(channel="production", api_base_url="https://cloud.example.test")
    )

    resolved = meta.resolve(
        lambda name: (
            b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            if name.endswith(".pem")
            else b"k" * 32
        )
    )

    assert resolved.channel == "production"
    assert resolved.api_base_url == "https://cloud.example.test"


def test_resolve_rejects_non_pem_ca_bundle() -> None:
    meta = parse_cloud_default_config(_document())
    with pytest.raises(CloudConfigMalformed, match="PEM"):
        meta.resolve(lambda name: b"not-a-pem")


def test_resolve_rejects_wrong_length_license_key() -> None:
    meta = parse_cloud_default_config(_document())
    with pytest.raises(CloudConfigMalformed, match="32-byte"):
        meta.resolve(
            lambda name: (
                b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                if name.endswith(".pem")
                else b"short"
            )
        )
