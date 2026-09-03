"""Vendored default cloud configuration and its schema validator (RAY-364 R2).

The wheel carries one public default bundle under ``defaults/integration/``,
so an application can develop, test, and run seed-stage integrations against
the shared integration channel with zero local setup::

    from techflex_cloud_foundation import load_default_cloud_config

    default = load_default_cloud_config()
    default.api_base_url      # integration entrypoint
    default.ca_bundle_pem     # PEM bytes for TLS verification
    default.license_public_key  # raw 32-byte license verification key

An application moving to its own environment parses its own document through
the same validator and supplies its own resource bytes; production material
is never vendored into this library:

    meta = parse_cloud_default_config(json.loads(path.read_text()))
    config = meta.resolve(lambda name: (config_dir / name).read_bytes())

Invariants carried over from RAY-341:

- The vendored default is the ``integration`` channel only; an integration
  IP, a private CA, and a nonstandard port never constitute production
  ingress.
- Unknown channels are refused, never guessed.
- The bundle is provisional until a second consuming product confirms it.
"""

from __future__ import annotations

from dataclasses import dataclass
from importlib import resources
import json
from typing import Any, Callable, Mapping

SUPPORTED_SCHEMA_VERSION = "feetforceplate-client-cloud-default/1"
DEFAULT_CHANNEL = "integration"
_VENDORED_CHANNELS = frozenset({DEFAULT_CHANNEL})


class CloudConfigError(Exception):
    """Base class for cloud default configuration failures."""


class CloudConfigMalformed(CloudConfigError):
    """The document or a referenced resource is structurally invalid."""


class CloudConfigVersionUnsupported(CloudConfigError):
    """The document declares a schema version this build refuses."""


class CloudConfigChannelUnknown(CloudConfigError):
    """The requested channel has no vendored default bundle."""


def _require_str(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value:
        raise CloudConfigMalformed(f"{field_name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class CloudDefaultConfigMeta:
    """A validated cloud default document, before resource resolution."""

    schema_version: str
    channel: str
    api_base_url: str
    license_key_id: str
    ca_bundle_resource: str
    license_public_key_resource: str

    def resolve(self, read_resource: Callable[[str], bytes]) -> CloudDefaultConfig:
        """Resolve the named resources into an immutable config.

        ``read_resource`` receives the resource name exactly as the document
        declares it and returns its bytes; application-supplied documents use
        their own directories, never library internals.
        """
        ca_bundle_pem = read_resource(self.ca_bundle_resource)
        license_public_key = read_resource(self.license_public_key_resource)
        if not ca_bundle_pem.startswith(b"-----BEGIN CERTIFICATE-----"):
            raise CloudConfigMalformed(
                f"{self.ca_bundle_resource} must be a PEM certificate bundle"
            )
        if len(license_public_key) != 32:
            raise CloudConfigMalformed(
                f"{self.license_public_key_resource} must be a raw 32-byte public key"
            )
        return CloudDefaultConfig(
            meta=self,
            ca_bundle_pem=ca_bundle_pem,
            license_public_key=license_public_key,
        )


@dataclass(frozen=True)
class CloudDefaultConfig:
    """A validated cloud default with its resource bytes resolved."""

    meta: CloudDefaultConfigMeta
    ca_bundle_pem: bytes
    license_public_key: bytes

    @property
    def channel(self) -> str:
        return self.meta.channel

    @property
    def api_base_url(self) -> str:
        return self.meta.api_base_url

    @property
    def license_key_id(self) -> str:
        return self.meta.license_key_id


def parse_cloud_default_config(document: Mapping[str, Any]) -> CloudDefaultConfigMeta:
    """Validate a cloud default document against the supported schema.

    Application-injected documents go through the exact same validation path
    as the vendored bundle.
    """
    schema_version = _require_str(
        document.get("schema_version"), field_name="schema_version"
    )
    if schema_version != SUPPORTED_SCHEMA_VERSION:
        raise CloudConfigVersionUnsupported(
            f"schema_version {schema_version!r} is not supported; "
            f"this build accepts only {SUPPORTED_SCHEMA_VERSION!r}"
        )
    channel = _require_str(document.get("channel"), field_name="channel")
    api_base_url = _require_str(
        document.get("api_base_url"), field_name="api_base_url"
    )
    if not api_base_url.startswith("https://"):
        raise CloudConfigMalformed("api_base_url must be an https:// URL")
    return CloudDefaultConfigMeta(
        schema_version=schema_version,
        channel=channel,
        api_base_url=api_base_url,
        license_key_id=_require_str(
            document.get("license_key_id"), field_name="license_key_id"
        ),
        ca_bundle_resource=_require_str(
            document.get("ca_bundle_resource"), field_name="ca_bundle_resource"
        ),
        license_public_key_resource=_require_str(
            document.get("license_public_key_resource"),
            field_name="license_public_key_resource",
        ),
    )


def load_default_cloud_config(channel: str = DEFAULT_CHANNEL) -> CloudDefaultConfig:
    """Load the vendored default bundle for ``channel``.

    Only channels shipped inside the wheel resolve; anything else is refused
    so a caller can never silently land on a guessed endpoint.
    """
    if channel not in _VENDORED_CHANNELS:
        raise CloudConfigChannelUnknown(
            f"no vendored default bundle for channel {channel!r}; "
            "supply an application configuration through "
            "parse_cloud_default_config instead"
        )
    bundle_dir = resources.files("techflex_cloud_foundation").joinpath(
        f"defaults/{channel}"
    )
    document = json.loads(bundle_dir.joinpath("cloud-default.json").read_bytes())
    meta = parse_cloud_default_config(document)
    if meta.channel != channel:
        raise CloudConfigMalformed(
            f"vendored bundle for {channel!r} declares channel {meta.channel!r}"
        )
    return meta.resolve(lambda name: bundle_dir.joinpath(name).read_bytes())
