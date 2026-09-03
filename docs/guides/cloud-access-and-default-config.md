# Guide: Cloud Access & Default Configuration

Modules: `cloud_config`, `transport`, `tokens`.
Reference tests: `tests/test_cloud_config.py`, `tests/test_public_contracts.py`.

## When to use

Any time the application talks to the cloud: resolving which endpoint and
trust material to use, making authenticated HTTPS calls, and issuing or
verifying service tokens.

## 1. Resolve the cloud configuration

```python
from techflex_cloud_foundation import load_default_cloud_config

config = load_default_cloud_config()          # vendored "integration" channel
config.api_base_url                           # "https://39.105.216.113:7443"
config.ca_bundle_pem                          # PEM bytes for TLS verification
config.license_public_key                     # raw 32-byte license key
```

Enforced semantics (see `tests/test_cloud_config.py`):

- Only vendored channels resolve; anything else raises
  `CloudConfigChannelUnknown` — endpoints are never guessed.
- Your own environment: `parse_cloud_default_config(document)` validates the
  same schema (`feetforceplate-client-cloud-default/1`), then
  `meta.resolve(read_resource)` binds resource bytes. Non-`https://` base
  URLs raise `CloudConfigMalformed`; unknown schema versions raise
  `CloudConfigVersionUnsupported`.

## 2. Make authenticated requests

`SecureTransport` is a strict httpx wrapper: `trust_env=False` (proxy and
cert environment variables are ignored), pinned timeouts, caller-supplied
correlation IDs are reused, never regenerated
(`tests/test_public_contracts.py::test_secure_transport_reuses_a_supplied_correlation_id_without_generating_one`).

`AuthorizedTransport` adds bearer auth on top. Your `TokenProvider`
implements `current_access_token()` and `refresh()`; after a 401 the token
is refreshed **at most once** per request
(`test_authorized_transport_refreshes_at_most_once_after_401`):

```python
from techflex_cloud_foundation import AuthorizedTransport, SecureTransport

with SecureTransport(config.api_base_url) as transport:
    response = AuthorizedTransport(transport, tokens).request("GET", "/v1/check")
```

For the integration channel's private CA, pass a CA bundle path via
`SecureTransport(base_url, verify=ca_bundle_path)`; materialize
`config.ca_bundle_pem` to a file with `atomic_write` first.

Credential storage is the application's `CredentialVault` implementation
(`get`/`set`/`delete`); the library defines the protocol, not the storage.

## 3. Issue and verify service tokens

`HmacTokenCodec` (HS256) issues and verifies compact tokens for one key id,
token type, and audience (secrets must be at least 32 bytes). Failures are
typed: `TokenMalformed`, `TokenSignatureInvalid`, `TokenHeaderMismatch`,
`TokenAudienceMismatch`, `TokenExpired` (`tests/test_tokens.py`).

```python
from techflex_cloud_foundation import HmacTokenCodec

codec = HmacTokenCodec(secret=secret, key_id="k1", token_type="access", audience="api")
token = codec.issue({"subject": "device-1"})
claims = codec.verify(token)   # raises TokenExpired / TokenAudienceMismatch / ...
```

## Invariants

- `trust_env=False`: no ambient proxy or CA environment leaks into requests.
- One 401 refresh per request; loops are impossible.
- Correlation IDs propagate end-to-end; supply your own to join with logs.
- Token verification failures are specific exceptions, never boolean False.
