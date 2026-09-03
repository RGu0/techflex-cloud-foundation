# Techflex Cloud Foundation

Private reusable cloud, authorization, security, and reliable-operation
foundation for Techflex applications. The public Python API is exposed only
from the `techflex_cloud_foundation` package.

This repository is governed through Linear delivery scopes and GitHub pull
requests. Application-specific adapters, business schemas, credentials, and
customer data do not belong here. Public material that confirmed requirements
share across environments — CA certificates, license public keys, and default
endpoint configuration — may be vendored under `config/`; private keys,
secrets, and customer data remain prohibited.

## Public cloud defaults

`config/public-cloud-defaults/` vendors the shared default cloud configuration
first proven by FeetForcePlate (schema
`feetforceplate-client-cloud-default/1`):

- `cloud-default.json` selects channel `integration` with
  `api_base_url` pointing at the integration entrypoint;
- `cloud-ca.pem` is the private root CA for that channel;
- `license-public.key` is the raw 32-byte license verification public key.

This is the **integration** channel default, not a production entrypoint: an
integration IP, a private/self-signed CA, and a nonstandard port do not
constitute production ingress (RAY-341 invariants). Evidence currently comes
from a single consumer (FeetForcePlate), so the bundle is **provisional**
until a second consumer confirms it.

The same bundle also ships inside the wheel as package resources, so a
consuming application can develop, test, and run seed-stage integrations with
zero local setup:

```python
from techflex_cloud_foundation import load_default_cloud_config

default = load_default_cloud_config()          # channel="integration"
default.api_base_url                          # integration entrypoint
default.ca_bundle_pem                         # PEM bytes for TLS verification
default.license_public_key                    # raw 32-byte license key
```

Only vendored channels resolve; an unknown channel raises
`CloudConfigChannelUnknown` rather than guessing an endpoint. An application
moving to its own environment validates its own document through
`parse_cloud_default_config` — the same validator the vendored bundle uses —
and supplies its own resource bytes. Production material is never vendored
into this library.

## Platform deployment profiles (CP-01)

`parse_deployment_profile` validates a versioned deployment profile document
(`techflex-platform-deployment/1`) covering environment, region, public
ingress, database roles, KMS reference, logical-bucket mappings, retention
tiers, and registered products. The schema carries **references, never
secrets**: databases, signing keys, and cloud credentials are named through
`SecretRef` (`env` / `file` / `kms` provider + locator); an inline field whose
name implies secret material is refused, as are placeholder values, unknown
fields, and unknown schema versions. Production ingress must be a public-CA
hostname on 443 — an IP literal, private CA, or temporary port is an
integration channel, never production ingress. Logical bucket roles share a
physical bucket only when encryption, versioning, and retention policies are
identical, and `raw-immutable` buckets must keep versioning on. A validated
`DeploymentProfile` is immutable and serializes to a reproducible canonical
form whose complete SHA-256 `digest()` can anchor snapshot receipts. Concrete
deployment values (cloud account, domain, certificate, KMS key, physical
bucket names) stay with the deploying application and are never vendored here.

## Private package use

Applications consume a released, versioned `techflex-cloud-foundation` wheel
and implement their own business adapters. They must not copy or alter the
foundation’s transport, authorization, credential, trust, or operation-store
implementation. Use `./dev test`, `./dev lint`, and `./dev build` (or
`./dev.ps1 <action>` on Windows) for the locked quality gates.

The build creates only temporary artifacts and redacted release evidence:
revision, dependency inventory, checksums, and benchmark summaries. It never
records credentials, activation material, customer data, or raw frames.
