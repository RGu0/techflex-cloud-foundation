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

## Private package use

Applications consume a released, versioned `techflex-cloud-foundation` wheel
and implement their own business adapters. They must not copy or alter the
foundation’s transport, authorization, credential, trust, or operation-store
implementation. Use `./dev test`, `./dev lint`, and `./dev build` (or
`./dev.ps1 <action>` on Windows) for the locked quality gates.

The build creates only temporary artifacts and redacted release evidence:
revision, dependency inventory, checksums, and benchmark summaries. It never
records credentials, activation material, customer data, or raw frames.
