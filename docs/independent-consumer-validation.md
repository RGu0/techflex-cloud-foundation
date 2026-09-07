# Independent consumer validation

`techflex-cloud-foundation` `0.1.1` was installed and executed by the separate,
private repository [`RGu0/techflex-foundation-consumer-validation`](https://github.com/RGu0/techflex-foundation-consumer-validation), at commit
`2a1f569`.

The consumer pins the published wheel by release, filename, and SHA-256:

- release: `v0.1.1`
- wheel: `techflex_cloud_foundation-0.1.1-py3-none-any.whl`
- SHA-256: `26a8647541398ab95c8d039c86e8b440815318960686ba94174c6043bb469107`

Its validation flow downloads the private release asset, verifies the digest,
creates a clean locked environment, and runs `consumer_smoke.py`. The smoke
program imports only public symbols from `techflex_cloud_foundation`, confirms
the installed distribution version, and asserts that no legacy `client` module
is available. It contains no FeetForcePlate code, source checkout, business
adapter, credential, activation material, or customer data.

This proves versioned artifact consumption for a non-FeetForcePlate consumer.

## Current release pin

The current release a consumer should pin is:

- release: `v0.2.0`
- wheel: `techflex_cloud_foundation-0.2.0-py3-none-any.whl`
- SHA-256: `1dd34fb4902fb7359af346e153123e8db12befc6ae8a9de2105e11f80af74303`

## Consumer CI credential

A consumer CI that downloads the private release asset authenticates with a
fine-grained personal access token:

- **Issuer**: the `RGu0/techflex-cloud-foundation` repository owner.
- **Scope**: `contents:read` on `RGu0/techflex-cloud-foundation` only — no
  other repository, no write permission.
- **Storage**: a secret in the consuming repository's own CI configuration;
  the token itself is never committed anywhere.
- **Rotation**: every 90 days, and immediately when a maintainer with access
  to the secret changes.

This decision grants the consumer CI exactly the private release assets and
nothing else; it does not widen access to source, workflows, or settings.
