# Independent consumer validation

`techflex-cloud-foundation` `0.1.1` was installed and executed by the separate,
private repository [`RGu0/techflex-foundation-consumer-validation`](https://github.com/RGu0/techflex-foundation-consumer-validation), at commit
`2a1f569`.

The consumer pins the published wheel by release, filename, and SHA-256:

- release: `v0.1.1`
- wheel: `techflex_cloud_foundation-0.1.1-py3-none-any.whl`
- SHA-256: `26a8647541398ab95c8d039c86e8b440815318960686ba94174c6043bb469107`

Its validation flow downloads the release asset, verifies the digest,
creates a clean locked environment, and runs `consumer_smoke.py`. The smoke
program imports only public symbols from `techflex_cloud_foundation`, confirms
the installed distribution version, and asserts that no legacy `client` module
is available. It contains no FeetForcePlate code, source checkout, business
adapter, credential, activation material, or customer data.

This proves versioned artifact consumption for a non-FeetForcePlate consumer.

## Current release pin

The current release a consumer should pin is:

- release: `v0.3.0`
- wheel: `techflex_cloud_foundation-0.3.0-py3-none-any.whl`
- SHA-256: `6790d4f770a0ad0756885f6b58555d4da8c7ef3aad3274b6df8f583b6e63e089`

## Consumer CI credential: none required today

`RGu0/techflex-cloud-foundation` is a public repository, and its release
assets download without authentication. Verified 2026-09-07: an
unauthenticated download of the `v0.2.0` wheel returned exactly the pinned
digest above. A consumer CI needs no credential to install the pinned wheel.

Introduce a credential only when one of these triggers occurs:

- the repository becomes private;
- unauthenticated download rate limits begin failing CI.

The scheme to apply then is a fine-grained personal access token: issued by
the `RGu0/techflex-cloud-foundation` repository owner, `contents:read` on
`RGu0/techflex-cloud-foundation` only — no other repository, no write
permission — stored as a secret in the consuming repository's own CI
configuration (never committed anywhere), rotated every 90 days and
immediately when a maintainer with access to the secret changes.
