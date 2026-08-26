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
It does not grant the consumer CI a cross-repository release credential; that
credential remains a separately scoped, least-privilege deployment decision.
