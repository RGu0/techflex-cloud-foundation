# Consumer Documentation

Markdown-first documentation set for applications consuming
`techflex-cloud-foundation` (RAY-367). Primary audience: engineers and agents
integrating the library.

## Contents

- [Getting Started](getting-started.md) — install, version policy, the
  vendored integration default, and an executable end-to-end example.
- Guides (by scenario, not by module):
  - [Cloud Access & Default Configuration](guides/cloud-access-and-default-config.md)
  - [Local Durability & Offline Operation](guides/local-durability-and-offline.md)
  - [Reliable Upload & Background Queue](guides/reliable-upload.md)
  - [License, Entitlement & Data Lifecycle](guides/license-and-lifecycle.md)
  - [Operations, Diagnostics & Testing Support](guides/operations-and-diagnostics.md)
- [Independent consumer validation](independent-consumer-validation.md) —
  how the wheel is proven consumable without the source tree.
- [Boundaries & Troubleshooting](boundaries-and-troubleshooting.md) —
  application vs library ownership, provisional capabilities, and the error
  catalogue.

Planned (RAY-367 scope `docs-api-reference`): the per-symbol API reference.

## Conventions

- Every code listing either is executed in CI or names the test file it
  comes from; neither may silently drift from the code.
- The v1 public API is exactly
  `techflex_cloud_foundation/__init__.py::__all__`.
- Capabilities proven by a single consuming product are marked provisional
  until a second consumer confirms them.
