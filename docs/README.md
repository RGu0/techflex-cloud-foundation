# Consumer Documentation

Markdown-first documentation set for applications consuming
`techflex-cloud-foundation` (RAY-367). Primary audience: engineers and agents
integrating the library.

## Contents

- [Getting Started](getting-started.md) — install, version policy, the
  vendored integration default, and an executable end-to-end example.
- Guides (by scenario, not by module):
  - [Cloud Access & Default Configuration](guides/cloud-access-and-default-config.md)
  - [正式入口与证书轮换验收](guides/public-ingress-and-certificate-rotation.md)
  - [Independent Installations & Refresh Families](guides/multi-installation-isolation.md)
  - [Local Durability & Offline Operation](guides/local-durability-and-offline.md)
  - [Reliable Upload & Background Queue](guides/reliable-upload.md)
  - [Stored Content Verification & Receipt Migration](guides/ingestion-content-verification.md)
  - [License, Entitlement & Data Lifecycle](guides/license-and-lifecycle.md)
  - [Operations, Diagnostics & Testing Support](guides/operations-and-diagnostics.md)
  - [Diagnostic Upload & Support-Access Boundaries](guides/diagnostics-adapter-boundary.md)
  - [智能鞋垫产品接入契约](guides/insole-product-contract.md)
  - [设备身份、证明与机构库存边界](guides/device-inventory-boundary.md)
  - [Replay Authentication & New-Effect Admission](guides/replay-admission-contract.md)
  - [Tenant Data & Application Subject Records](guides/tenant-data-contract.md)
  - [Foundation Release Preparation](guides/foundation-release.md)
- [API Reference](api-reference.md) — every exported symbol, generated from
  docstrings and drift-checked in CI.
- [Portable contract vectors](contracts/README.md) — frozen JSON inputs and
  expectations for existing manifest/receipt, error and license contracts,
  available in the sdist for other-language implementations.
- [Independent consumer validation](independent-consumer-validation.md) —
  how the wheel is proven consumable without the source tree.
- [Boundaries & Troubleshooting](boundaries-and-troubleshooting.md) —
  application vs library ownership, provisional capabilities, and the error
  catalogue.

## Conventions

- Every code listing either is executed in CI or names the test file it
  comes from; neither may silently drift from the code.
- The v1 public API is exactly
  `techflex_cloud_foundation/__init__.py::__all__`.
- Capabilities proven by a single consuming product are marked provisional
  until a second consumer confirms them.
