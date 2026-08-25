# Private Foundation Extraction Design

**Issue:** RAY-271  
**Requirement revision:** R2  
**Scope:** `repository-extraction-contracts`

## Goal

Make `techflex-cloud-foundation` a private, independently buildable Python
distribution at version `0.1.1`.  It must retain only the stable cloud,
authorization, trust, reliability, diagnostics, and optional server-runtime
contracts already validated in FeetForcePlate.

## Source boundary

The source of record is the RAY-269 validated package at:

```text
packages/techflex-cloud-foundation/
```

The extracted repository contains these public implementation modules, without
renaming their import path:

```text
src/techflex_cloud_foundation/
  __init__.py
  database.py
  diagnostics.py
  entitlement.py
  reliability.py
  transport.py
  py.typed
```

It also contains the package README and its standalone Hatch build metadata.
The package name remains `techflex-cloud-foundation`; the Python import remains
`techflex_cloud_foundation`.

The repository must not contain `client/`, `cloud/`, `shared/`, device code,
FeetForcePlate reports, business schemas, SQL/RLS/migrations, application
routes, raw frames, credentials, activation codes, or customer data.

## Distribution and dependencies

The repository root is the distributable project rather than a workspace
member.  `pyproject.toml` declares version `0.1.1`, Python `>=3.11`, and only
the runtime dependencies `cryptography>=42,<51` and `httpx>=0.28,<1`.

`asyncpg>=0.30,<1` remains only in the optional `server` extra.  Installing
the default package must not install an async database driver and cannot carry
database credentials or License private keys.

The build creates both a wheel and an sdist.  `dist/`, virtual environments,
coverage files, and generated release evidence stay ignored.  A lockfile and
the committed Python version pin make test, lint, and build reproducible.

## Runtime and release entrypoints

The root `dev` and `dev.ps1` implement only the governed `setup`, `test`,
`lint`, and `build` actions recorded in `.ai-project/project.yaml`.

`build` performs the following in one invocation:

1. installs the locked development environment;
2. builds wheel and sdist;
3. generates non-secret release evidence with dependency inventory, source
   revision, artifact SHA-256 values, and offline performance measurements;
4. compares the package transport against the preserved
   `legacy-httpx-client/1` workload and rejects P95 overhead above 5 percent
   or peak-memory overhead above 10 percent.

The preserved workload remains executable benchmark code in the release
evidence tool; it is not FeetForcePlate application code and does not require
the FeetForcePlate repository at build time.  The provenance record identifies
the approved pre-extraction source revision `6e76234f0ec466f4fa62f6368ea646ec8b37979e`.

## Tests and isolation checks

The migration retains and refactors the RAY-269 public-contract tests for:

- reliable-operation persistence and interrupted lease recovery;
- retry-after handling;
- authorized transport refresh behavior;
- supplied correlation-ID reuse;
- signed, monotonic trust-bundle verification;
- immutable, application-scoped entitlement decisions.

Release tests verify SBOM shape, artifact checksums, source provenance,
performance-budget refusal, and the vulnerability-audit command contract.

Two new repository-local checks are required:

1. **Source isolation:** scan tracked Python/configuration files and fail on
   `feetforceplate`, `client.`, `cloud.`, `shared.`, or an absolute
   FeetForcePlate path outside intentionally documented historical provenance.
2. **Artifact consumer:** build the distributions, create a clean temporary
   environment, install the wheel by file path with no source-tree path on
   `PYTHONPATH`, and run a small consumer that imports only symbols exported by
   `techflex_cloud_foundation`.

The consumer fixture exercises `SecureTransport`, `ReliableOperation`,
`SqliteOperationStore`, `RetryPolicy`, `TrustBundle`, and
`EntitlementDecision`; it imports no private module and no FeetForcePlate
module.

## CI and evidence

GitHub Actions runs the locked test, lint, and build actions on macOS, Ubuntu,
and Windows.  The release job additionally runs a strict dependency audit,
archives the wheel, sdist, and redacted release evidence, and rejects a failed
performance comparison.

Evidence records only package version, source revision, dependency names and
versions, checksums, benchmark summaries, timestamps, and correlation-free
test identifiers.  It never contains secrets, credentials, customer data,
activation data, raw payloads, or private keys.

## Non-goals and follow-up scopes

This scope does not change FeetForcePlate imports or lockfiles, and it does
not publish to a remote private PyPI registry.  Those are respectively
`feetforceplate-versioned-consumer` and a future, separately approved release
scope after the company registry is chosen.  The first scope only proves that
the private source repository independently builds an installable `0.1.1`
artifact.
