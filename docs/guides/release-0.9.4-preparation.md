# Foundation 0.9.4 release preparation

RAY-984 R1, `release-094`. On 2026-11-16 America/Los_Angeles the user authorized
preparation, validation, a PR and independent review. **Merge and publication each
require separate confirmation.** This document prepares a release; it does not
authorize a tag, asset upload, runtime pin, deployment or host operation.

## Included changes and boundaries

The baseline is PR #121, merge `690159505e7d497b7209903c754f2cdccce434ec`,
after the published `v0.9.3` at `2c50bc32d8e5528f24aa01e7a95341315fc4655b`.
The latter release was published on 2026-11-12 America/Los_Angeles
(2026-11-13 02:18:55 UTC). Its assets remain unchanged.

0.9.4 prepares the already merged `server.observability` modules (`events`,
`alerts`, `uploader`, `diagnostics`), source tests and byte-identical
`migrations/0001_ops.sql`. These remain distinct from the top-level CP-10
`observability.py` contracts. There is no new HTTP route or runtime composition.
See [server HTTP routes](server-http-routes.md#operations-observability-serverobservability).

The SQL is **package data only** and is excluded from `DEFAULT_PLAN`. Its SHA-256
is `f0fafe723b26767ec03103796c8a9c6af0b25d8425f448d90c1a572eb5afa5d1`.
The main plan already creates a different `ops.outbox_events`; the carried SQL
cannot be applied as-is to a plan-migrated database. Do not apply it as part of
release acceptance. This release adds no main-plan migration.

The baseline also contains the project lock's `opentelemetry-api` 1.45.2 patch
for CVE-2026-126360. This is a project-lock fact, not a claim that the wheel pins
every transitive consumer dependency. Deployment locks and consumer upgrades
remain separately scoped. Unmerged Dependabot PR #120 is not included.

## Candidate acceptance before merge

Use the registered Worktree and governed `project_command.py` actions. Record the
exact clean PR head, R1 and source comparison to `v0.9.3` under
`.project-context/evidence/ray-984/release-094/`.

1. Run governed setup/lint/test/build and retain wheel, sdist and
   `release-evidence.json` in an absolute, empty local `FOUNDATION_RELEASE_DIR`.
   Verify artifact digests and the evidence's source revision and lock digest.
2. Install that actual wheel into a new isolated Python environment with the
   reviewed locked dependencies. Verify version 0.9.4, the installed module
   location outside this checkout, all four observability imports and their
   retained source tests. A source-tree import is not wheel acceptance.
3. Read the SQL from both wheel/sdist and the installed package and verify its
   digest. Compare installed `DEFAULT_PLAN` to the baseline and prove this SQL
   is absent, without creating a database or running SQL.
4. Independently review the exact head and require all final Ubuntu/macOS/Windows
   CI checks, including the mandatory PostgreSQL test and dependency audit.
   Keep the PR draft until review, candidate acceptance and CI pass; then mark
   it ready and request the exact-head merge decision.

## After an authorized merge, before publication

Build again from the exact clean merged commit. Repeat digest, isolated-consumer
and package-resource checks on those new artifacts. Never relabel PR-head
`release-evidence.json` as merged-commit evidence. Scope completion after merge
does not complete RAY-984's publication acceptance.

Prepare a concrete packet naming the `v0.9.4` tag target, reviewed merge SHA,
wheel/sdist/evidence filenames and SHA-256 values, release notes, CI and consumer
results. Obtain a separate publication approval before creating the tag or GitHub
Release. Preserve immutable 0.9.3 assets and do not overwrite an existing 0.9.4.

After publication is authorized and actually performed, download the public
assets, recheck their digests, repeat isolated-wheel acceptance, and read back
the tag target and Release metadata. Only then assess RAY-984 Done. RAY-969's
dependency adoption and RAY-830's remaining acceptance stay independent.

No step here deploys, updates a host, changes a runtime lock or accesses the
integration endpoint.
