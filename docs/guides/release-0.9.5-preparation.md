# Foundation 0.9.5 release preparation

RAY-1008 R1, `release-095`. On 2026-11-19 America/Los_Angeles the user opened the
release, chose version 0.9.5 and authorized preparation, validation, a PR and
independent review. **Merge and publication each require separate confirmation.**
This document prepares a release; it does not authorize a tag, asset upload,
runtime pin, deployment or host operation.

## Included changes and boundaries

The baseline is `main` at PR #124's merge
`5496f6af828d463d058ffd5133a097f4f019a894`, after the published `v0.9.4` at
`26f2c4321a29ef62e2c0636b7f03c1d6b0326c4c` (published 2026-11-16
America/Los_Angeles, 2026-11-17 03:43:51 UTC). Its assets remain unchanged; the
CHANGELOG heading for 0.9.4 now records that publication date.

0.9.5 contains three merged changes since `v0.9.4`:

- **RAY-831 `registry-analysis-dispatch` (PR #124).** Payload schema registry
  analyzer bindings (`bind_analyzer`, `analyzer_for`, `analyzer_bindings`,
  `AnalyzerBindingConflict`); the default registry binds `raw-segment/1` to
  `FORCE_PLATE_ANALYZER` (`ffp.force-plate-analysis`) and leaves the insole and
  gait-IMU archives unbound. The new `analysis_dispatch` module provides
  `IngestedEventDispatcher`. `session.ingested.v1` gains `payload_schema_version`
  on the in-memory and PostgreSQL paths; this is additive, the event type is
  unchanged and no migration is added. See
  [analysis dispatch](analysis-dispatch.md).
- **RAY-995 `runtime-pin-094` (PR #123).** The seed deployment runtime is pinned
  to the published 0.9.4 server wheel. This is deployment configuration in the
  repository; the 0.9.5 release does not change that pin.
- **Dependabot PR #120.** The project lock's python-dependencies group update.
  Only `uv.lock` changed; declared dependency ranges in `pyproject.toml` are
  unchanged, so this is a project-lock fact, not a claim about every consumer's
  transitive resolution.

There is no Breaking change, so under the CHANGELOG's `0.y.z` rule the version is
a patch bump, matching 0.9.4. No HTTP route, migration or runtime composition is
added. No production process consumes `ops.outbox_events`; the dispatcher is a
library component and FeetForcePlate's adoption is RAY-1006.

## Candidate acceptance before merge

Use the registered Worktree and governed `project_command.py` actions. Record the
exact clean PR head, R1 and the source comparison to `v0.9.4` under
`.project-context/evidence/ray-1008/release-095/`.

1. Run governed setup/lint/test/build and retain wheel, sdist and
   `release-evidence.json` in an absolute, empty local `FOUNDATION_RELEASE_DIR`.
   Verify artifact digests and the evidence's source revision and lock digest.
2. Install that actual wheel into a new isolated Python environment with the
   reviewed locked dependencies. Verify version 0.9.5 and an installed module
   location outside this checkout; import `analysis_dispatch`,
   `IngestedEventDispatcher`, `FORCE_PLATE_ANALYZER` and the registry binding
   API; confirm `default_payload_schema_registry()` binds `raw-segment/1` to
   `ffp.force-plate-analysis` and nothing else, and that a dispatcher built with
   a force-plate handler routes a `raw-segment/1` event to it and reports an
   insole event as `INGEST_ONLY`. A source-tree import is not wheel acceptance.
3. Independently review the exact head and require all final
   Ubuntu/macOS/Windows CI checks. Keep the PR draft until review, candidate
   acceptance and CI pass; then mark it ready and request the exact-head merge
   decision.

## After an authorized merge, before publication

Build again from the exact clean merged commit and repeat the digest and
isolated-consumer checks on those new artifacts. Never relabel PR-head
`release-evidence.json` as merged-commit evidence. Scope completion after merge
does not complete RAY-1008's publication acceptance.

Prepare a concrete packet naming the `v0.9.5` tag target, reviewed merge SHA,
wheel/sdist/evidence filenames and SHA-256 values, release notes, CI and consumer
results. Obtain a separate publication approval before creating the tag or GitHub
Release. Preserve the immutable 0.9.4 assets and do not overwrite an existing
0.9.5.

After publication is authorized and performed, download the public assets,
recheck their digests, repeat isolated-wheel acceptance, and read back the tag
target and Release metadata. Only then assess RAY-1008 Done. RAY-1006's
dependency adoption and RAY-831's remaining acceptance stay independent.

No step here deploys, updates a host, changes a runtime lock or accesses the
integration endpoint.
