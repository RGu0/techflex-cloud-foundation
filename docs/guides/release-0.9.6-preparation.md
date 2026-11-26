# Foundation 0.9.6 release preparation

RAY-1032 R2, `release-096`. On 2026-11-26 (America/Los_Angeles and Asia/Shanghai)
the user opened the release, chose version 0.9.6 and authorized preparation,
validation, a PR and independent review. When RAY-1028 reached `main` during that
preparation, the user confirmed (R2) that 0.9.6 includes it.
**Merge and publication each require separate confirmation.** This document
prepares a release; it does not authorize a tag, asset upload, runtime pin,
deployment or host operation.

## Included changes and boundaries

The baseline is `main` at PR #128's merge
`d82ab8d46d5dd4dbc6bdf71904be72a71a2ce3c1`, after the published `v0.9.5` at
`7deffa58cdffd7d8b79aaa667f757eb031162ec2` (published 2026-11-19
America/Los_Angeles, 2026-11-20 04:50:18 UTC). Its assets remain unchanged; the
CHANGELOG heading for 0.9.5 now records that publication date, using the
America/Los_Angeles date as the 0.9.4 heading did.

0.9.6 contains two merged changes since `v0.9.5`:

- **RAY-1030 `nginx-5xx-alert` (PR #127).** Seed deployment assets only, under
  `deploy/aliyun/seed/` and `tests/`:
  - `nginx_5xx_alert.py`, `feetforceplate-5xx-alert.service` and `.timer`. The
    timer scans the nginx access logs every five minutes; any 5xx produces one
    signed DingTalk group-robot message. The script runs with the host's system
    Python and the standard library only, not the service venv.
  - `install-seed-release.sh` installs both units, enables the timer, and adds
    `alert_5xx=... alert_config=...` to its final summary line.
  - `installer-recovery.sh` snapshots and stops the new units. It also no longer
    runs `systemctl stop` on units that did not exist before a failed install;
    on systemd 255 that failed recovery even though every file had been restored.
  - The seed deployment README documents the configuration, a test message and
    the scanner's behaviour.
- **RAY-1028 `oss-transient-errors` (PR #128).** Library and server changes:
  - New public exceptions `ObjectStoreRequestFailed` and its retryable subclass
    `ObjectStoreUnavailable` in `object_store`; the OSS gateway raises them for
    requests that fail before saying anything about the object.
  - An unreachable OSS (network, TLS, DNS, CA bundle, timeout) or a 5xx/429 answer
    is now 503 `E-CLD-503` (`retryable: true`) instead of 500 `E-CLD-500`; other
    refusals such as 403 stay 500. Segment uploads and manifest completions record
    such failures as `OBJECT_STORE_FAILURE` ingest problems, resolved by a later
    success.
  - Migration `0023_object_store_failure_problems` (tenant role may update the
    problem's status, evidence and timestamps; one OPEN problem per session and
    segment). A deployment must apply it.
  - Report PDF and diagnostic package reads no longer report an unreachable object
    store as a digest mismatch.

Neither change is marked **Breaking** by its delivery, so under the CHANGELOG's
`0.y.z` rule the version is a patch bump, matching 0.9.4 and 0.9.5. Consumers that
treated `E-CLD-500` on an OSS outage as final should note that it is now a
retryable `E-CLD-503`. The seed runtime remains pinned to the published 0.9.4
server wheel (RAY-995); moving that pin, and applying migration 0023 on a host, is
deployment work, not part of this release.

## Candidate acceptance before merge

Use the registered Worktree and governed `project_command.py` actions, with their
logs written to a local path (a log inside the OneDrive-backed `.project-context`
made the actions exit 134 on 2026-11-26). Record the exact clean PR head, R2 and
the source comparison to `v0.9.5` under
`.project-context/evidence/ray-1032/release-096/`.

1. Run governed lint/test/build and retain wheel, sdist and
   `release-evidence.json` in an absolute, empty local `FOUNDATION_RELEASE_DIR`.
   Verify artifact digests and the evidence's source revision and lock digest.
2. Install that actual wheel into a new isolated Python environment with the
   reviewed locked dependencies. Verify version 0.9.6 and an installed module
   location outside this checkout. Import `ObjectStoreRequestFailed` and
   `ObjectStoreUnavailable` (the latter a subclass of the former), confirm the
   installed migration plan lists `0023_object_store_failure_problems`, and keep
   the 0.9.5 consumer probe passing. A source-tree import is not wheel acceptance.
3. Check that the retained sdist contains the 5xx alert script, units, installer,
   recovery script and README byte-identical to the reviewed head, and the
   `0023` SQL file.
4. Record the package files that differ from the published 0.9.5 wheel; they
   should be exactly RAY-1028's `src/` changes.
5. Independently review the exact head and require all final
   Ubuntu/macOS/Windows CI checks. Keep the PR draft until review, candidate
   acceptance and CI pass; then mark it ready and request the exact-head merge
   decision.

## After an authorized merge, before publication

Build again from the exact clean merged commit and repeat the digest,
isolated-consumer and sdist-content checks on those new artifacts. Never relabel
PR-head `release-evidence.json` as merged-commit evidence. Scope completion after
merge does not complete RAY-1032's publication acceptance.

Prepare a concrete packet naming the `v0.9.6` tag target, reviewed merge SHA,
wheel/sdist/evidence filenames and SHA-256 values, release notes, CI and consumer
results. Obtain a separate publication approval before creating the tag or GitHub
Release. Preserve the immutable 0.9.5 assets and do not overwrite an existing
0.9.6.

After publication is authorized and performed, download the public assets,
recheck their digests, repeat isolated-wheel acceptance and the sdist-content
check, and read back the tag target and Release metadata. Only then assess
RAY-1032 Done. Deploying to integration (including migration 0023 and the alert
timer) and RAY-1030's Issue-level acceptance (the user's first real DingTalk
message) stay independent.

No step here deploys, updates a host, changes a runtime lock or accesses the
integration endpoint.
