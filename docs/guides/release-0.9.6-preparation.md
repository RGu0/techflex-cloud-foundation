# Foundation 0.9.6 release preparation

RAY-1032 R1, `release-096`. On 2026-11-26 (America/Los_Angeles and Asia/Shanghai) the user opened the
release, chose version 0.9.6 and authorized preparation, validation, a PR and
independent review. **Merge and publication each require separate confirmation.**
This document prepares a release; it does not authorize a tag, asset upload,
runtime pin, deployment or host operation.

## Included changes and boundaries

The baseline is `main` at PR #127's merge
`c5210eade57c6dd9d7335672d893b4ff5df09905`, after the published `v0.9.5` at
`7deffa58cdffd7d8b79aaa667f757eb031162ec2` (published 2026-11-19
America/Los_Angeles, 2026-11-20 04:50:18 UTC). Its assets remain unchanged; the
CHANGELOG heading for 0.9.5 now records that publication date, using the
America/Los_Angeles date as the 0.9.4 heading did.

0.9.6 contains one merged change since `v0.9.5`:

- **RAY-1030 `nginx-5xx-alert` (PR #127).** Seed deployment assets only, all under
  `deploy/aliyun/seed/` and `tests/`:
  - `nginx_5xx_alert.py`, `feetforceplate-5xx-alert.service` and `.timer`. The
    timer scans the nginx access logs every five minutes; any 5xx produces one
    signed DingTalk group-robot message. The script runs with the host's system
    Python and the standard library only, not the service venv.
  - `install-seed-release.sh` installs both units and enables the timer, and
    reports whether `/etc/feetforceplate/alert.env` is present.
  - `installer-recovery.sh` snapshots and stops the new units. It also no longer
    runs `systemctl stop` on units that did not exist before a failed install;
    on systemd 255 that failed recovery even though every file had been restored.
  - The seed deployment README documents the configuration, a test message and
    the scanner's behaviour.

Nothing under `src/` changed, so the 0.9.6 wheel's package code is identical to
0.9.5 apart from its version. The new assets reach a host through the release's
source archive and sdist, which the seed installer deploys. There is no Breaking
change, so under the CHANGELOG's `0.y.z` rule the version is a patch bump,
matching 0.9.4 and 0.9.5. No HTTP route, migration, public interface or runtime
composition is added. The seed runtime remains pinned to the published 0.9.4
server wheel (RAY-995); moving that pin is deployment work, not part of this
release.

## Candidate acceptance before merge

Use the registered Worktree and governed `project_command.py` actions. Record the
exact clean PR head, R1 and the source comparison to `v0.9.5` under
`.project-context/evidence/ray-1032/release-096/`.

1. Run governed setup/lint/test/build and retain wheel, sdist and
   `release-evidence.json` in an absolute, empty local `FOUNDATION_RELEASE_DIR`.
   Verify artifact digests and the evidence's source revision and lock digest.
2. Install that actual wheel into a new isolated Python environment with the
   reviewed locked dependencies. Verify version 0.9.6 and an installed module
   location outside this checkout, and import the package. A source-tree import
   is not wheel acceptance.
3. Check that the retained sdist contains `deploy/aliyun/seed/nginx_5xx_alert.py`,
   `feetforceplate-5xx-alert.service` and `feetforceplate-5xx-alert.timer`, and
   that they match the reviewed head byte for byte.
4. Independently review the exact head and require all final
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
RAY-1032 Done. Deploying the alert to integration and RAY-1030's Issue-level
acceptance (the user's first real DingTalk message) stay independent.

No step here deploys, updates a host, changes a runtime lock or accesses the
integration endpoint.
