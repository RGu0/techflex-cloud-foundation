# RAY-830 R5: pre-cutover validation and decision record

As of 2026-11-03 (America/Los_Angeles). This is a preparation checklist, not
permission to switch the integration endpoint. The user must approve the actual
switching window and privileged operations. Keep RAY-830 In Progress.

## Current no-go: gait-IMU HTTP ingestion

The default payload registry accepts `gait-session-archive/1`, but foundation
0.9.0's migrated HTTP `SessionCreateRequest` still requires subject, consent,
device, test protocol and frame-product version fields. The seed composition's
`supported_payload_schemas` contains only `raw-segment/1` and
`insole-session-archive/1`; segment and manifest parsing also uses those two
legacy shapes. A registry-valid gait session receives HTTP 422 before upload.

`tests/test_ray830_pre_cutover_smoke.py` reproduces that failure against the real
in-process application. Its passing *test* means the blocker was reproduced;
it does not mean gait ingestion passed. The test must change with the eventual
service fix. The probe itself exits nonzero unless the entire upload reaches
`INGESTED` with matching IDs and digest. A protocol-stub success test verifies
the probe, not the service. No production request was made for this finding.

Resolve this before asking for cutover approval: a separately confirmed service
fix must connect the registry to HTTP ingestion/persistence and be released and
pinned, or the user must explicitly decide a different acceptance scope. Do not
rewrite v0.9.0 assets, add fabricated foot-pressure fields to gait requests, or
count its 422 as successful acceptance. This tools-only scope changes no server
code, schema migration, package version or runtime lock.

## Missing smoke tools now available

Run from the repository root using the pinned project environment, or from the
reviewed deployment archive using its pinned runtime. The tool imports the
released contract DTOs; retain the **tool commit separately from wheel version**.
Use one fresh output path per execution (existing evidence is never overwritten).

```bash
python -m scripts.run_ray830_pre_cutover_smoke \
  --mode gait --environment rehearsal \
  --base-url https://127.0.0.1:27443 --ca-file /path/to/rehearsal/tls/ca.pem \
  --account-name TEST_ACCOUNT --output /path/to/evidence/gait.json
python -m scripts.run_ray830_pre_cutover_smoke \
  --mode diagnostics --environment rehearsal \
  --base-url https://127.0.0.1:27443 --ca-file /path/to/rehearsal/tls/ca.pem \
  --account-name TEST_ACCOUNT --output /path/to/evidence/diagnostics.json
```

The password is prompted, never passed as an argument. Rehearsal accepts only a
loopback IP on port 27443 (SSH local forwarding may be used). TLS verification
stays enabled; redirects are refused. Production targets need
`--environment production --allow-production-write`, and only after the separate
user approval. The flag alone is not that approval.

Each run temporarily uses one free terminal seat, revokes the terminal even after
a failure, and writes redacted status evidence. A cleanup failure fails the run
and requires an operator to inspect/revoke the smoke terminal. Gait writes a
small synthetic gzip archive in multiple byte segments; it creates no subject or
invented measurement device. Diagnostics uploads a synthetic NDJSON package,
checks size/digest/30-day expiry and identical idempotent replay. Uploaded records
remain; diagnostic content expires after 30 days. No real diagnostic export or
patient data is needed. Support retrieval/purge is outside this smoke's coverage.

## Evidence matrix before a decision

| Check | Evidence currently available | Required next evidence |
| --- | --- | --- |
| 0.9.0 release and runtime pin | Published/digest-verified record under release-cutover/release; PR #98 merged | Re-read approved release/lock digest for the actual candidate; a service fix requires a new release |
| Restored DB and migration adoption | Historical 2026-11-02 host rehearsal: adopted ffp 0017/0018 as foundation 0018/0019 | Operator runs read-only migration-state check and refreshes restore proof before switching |
| Offline runtime and ACL | Historical host rehearsal passed after cache warming and ACL replay | Run parameterised repository scripts against the candidate restored copy; preserve errors and cleanup results |
| Foot plate, insole, subjects | Four loopback TLS smokes passed historically | Repeat against exact candidate, then production TLS only after approval |
| Diagnostics | Current in-process API upload/replay/receipt/revoke tests | Loopback TLS smoke; production smoke after approval |
| Gait-IMU | Registry passes; real HTTP rejects core with 422 | Fix/release/pin, then loopback and production TLS to INGESTED |
| Installer as root | Not executed in the prior rehearsal | Privileged execution remains an operator step; never infer success from shell tests |
| Rollback | Ledger rollback test and historical backup restore | Capture old application, units, nginx config and offline environment; verify rollback on isolated copy |

Historical host evidence is under
`.project-context/evidence/ray-830/release-cutover/acceptance/host-rehearsal-step{1,2,3}-20261102.md`.
`rehearsal-runbook` PR #101 parameterised the scripts but did not rerun that form
on the host. Its merge and CI are not host acceptance.

## Concrete cutover approval packet (complete before asking)

1. Identify candidate tool/deploy commit, released wheel version and SHA-256,
   runtime lock digest, source drift check, exact CI and review results.
2. Operator records current release symlink/SHA, listeners 7443/8743, service
   units, nginx configuration, PostgreSQL config and migration state without
   printing secrets. Read-only SQL remains user-run per RAY-830 D1.
3. Record latest encrypted backup name/hash/verified sidecar and successful restore
   of that backup, candidate migrations/adoption and restored-copy ACL comparison.
   Keep diagnostics object backup omission visible: current exporter omits those
   objects, so database restore alone does not recover their content.
4. Obtain loopback TLS results for all three products, subject sync and diagnostics
   on the exact candidate, plus teardown evidence. Any failed/missing result is a
   no-go; current gait failure therefore blocks this packet.
5. State switch window, operator/sudo method, exact installer command, expected
   PostgreSQL/service restarts, affected endpoint, stop conditions and rollback
   artifacts. Confirm test institution, free seat and private CA availability.
6. Request approval for that concrete switch only after the packet is complete.

## Failure and rollback handling

Stop on a digest/cache/schema/backup discrepancy or any failing smoke. Do not
retry the installer blindly after a partial mutation: first record which steps
ran, active release, listeners and migration status.

Before switching preserve the **currently deployed** unit files, timer and nginx
configuration as well as old application symlink and its offline dependencies.
`nginx.conf.pre-seed` may describe an earlier bootstrap, not today's state; it
must not be assumed to be the correct rollback target. Rollback of the application
restores the captured units/config and old symlink, syncs its own runtime offline,
reloads systemd and restarts the old service under operator control. Recheck
readiness and the old client's smoke before reopening traffic.

SQL is forward-only. Dropping the migration ledger does not undo schema/data
changes; restoring the cutover backup is the data rollback and can lose writes
made since that backup. The switch packet must identify a write-quiescence plan
or an explicitly accepted recovery point before the user decides. This document
performs neither a restore nor any service operation.
