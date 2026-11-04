# RAY-830 R5: pre-cutover validation and decision record

As of 2026-11-03 (America/Los_Angeles). This is a preparation checklist, not
permission to switch the integration endpoint. The user must approve the actual
switching window and privileged operations. Keep RAY-830 In Progress.

## Code gap repaired; release and host acceptance remain

On 2026-11-03 (America/Los_Angeles), PR #106 merged the registered HTTP ingestion
fix at `56fbb06dc790bdc41c93beee96b7760d41658b80`. The 0.9.1 candidate accepts
registry-valid gait core requests, persists segment metadata and completes to
`INGESTED`. The in-process smoke regression now asserts successful creation,
segment listing, matching completion receipt, final status and terminal revocation.
[Registry ingestion](registry-ingestion.md) documents the migration and quality
semantics. This proves current source behavior, not the published wheel or TLS.

Historical finding retained: on the original tools head `36885d3`, foundation
0.9.0's legacy HTTP DTO rejected the gait core with 422. That actual failing run
remains in `evidence/ray-830/pre-cutover-validation/acceptance/validation-36885d3.md`.
The old release is unchanged and must not be treated as a valid three-product
cutover candidate. Do not manufacture legacy measurement fields to bypass it.

The probe still fails unless the upload reaches `INGESTED` with matching IDs and
digest. Its receipt-fault stub test checks rejection of a wrong receipt; the actual
current application test checks the successful path. No production request was
made for this alignment. This tools-only scope adds no server change of its own;
PR #106 supplies the service and migration through main.

Before cutover approval: separately approve/publish the repaired version, pin its
immutable wheel and runtime lock, apply 0020 on a restored copy, then collect fresh
loopback TLS, rollback and production-switch evidence. Old runtime rollback after
neutral rows are written requires the pre-upgrade database backup.

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
| Gait-IMU | PR #106 fixed source path; actual in-process smoke reaches INGESTED with matching receipt | Approve release/pin, migrate restored copy, then loopback and approved production TLS |
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
   no-go; a source-level success alone cannot complete this packet.
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
