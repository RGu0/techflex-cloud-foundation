# 0.9.1 release preparation

RAY-830 R5, `release-091-preparation`. Dated 2026-11-03 America/Los_Angeles.
Publication and the production switch each need separate user approval.

## Candidate and impact

Main `a311b07cfe0721602573a2569f3186789b335ea8` includes PR106 registered gait
HTTP ingestion/0020, PR103 conflict guard, PR104 safe rehearsal teardown,
PR105 installer recovery, PR102 smoke/checklist and PR107 registry R2/0021.
The retained candidate was built from this clean merged commit, before this
preparation PR. This PR's tests/docs are separate tooling. A later source change
requires a new candidate and validation; do not relabel an earlier artifact.

RAY-953 is included through merged PR107. New neutral requests preserve canonical
identity in TEXT and a digest; historical 0020 JSONB rows retain their provenance
and may conflict when numeric spelling was lost. No historical identity or
unknown timezone is reconstructed. Legacy insole inputs use their complete old
boundary; core insole and injected products use strict registry validation.
Neither compatibility path is removed. See [registry ingestion](registry-ingestion.md).

## Retained-wheel acceptance

Use the governed test action with `PYTEST_ADDOPTS=tests/test_release_server_wheel.py`,
`FOUNDATION_CANDIDATE_WHEEL` pointing to the retained wheel, and a fresh absolute
`FOUNDATION_CANDIDATE_REPORT` JSON path. With `FOUNDATION_PREDECESSOR_WHEEL`, also run
real predecessor-wheel writing, candidate migration and a separate candidate
process replay against disposable UTF8 and SQL_ASCII PostgreSQL databases.

The consumer installs the actual wheel with its server extra into an isolated
venv, copies tests/docs/tools without `src`, asserts the installed import path,
version and 0021 plan, and runs registry HTTP/auth/upgrade/constraint/public-entry
and gait/diagnostics probe regressions. The optional predecessor is the retained
PR106 **unpublished 0.9.1 candidate**, not released 0.9.0. Its 0020 receiving session
is written by its installed implementation, then resumed/completed by the candidate.
This complements the broader old-column fixtures for completed rows, concurrency
and numeric-normalization limitations. It does not prove production upgrades.

## Approval sequence

1. Review this preparation PR, its exact head, CI and local evidence. Merge requires
   its own approval. Candidate wheel/sdist/source SHA are recorded separately.
2. Review the publication packet: immutable v0.9.1 target, retained artifact hashes,
   isolated installed-wheel results, migration/compatibility limits and CI links.
   Only after publication approval create the tag and GitHub Release. Keep old
   releases unchanged. Download actual attachments and recheck hashes/consumer.
3. Prepare runtime pin in a separately registered successor scope and independent
   PR, after publication approval and asset verification. Pin only an actually published,
   digest-verified wheel. Do not invent a URL/hash or mix source 0021 with runtime0.9.0.
4. Obtain needed host-operation authority, then refresh restored-copy offline/ACL,
   migration, three-product/subjects/diagnostics loopback TLS, teardown and rollback
   evidence on the exact wheel/tool/archive/lock set. Current source checks are not TLS.
5. Submit a separate switch packet with actual results, current configuration and
   backup hashes, stop conditions, operator/sudo, write-quiescence/recovery point,
   restart impact, window and exact rollback commands. Old-runtime rollback after
   neutral writes needs the pre-upgrade database backup, not ledger deletion.

The deployed runtime pin stays 0.9.0 until the published successor is verified.
The RAY-830 parent still needs host/TLS/switch and ffp adoption acceptance.
