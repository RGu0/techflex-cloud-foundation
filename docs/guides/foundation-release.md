# Foundation release preparation and acceptance

RAY-514 R1 records the proposed 0.4.0 release and its acceptance criteria. The
version bump and build output prepare reviewable assets; they do not publish.
On 2026-10-07, RAY-515 R2's three scopes completed acceptance and RAY-540 completed
the content verification contract: PR75/76/77 merged, and the fully integrated
library suite passed 910 tests without skips. This candidate contains those
changes. The remaining gate is this release's own review, merge authorization,
exact merged-commit build, publication authorization and actual asset acceptance.

Version 0.4.0 includes a breaking content contract: `entry-parts/1` mapping,
streaming object `read_chunks`, atomic session `finalize` and immutable
`content/1` receipt retirement. Consumer adapters must migrate, and old/unknown
receipts must retain local bytes. See the
[migration guide](ingestion-content-verification.md) and portable vectors.

1. Run governed test/lint/build on the registered release worktree. Use an
   absolute empty `FOUNDATION_RELEASE_DIR` to retain wheel, sdist, and redacted
   `release-evidence.json`. Unix and PowerShell use the same variable.
2. Review the exact final commit and its Ubuntu/macOS/Windows CI and performance
   evidence. After authorized merge, build from that exact clean commit. Assets
   built before a merge record the earlier revision and cannot be relabelled as
   the merged version's evidence.
3. Verify wheel and sdist SHA-256 against evidence. In an isolated consumer
   environment, install the wheel and import `ResumeDriver`, `TransferEndpoint`,
   `PartSource`, `TransferRetryable`, `TransferQuarantined`, `TransferExhausted`,
   and `TransferConflict`; verify the installed package is version 0.4.0.
   This must install the actual retained candidate wheel, with its recorded
   SHA-256, rather than rebuilding another wheel for the consumer check. Verify
   the installed import location, optional RetryPolicy jitter arguments and
   content/1 retirement gate in the isolated environment.
4. After release authorization, create tag `v0.4.0` at the approved commit and a
   GitHub Release attaching both assets. Put their filenames and SHA-256 values
   in the release notes. Include reviewed breaking changes and migration notes.
5. Download the actual published attachments, recheck their SHA-256, and repeat
   the isolated consumer check. Record tag/commit, Release URL, CI runs, asset
   digests, and redacted results under the scope evidence directory.
6. Run the scope completion gate with current requirement revision and receipts;
   mark the scope and RAY-514 complete only when the published assets and every
   parent acceptance criterion are verified.

No application repository, deployment, mobile signing, or business OpenAPI is
changed by this library release. Consumer upgrades remain separately scoped.
