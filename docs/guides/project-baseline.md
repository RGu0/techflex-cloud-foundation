# Project baseline and requirement index

## Requirements and historical boundaries

Linear owns current requirements, acceptance and task status. GitHub owns source,
reviews, CI, releases and merges. Read the linked Issue before starting a scope;
this index is not a substitute for its current revision.

- [RAY-827](https://linear.app/ruiguo/issue/RAY-827) defines the product-neutral
  platform migration and schema-registration goal (R1 when read on 2026-11-09).
- [RAY-830](https://linear.app/ruiguo/issue/RAY-830) governs the server, database,
  object-store and deployment migration, its registered scopes and cutover
  acceptance (R5 when read on 2026-11-09).
- RAY-828, RAY-829 and RAY-833 cover the core contracts, session extensions and
  insole/gait schema onboarding; RAY-831 covers analyzer dispatch. Their current
  criteria and cross-consumer acceptance remain in Linear under RAY-827.
- RAY-341 R2 and RAY-338 R1 retain the earlier capability roadmap and local
  durability delivery boundaries. They are historical requirements, not a reason
  to reopen completed work or expand a completed scope. Earlier FeetForcePlate
  requirements and deployments remain evidence for that application, not proof
  of foundation acceptance.

On 2026-11-09 Linear still reports RAY-827 as Backlog and RAY-830 as In Progress.
A merged child scope, published package or host observation cannot by itself
complete either parent's remaining acceptance. Algorithms, reports, device
protocols, product policies, secrets and customer data retain their application
boundaries; migration does not move them into this repository.

## Read deployment evidence by date

The [cutover runbook](seed-cutover-runbook.md) separates procedures from dated
observations. Its 2026-11-02 restored-copy rehearsal is historical evidence for
that candidate; it does not validate a later candidate. The 2026-11-05 CST cutover
records foundation 0.9.1 with deployment source
`0d3473145457b07833304cf99f0833c637a70c52`. The linked acceptance record is
`.project-context/evidence/ray-830/release-cutover/acceptance/cutover-0d34731-20261105.md`.
These statements reproduce retained evidence; RAY-956 performs no new host probe.

Newer source, runtime locks and release assets must be verified separately.
Publication does not imply host adoption, and an integration endpoint does not
establish formal public ingress or certificate-rotation acceptance. Remaining
scope and parent acceptance must be read from RAY-830, not inferred from an old
"not yet run" paragraph or from the presence of procedural shell commands.

## Safely select and synchronize a local baseline

Use the configured repository and approved network/proxy route. From the local
bare container, inspect before writing anything (replace the path for your host):

```sh
container=/absolute/path/to/techflex-cloud-foundation
git -C "$container" worktree list --porcelain
git -C "$container/main" status --porcelain=v1 --untracked-files=all
git -C "$container/main" branch --show-current
git -C "$container" fetch origin
git -C "$container" rev-parse main origin/main
git -C "$container" rev-list --left-right --count main...origin/main
```

Stop if fetch fails, the mapped Worktree is missing, its branch is not `main`,
its status is nonempty, or ownership is uncertain. Do not hide changes with stash,
reset, rebase, force-push or deletion. A clean status alone does not establish
ancestry: the first count must be zero. A nonzero first count means local commits
need investigation; both counts nonzero mean divergence. Preserve them and ask
for a specific reconciliation decision.

If both counts are zero, no update is needed. If only the second is nonzero,
coordinate with other active chats first. The following **mutates the local main
Worktree** and is performed only with explicit synchronization authorization:

```sh
git -C "$container/main" merge --ff-only origin/main
git -C "$container/main" status --porcelain=v1 --untracked-files=all
git -C "$container" rev-parse main origin/main
```

Recheck branch, status and counts immediately before the update. A failed
fast-forward is a stop, not permission for another integration strategy. Record
the resulting exact SHA; these source operations do not deploy anything.

Never develop in the default-branch Worktree. Create/resume the registered scope
with the `work-on-linear-scope` skill and `create_scope_worktree.py`, which fetches
the configured default branch and reports `based_on`. Compare that exact SHA to
GitHub; do not select a candidate merely because local `main` exists. An existing
scope resumes its own branch and must not silently absorb newer main commits.
Run setup/test/lint/build through `project_command.py` in that scope's Worktree.
