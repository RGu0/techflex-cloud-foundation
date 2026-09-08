# Production acceptance runners (RAY-404)

Deployment-side drill tooling used by the RAY-404 `production-acceptance`
scope to produce the tier=production release receipts on the real
FeetForcePlate deployment.  These scripts run **on the deployment host**;
they read secrets only from the deployment environment and never print or
persist them.  Receipts serialize the release-gate whitelist and nothing
else.

- `integration_channel_probe.py` — read-only TLS / correlation-id probe of
  the vendored integration channel (`uv run python ... > probe.md`).
- `validate_rls_snapshot.py` — validate a captured RLS introspection
  snapshot against the CP-08 contract.
- `acceptance_drills.py` — tenant lifecycles, isolation probes, and
  capacity measurement against the live HTTPS API; bootstraps a dedicated
  acceptance platform operator with the deployment's own crypto.
- `gate_run_v4.py` — composes every validator, runs the restore drill
  (bundle decrypt, empty-target restore, per-component digest re-verify),
  and evaluates the `ReleaseGate` for the final redacted receipt.

Server-side paths (`/opt/feetforceplate/app`, `/srv/feetforceplate/...`,
`/tmp/ray404/...`) and env var names reflect the production host; adjust
for other deployments.  The acceptance evidence, runbooks, and receipts
live in the shared evidence library under
`.project-context/evidence/ray-404/production-acceptance/`.

Future re-acceptance (e.g. the gait-IMU dual-product upgrade, RAY-429)
reuses these runners unchanged.
