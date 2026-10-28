BEGIN;

-- RAY-830 R3 (db-migrations): the ledger of applied migrations. 0001-0016 were
-- applied by probing the catalog; the runner registers them here by checksum
-- the first time it runs, so later drift in a shipped file is detected.
-- Re-running is safe: every statement converges.

CREATE TABLE IF NOT EXISTS ops.schema_migrations (
    migration_id text PRIMARY KEY,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    method text NOT NULL CHECK (method IN ('applied', 'baseline')),
    applied_at timestamptz NOT NULL DEFAULT now()
);

REVOKE ALL ON ops.schema_migrations FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_seed_backup') THEN
        GRANT SELECT ON ops.schema_migrations TO ffp_seed_backup;
    END IF;
END
$$;

COMMIT;
