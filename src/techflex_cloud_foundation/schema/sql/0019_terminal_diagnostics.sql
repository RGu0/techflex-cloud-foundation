BEGIN;

-- RAY-802 R1: terminal diagnostic packages. One row per accepted package;
-- the content lives in the object store under object_key. The purge deletes
-- the content after expires_at and keeps the row as a tombstone (deleted_at
-- set): there is no DELETE grant. Existing tables are not changed.
CREATE TABLE ops.terminal_diagnostics (
    diagnostic_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    client_installation_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
    format text NOT NULL CHECK (format = 'gait-insole-diagnostics/1'),
    size_bytes integer NOT NULL CHECK (size_bytes BETWEEN 1 AND 8388608),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    object_key text NOT NULL CHECK (char_length(object_key) BETWEEN 1 AND 512),
    received_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    deleted_at timestamptz,
    UNIQUE (tenant_id, diagnostic_id),
    UNIQUE (tenant_id, client_installation_id, idempotency_key),
    CHECK (expires_at > received_at),
    CHECK (deleted_at IS NULL OR deleted_at >= received_at)
);

CREATE INDEX ix_terminal_diagnostics_tenant_received
ON ops.terminal_diagnostics (tenant_id, received_at DESC, diagnostic_id DESC);
CREATE INDEX ix_terminal_diagnostics_live_expiry
ON ops.terminal_diagnostics (tenant_id, expires_at) WHERE deleted_at IS NULL;

ALTER TABLE ops.terminal_diagnostics ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.terminal_diagnostics FORCE ROW LEVEL SECURITY;

CREATE POLICY ops_terminal_diagnostics_tenant_isolation ON ops.terminal_diagnostics
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

-- Terminals upload through the activation role; Platform support reads and
-- the purge sets deleted_at, the only column it may change. No DELETE grant.
GRANT SELECT, INSERT ON ops.terminal_diagnostics TO ffp_activation_app;
GRANT SELECT ON ops.terminal_diagnostics TO ffp_platform_app;
GRANT UPDATE (deleted_at) ON ops.terminal_diagnostics TO ffp_platform_app;

COMMIT;
