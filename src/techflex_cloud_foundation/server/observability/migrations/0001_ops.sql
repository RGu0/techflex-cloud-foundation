BEGIN;

CREATE SCHEMA IF NOT EXISTS ops;

CREATE OR REPLACE FUNCTION ops.reject_immutable_ops_row()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'ops evidence rows are immutable';
END;
$$;

CREATE TABLE ops.outbox_events (
    event_id uuid PRIMARY KEY,
    event_type text NOT NULL,
    tenant_id uuid,
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    correlation_id uuid,
    causation_id uuid,
    payload jsonb NOT NULL,
    occurred_at timestamptz NOT NULL,
    published_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL
);

CREATE TABLE ops.telemetry_batches (
    telemetry_batch_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    terminal_id uuid,
    batch_id uuid NOT NULL,
    event_count integer NOT NULL CHECK (event_count > 0),
    object_key text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    min_severity text NOT NULL
        CHECK (min_severity IN ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL')),
    received_at timestamptz NOT NULL,
    processing_status text NOT NULL
        CHECK (processing_status IN ('RECEIVED', 'PROCESSED', 'QUARANTINED')),
    safe_summary jsonb NOT NULL,
    UNIQUE (tenant_id, batch_id),
    UNIQUE (tenant_id, object_key)
);

CREATE TABLE ops.alert_incidents (
    alert_incident_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    terminal_id uuid,
    rule_id text NOT NULL,
    dedupe_key text NOT NULL,
    severity text NOT NULL CHECK (severity IN ('WARNING', 'CRITICAL')),
    status text NOT NULL CHECK (status IN ('OPEN', 'RESOLVED')),
    occurrence_count integer NOT NULL CHECK (occurrence_count > 0),
    runbook text NOT NULL,
    opened_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    resolved_at timestamptz,
    safe_context jsonb NOT NULL
);

CREATE UNIQUE INDEX alert_incidents_one_open_idx
ON ops.alert_incidents (tenant_id, dedupe_key)
WHERE status = 'OPEN';

CREATE TABLE ops.diagnostic_packages (
    diagnostic_package_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    terminal_id uuid NOT NULL,
    object_key text NOT NULL,
    plaintext_sha256 text NOT NULL CHECK (plaintext_sha256 ~ '^[0-9a-f]{64}$'),
    ciphertext_sha256 text NOT NULL CHECK (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes > 0),
    encryption_algorithm text NOT NULL,
    encryption_key_id text NOT NULL,
    contains_session_data boolean NOT NULL DEFAULT false
        CHECK (contains_session_data = false),
    status text NOT NULL
        CHECK (status IN ('RECEIVED', 'AVAILABLE', 'EXPIRED', 'QUARANTINED')),
    requested_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, object_key)
);

CREATE TABLE ops.support_audit_logs (
    support_audit_log_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    role text NOT NULL CHECK (role IN ('SUPPORT_ENGINEER', 'SECURITY_ADMIN')),
    action text NOT NULL CHECK (action = 'SUPPORT_DIAGNOSTIC_ACCESS'),
    resource_type text NOT NULL,
    resource_id uuid NOT NULL,
    reason text NOT NULL,
    occurred_at timestamptz NOT NULL,
    correlation_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER support_audit_logs_immutable
BEFORE UPDATE OR DELETE ON ops.support_audit_logs
FOR EACH ROW EXECUTE FUNCTION ops.reject_immutable_ops_row();

CREATE INDEX outbox_unpublished_idx
ON ops.outbox_events (next_attempt_at, occurred_at)
WHERE published_at IS NULL;

CREATE INDEX telemetry_terminal_time_idx
ON ops.telemetry_batches (tenant_id, terminal_id, received_at DESC);

CREATE INDEX diagnostic_expiry_idx
ON ops.diagnostic_packages (status, expires_at);

ALTER TABLE ops.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.telemetry_batches ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.alert_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.diagnostic_packages ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.support_audit_logs ENABLE ROW LEVEL SECURITY;

CREATE POLICY outbox_tenant_policy ON ops.outbox_events
USING (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id IS NULL OR tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY telemetry_tenant_policy ON ops.telemetry_batches
USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY alert_incidents_tenant_policy ON ops.alert_incidents
USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY diagnostic_packages_tenant_policy ON ops.diagnostic_packages
USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

CREATE POLICY support_audit_tenant_policy ON ops.support_audit_logs
USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid);

COMMIT;
