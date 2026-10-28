BEGIN;

CREATE TABLE ops.session_holds (
    hold_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    state text NOT NULL CHECK (state IN ('HELD', 'RELEASED')),
    reason_code text NOT NULL CHECK (reason_code = 'IDENTITY_UNVERIFIED'),
    applied_at timestamptz NOT NULL DEFAULT now(),
    released_at timestamptz,
    UNIQUE (tenant_id, hold_id),
    UNIQUE (tenant_id, session_id),
    FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions(tenant_id, session_id)
);

CREATE TABLE ops.session_hold_events (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    hold_id uuid NOT NULL,
    session_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('APPLY', 'DISPOSITION', 'RELEASE')),
    actor_id uuid NOT NULL,
    ticket_sha256 text NOT NULL CHECK (ticket_sha256 ~ '^[0-9a-f]{64}$'),
    safe_context jsonb NOT NULL DEFAULT '{}'::jsonb,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_id),
    FOREIGN KEY (tenant_id, hold_id) REFERENCES ops.session_holds(tenant_id, hold_id),
    FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions(tenant_id, session_id)
);

CREATE TABLE ops.session_hold_idempotency (
    tenant_id uuid NOT NULL,
    key_sha256 text NOT NULL CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    hold_id uuid NOT NULL,
    action text NOT NULL CHECK (action IN ('APPLY', 'DISPOSITION', 'RELEASE')),
    result_state text NOT NULL CHECK (result_state IN ('HELD', 'RELEASED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_sha256),
    FOREIGN KEY (tenant_id, hold_id) REFERENCES ops.session_holds(tenant_id, hold_id)
);

CREATE TABLE ops.session_hold_dispositions (
    disposition_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL,
    hold_id uuid NOT NULL,
    decision_code text NOT NULL CHECK (decision_code IN ('RETAIN_WITH_VALID_BASIS', 'RESTRICT_AND_DISPOSE')),
    evidence_sha256 text NOT NULL CHECK (evidence_sha256 ~ '^[0-9a-f]{64}$'),
    valid_basis_sha256 text CHECK (valid_basis_sha256 ~ '^[0-9a-f]{64}$'),
    retention_policy_id uuid,
    planned_job_id uuid,
    decided_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, disposition_id),
    UNIQUE (tenant_id, hold_id),
    FOREIGN KEY (tenant_id, hold_id) REFERENCES ops.session_holds(tenant_id, hold_id),
    FOREIGN KEY (tenant_id, retention_policy_id) REFERENCES ops.retention_policies(tenant_id, retention_policy_id),
    CHECK (
        (decision_code = 'RETAIN_WITH_VALID_BASIS' AND valid_basis_sha256 IS NOT NULL AND retention_policy_id IS NULL AND planned_job_id IS NULL)
        OR (decision_code = 'RESTRICT_AND_DISPOSE' AND valid_basis_sha256 IS NULL AND retention_policy_id IS NOT NULL AND planned_job_id IS NOT NULL)
    )
);

ALTER TABLE ops.session_holds ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.session_holds FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.session_hold_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.session_hold_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.session_hold_idempotency ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.session_hold_idempotency FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.session_hold_dispositions ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.session_hold_dispositions FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON ops.session_holds
    USING (tenant_id = ops.current_tenant_id()) WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON ops.session_hold_events
    USING (tenant_id = ops.current_tenant_id()) WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON ops.session_hold_idempotency
    USING (tenant_id = ops.current_tenant_id()) WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON ops.session_hold_dispositions
    USING (tenant_id = ops.current_tenant_id()) WITH CHECK (tenant_id = ops.current_tenant_id());

GRANT SELECT ON screening.sessions TO ffp_platform_app;
GRANT INSERT ON ops.audit_logs TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON ops.session_holds TO ffp_platform_app;
GRANT SELECT, INSERT ON ops.session_hold_events, ops.session_hold_idempotency TO ffp_platform_app;
GRANT SELECT, INSERT ON ops.session_hold_dispositions TO ffp_platform_app;
GRANT SELECT ON ops.retention_policies TO ffp_platform_app;
GRANT INSERT ON ops.data_disposition_jobs TO ffp_platform_app;
GRANT SELECT ON ops.session_holds TO ffp_tenant_app;

COMMIT;
