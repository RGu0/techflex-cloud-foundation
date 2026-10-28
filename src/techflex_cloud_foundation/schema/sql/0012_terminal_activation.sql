BEGIN;

-- RAY-656 R2: one institutional account activates several terminals. The
-- License carries the seat limit; each terminal owns an independent refresh
-- family. Existing account/hardware activation tables are not changed.
ALTER TABLE device.license_entitlements
    ADD COLUMN terminal_seats integer NOT NULL DEFAULT 0
    CONSTRAINT license_entitlements_terminal_seats_check CHECK (terminal_seats >= 0);

ALTER TABLE ops.authentication_attempts
    DROP CONSTRAINT IF EXISTS authentication_attempts_attempt_kind_check;

ALTER TABLE ops.authentication_attempts
    ADD CONSTRAINT authentication_attempts_attempt_kind_check
    CHECK (attempt_kind IN (
        'TENANT_LOGIN', 'TENANT_ACTIVATION', 'PLATFORM_LOGIN', 'TERMINAL_ACTIVATION'
    ));

CREATE TABLE iam.access_terminals (
    client_installation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    license_id uuid NOT NULL,
    terminal_name text NOT NULL CHECK (char_length(terminal_name) BETWEEN 1 AND 64),
    platform text NOT NULL CHECK (platform IN ('ios', 'android')),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    refresh_family_id uuid NOT NULL,
    activated_at timestamptz NOT NULL,
    last_refreshed_at timestamptz,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_installation_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, license_id) REFERENCES device.license_entitlements(tenant_id, license_id),
    CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE INDEX ix_access_terminals_active_license
ON iam.access_terminals (tenant_id, license_id)
WHERE status = 'ACTIVE';

CREATE TABLE iam.terminal_refresh_sessions (
    refresh_session_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    client_installation_id uuid NOT NULL,
    refresh_family_id uuid NOT NULL,
    refresh_token_hash bytea NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    replaced_by_session_id uuid,
    revoked_at timestamptz,
    revoke_reason text CHECK (
        revoke_reason IN ('TERMINAL_REVOKED', 'REFRESH_REPLAYED', 'SUPERSEDED')
    ),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, refresh_session_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, client_installation_id)
        REFERENCES iam.access_terminals(tenant_id, client_installation_id),
    FOREIGN KEY (tenant_id, replaced_by_session_id)
        REFERENCES iam.terminal_refresh_sessions(tenant_id, refresh_session_id),
    CHECK (idle_expires_at > issued_at),
    CHECK (absolute_expires_at >= idle_expires_at),
    CHECK ((rotated_at IS NULL) = (replaced_by_session_id IS NULL)),
    CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);

CREATE INDEX ix_terminal_refresh_sessions_family
ON iam.terminal_refresh_sessions (tenant_id, refresh_family_id);

-- Opaque routes needed before an RLS-scoped transaction can begin; they hold
-- no names, platforms or credentials.
CREATE TABLE iam.terminal_directory (
    client_installation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.terminal_refresh_directory (
    refresh_token_hash bytea PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    refresh_session_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, refresh_session_id)
        REFERENCES iam.terminal_refresh_sessions(tenant_id, refresh_session_id)
);

ALTER TABLE iam.access_terminals ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.access_terminals FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.terminal_refresh_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.terminal_refresh_sessions FORCE ROW LEVEL SECURITY;

CREATE POLICY iam_access_terminals_tenant_isolation ON iam.access_terminals
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY iam_terminal_refresh_sessions_tenant_isolation ON iam.terminal_refresh_sessions
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

REVOKE ALL ON iam.terminal_directory FROM PUBLIC;
REVOKE ALL ON iam.terminal_refresh_directory FROM PUBLIC;

GRANT SELECT, INSERT, UPDATE ON iam.access_terminals TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON iam.terminal_refresh_sessions TO ffp_activation_app;
GRANT SELECT, INSERT ON iam.terminal_directory TO ffp_activation_app;
GRANT SELECT, INSERT ON iam.terminal_refresh_directory TO ffp_activation_app;

COMMIT;
