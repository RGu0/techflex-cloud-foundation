BEGIN;

-- These group roles are intentionally non-login and non-privileged. Deployment
-- creates separate LOGIN roles and grants only the required group membership.
DO $roles$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_tenant_app') THEN
        EXECUTE 'CREATE ROLE ffp_tenant_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_activation_app') THEN
        EXECUTE 'CREATE ROLE ffp_activation_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ffp_platform_app') THEN
        EXECUTE 'CREATE ROLE ffp_platform_app NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS';
    END IF;
END
$roles$;

CREATE TABLE iam.tenant_accounts (
    account_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    login_name_hmac bytea NOT NULL,
    display_name text NOT NULL,
    password_hash text,
    status text NOT NULL CHECK (status IN ('PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED')),
    token_version integer NOT NULL DEFAULT 1 CHECK (token_version > 0),
    activated_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, account_id),
    UNIQUE (login_name_hmac),
    CHECK ((status = 'PENDING_ACTIVATION') = (password_hash IS NULL)),
    CHECK ((activated_at IS NULL) = (status = 'PENDING_ACTIVATION'))
);

-- Pre-authentication directory contains only keyed lookup material and opaque
-- identifiers. It lets the activation role discover the tenant before setting
-- app.tenant_id; the role receives no screening or subject privileges.
CREATE TABLE iam.account_login_directory (
    login_name_hmac bytea PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    status text NOT NULL CHECK (status IN ('PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id)
);

CREATE TABLE device.hardware_assets (
    hardware_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    stable_identity text NOT NULL CHECK (stable_identity ~ '^usb-serial-[0-9a-f]{20}$'),
    model text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, hardware_id),
    UNIQUE (stable_identity)
);

CREATE TABLE device.license_entitlements (
    license_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    status text NOT NULL CHECK (status IN ('PENDING_ACTIVATION', 'ACTIVE', 'SUSPENDED', 'REVOKED')),
    enabled_features text[] NOT NULL CHECK (cardinality(enabled_features) > 0),
    issued_at timestamptz NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_until timestamptz NOT NULL,
    license_version integer NOT NULL CHECK (license_version > 0),
    key_id text NOT NULL,
    document_json jsonb,
    signature text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, license_id),
    CHECK (valid_until > valid_from),
    CHECK ((status = 'PENDING_ACTIVATION') = (document_json IS NULL)),
    CHECK ((document_json IS NULL) = (signature IS NULL))
);

CREATE TABLE device.license_assignments (
    license_assignment_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    license_id uuid NOT NULL,
    account_id uuid NOT NULL,
    assigned_at timestamptz NOT NULL,
    unassigned_at timestamptz,
    reason_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, license_assignment_id),
    FOREIGN KEY (tenant_id, license_id) REFERENCES device.license_entitlements(tenant_id, license_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    CHECK (unassigned_at IS NULL OR unassigned_at > assigned_at),
    CHECK ((unassigned_at IS NULL) = (reason_code IS NULL))
);

CREATE UNIQUE INDEX uq_open_license_assignment
ON device.license_assignments (license_id)
WHERE unassigned_at IS NULL;

CREATE TABLE device.hardware_bindings (
    hardware_binding_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    license_id uuid NOT NULL,
    hardware_id uuid NOT NULL,
    bound_at timestamptz NOT NULL,
    unbound_at timestamptz,
    reason_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, hardware_binding_id),
    FOREIGN KEY (tenant_id, license_id) REFERENCES device.license_entitlements(tenant_id, license_id),
    FOREIGN KEY (tenant_id, hardware_id) REFERENCES device.hardware_assets(tenant_id, hardware_id),
    CHECK (unbound_at IS NULL OR unbound_at > bound_at),
    CHECK ((unbound_at IS NULL) = (reason_code IS NULL))
);

CREATE UNIQUE INDEX uq_open_hardware_binding
ON device.hardware_bindings (hardware_id)
WHERE unbound_at IS NULL;

CREATE UNIQUE INDEX uq_open_license_hardware_binding
ON device.hardware_bindings (license_id)
WHERE unbound_at IS NULL;

CREATE TABLE iam.account_activation_codes (
    activation_code_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    license_id uuid NOT NULL,
    hardware_id uuid NOT NULL,
    activation_code_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, activation_code_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, license_id) REFERENCES device.license_entitlements(tenant_id, license_id),
    FOREIGN KEY (tenant_id, hardware_id) REFERENCES device.hardware_assets(tenant_id, hardware_id)
);

CREATE TABLE device.client_installations (
    client_installation_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    first_seen_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, client_installation_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    CHECK (last_seen_at >= first_seen_at)
);

CREATE TABLE iam.tenant_refresh_sessions (
    refresh_session_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    account_id uuid NOT NULL,
    client_installation_id uuid NOT NULL,
    refresh_token_hash bytea NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz,
    replaced_by_session_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, refresh_session_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, client_installation_id) REFERENCES device.client_installations(tenant_id, client_installation_id),
    FOREIGN KEY (tenant_id, replaced_by_session_id) REFERENCES iam.tenant_refresh_sessions(tenant_id, refresh_session_id),
    CHECK (idle_expires_at > issued_at),
    CHECK (absolute_expires_at >= idle_expires_at),
    CHECK (last_used_at >= issued_at)
);

CREATE TABLE iam.refresh_session_directory (
    refresh_token_hash bytea PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    refresh_session_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, refresh_session_id) REFERENCES iam.tenant_refresh_sessions(tenant_id, refresh_session_id)
);

CREATE TABLE device.hardware_leases (
    lease_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    license_id uuid NOT NULL,
    account_id uuid NOT NULL,
    hardware_id uuid NOT NULL,
    client_installation_id uuid NOT NULL,
    acquired_at timestamptz NOT NULL,
    renewed_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    released_at timestamptz,
    release_reason text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, lease_id),
    FOREIGN KEY (tenant_id, license_id) REFERENCES device.license_entitlements(tenant_id, license_id),
    FOREIGN KEY (tenant_id, account_id) REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, hardware_id) REFERENCES device.hardware_assets(tenant_id, hardware_id),
    FOREIGN KEY (tenant_id, client_installation_id) REFERENCES device.client_installations(tenant_id, client_installation_id),
    CHECK (renewed_at >= acquired_at),
    CHECK (expires_at > renewed_at),
    CHECK (released_at IS NULL OR released_at >= acquired_at),
    CHECK ((released_at IS NULL) = (release_reason IS NULL))
);

CREATE UNIQUE INDEX uq_open_hardware_lease
ON device.hardware_leases (hardware_id)
WHERE released_at IS NULL;

CREATE TABLE iam.platform_identities (
    platform_identity_id uuid PRIMARY KEY,
    login_name_hmac bytea NOT NULL UNIQUE,
    display_name text NOT NULL,
    password_hash text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    token_version integer NOT NULL DEFAULT 1 CHECK (token_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.platform_roles (
    platform_role_id uuid PRIMARY KEY,
    role_name text NOT NULL UNIQUE CHECK (
        role_name IN ('PLATFORM_OWNER', 'PLATFORM_OPERATIONS', 'PLATFORM_SUPPORT', 'PLATFORM_ENGINEER')
    ),
    created_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO iam.platform_roles (platform_role_id, role_name)
VALUES
    (gen_random_uuid(), 'PLATFORM_OWNER'),
    (gen_random_uuid(), 'PLATFORM_OPERATIONS'),
    (gen_random_uuid(), 'PLATFORM_SUPPORT'),
    (gen_random_uuid(), 'PLATFORM_ENGINEER')
ON CONFLICT (role_name) DO NOTHING;

CREATE TABLE iam.platform_identity_role_bindings (
    platform_identity_role_binding_id uuid PRIMARY KEY,
    platform_identity_id uuid NOT NULL REFERENCES iam.platform_identities(platform_identity_id),
    platform_role_id uuid NOT NULL REFERENCES iam.platform_roles(platform_role_id),
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE UNIQUE INDEX uq_open_platform_role_binding
ON iam.platform_identity_role_bindings (platform_identity_id, platform_role_id)
WHERE valid_to IS NULL;

CREATE TABLE iam.platform_refresh_sessions (
    platform_refresh_session_id uuid PRIMARY KEY,
    platform_identity_id uuid NOT NULL REFERENCES iam.platform_identities(platform_identity_id),
    refresh_token_hash bytea NOT NULL UNIQUE,
    issued_at timestamptz NOT NULL,
    last_used_at timestamptz NOT NULL,
    idle_expires_at timestamptz NOT NULL,
    absolute_expires_at timestamptz NOT NULL,
    rotated_at timestamptz,
    revoked_at timestamptz,
    replaced_by_session_id uuid REFERENCES iam.platform_refresh_sessions(platform_refresh_session_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CHECK (idle_expires_at > issued_at),
    CHECK (absolute_expires_at >= idle_expires_at),
    CHECK (last_used_at >= issued_at)
);

CREATE TABLE ops.sensitive_access_grants (
    sensitive_access_grant_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    platform_identity_id uuid NOT NULL REFERENCES iam.platform_identities(platform_identity_id),
    purpose_code text NOT NULL,
    ticket_reference text NOT NULL,
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sensitive_access_grant_id),
    CHECK (expires_at > issued_at),
    CHECK (expires_at <= issued_at + interval '15 minutes'),
    CHECK (revoked_at IS NULL OR revoked_at >= issued_at)
);

CREATE TABLE ops.authentication_attempts (
    authentication_attempt_id uuid PRIMARY KEY,
    login_name_hmac bytea NOT NULL,
    source_fingerprint bytea NOT NULL,
    attempt_kind text NOT NULL CHECK (attempt_kind IN ('TENANT_LOGIN', 'TENANT_ACTIVATION', 'PLATFORM_LOGIN')),
    succeeded boolean NOT NULL,
    attempted_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Opaque identifiers need a tenant route before an RLS-scoped transaction can
-- begin. This directory deliberately stores no login, hardware, License
-- document, or subject data.
CREATE TABLE ops.access_resource_directory (
    resource_type text NOT NULL CHECK (
        resource_type IN ('ACCOUNT', 'LICENSE', 'HARDWARE', 'ACTIVATION_CODE', 'INSTALLATION')
    ),
    resource_id uuid NOT NULL,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (resource_type, resource_id)
);

CREATE TABLE device.hardware_identity_directory (
    stable_identity text PRIMARY KEY CHECK (stable_identity ~ '^usb-serial-[0-9a-f]{20}$'),
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    hardware_id uuid NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, hardware_id) REFERENCES device.hardware_assets(tenant_id, hardware_id)
);

CREATE TABLE ops.access_audit_events (
    access_audit_event_id uuid PRIMARY KEY,
    actor_id uuid NOT NULL,
    action text NOT NULL,
    tenant_id uuid REFERENCES iam.tenants(tenant_id),
    resource_id uuid,
    occurred_at timestamptz NOT NULL,
    details jsonb NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX ix_access_audit_events_tenant_time
ON ops.access_audit_events (tenant_id, occurred_at, access_audit_event_id);

CREATE INDEX ix_authentication_attempts_window
ON ops.authentication_attempts (login_name_hmac, attempted_at DESC);

ALTER TABLE iam.tenant_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenant_accounts FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.account_activation_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.account_activation_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.tenant_refresh_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenant_refresh_sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE device.hardware_assets ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.hardware_assets FORCE ROW LEVEL SECURITY;
ALTER TABLE device.license_entitlements ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.license_entitlements FORCE ROW LEVEL SECURITY;
ALTER TABLE device.license_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.license_assignments FORCE ROW LEVEL SECURITY;
ALTER TABLE device.hardware_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.hardware_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE device.client_installations ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.client_installations FORCE ROW LEVEL SECURITY;
ALTER TABLE device.hardware_leases ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.hardware_leases FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.sensitive_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.sensitive_access_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY iam_tenant_accounts_tenant_isolation ON iam.tenant_accounts
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY iam_account_activation_codes_tenant_isolation ON iam.account_activation_codes
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY iam_tenant_refresh_sessions_tenant_isolation ON iam.tenant_refresh_sessions
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_hardware_assets_tenant_isolation ON device.hardware_assets
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_license_entitlements_tenant_isolation ON device.license_entitlements
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_license_assignments_tenant_isolation ON device.license_assignments
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_hardware_bindings_tenant_isolation ON device.hardware_bindings
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_client_installations_tenant_isolation ON device.client_installations
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_hardware_leases_tenant_isolation ON device.hardware_leases
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY ops_sensitive_access_grants_tenant_isolation ON ops.sensitive_access_grants
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

REVOKE ALL ON iam.account_login_directory FROM PUBLIC;
REVOKE ALL ON iam.refresh_session_directory FROM PUBLIC;
REVOKE ALL ON ops.authentication_attempts FROM PUBLIC;
REVOKE ALL ON ops.access_resource_directory FROM PUBLIC;
REVOKE ALL ON device.hardware_identity_directory FROM PUBLIC;
REVOKE ALL ON ops.access_audit_events FROM PUBLIC;

GRANT USAGE ON SCHEMA iam, device, subject, screening, ops TO ffp_tenant_app;
GRANT USAGE ON SCHEMA iam, device, ops TO ffp_activation_app;
GRANT USAGE ON SCHEMA iam, device, subject, screening, ops TO ffp_platform_app;

GRANT SELECT, INSERT, UPDATE ON iam.tenant_accounts TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON iam.account_activation_codes TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON iam.tenant_refresh_sessions TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_assets TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.license_entitlements TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.license_assignments TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_bindings TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.client_installations TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_leases TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON device.terminals TO ffp_tenant_app;
GRANT SELECT ON device.devices TO ffp_tenant_app;
GRANT SELECT ON device.terminal_device_bindings TO ffp_tenant_app;
GRANT SELECT, INSERT ON device.terminal_heartbeats TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON subject.subjects TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON subject.external_identifiers TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON subject.identity_profiles TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON subject.analysis_profiles TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON subject.consents TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON screening.sessions TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON screening.session_segments TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON screening.session_manifests TO ffp_tenant_app;
GRANT SELECT, INSERT ON screening.ingest_problems TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON ops.idempotency_keys TO ffp_tenant_app;
GRANT SELECT, INSERT ON ops.outbox_events TO ffp_tenant_app;
GRANT INSERT ON ops.audit_logs TO ffp_tenant_app;

GRANT SELECT, UPDATE ON iam.account_login_directory TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON iam.refresh_session_directory TO ffp_activation_app;
GRANT SELECT, INSERT ON ops.authentication_attempts TO ffp_activation_app;
GRANT SELECT, INSERT ON ops.access_resource_directory TO ffp_activation_app;
GRANT SELECT ON device.hardware_identity_directory TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON iam.tenant_accounts TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON iam.account_activation_codes TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON iam.tenant_refresh_sessions TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.client_installations TO ffp_activation_app;
GRANT SELECT ON device.hardware_assets TO ffp_activation_app;
GRANT SELECT, UPDATE ON device.license_entitlements TO ffp_activation_app;
GRANT SELECT ON device.license_assignments TO ffp_activation_app;
GRANT SELECT ON device.hardware_bindings TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_leases TO ffp_activation_app;

GRANT SELECT, INSERT, UPDATE ON iam.platform_identities TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.platform_roles TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.platform_identity_role_bindings TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.platform_refresh_sessions TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.account_login_directory TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.refresh_session_directory TO ffp_platform_app;
GRANT SELECT, INSERT ON ops.authentication_attempts TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON ops.access_resource_directory TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_identity_directory TO ffp_platform_app;
GRANT SELECT, INSERT ON ops.access_audit_events TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.tenants TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.tenant_accounts TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.account_activation_codes TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON iam.tenant_refresh_sessions TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_assets TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.license_entitlements TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.license_assignments TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_bindings TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.client_installations TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON device.hardware_leases TO ffp_platform_app;
GRANT SELECT, INSERT, UPDATE ON ops.sensitive_access_grants TO ffp_platform_app;

COMMIT;
