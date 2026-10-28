BEGIN;

CREATE TABLE iam.users (
    user_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    auth_subject_hash bytea NOT NULL,
    display_name text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_id),
    UNIQUE (tenant_id, auth_subject_hash)
);

CREATE TABLE iam.roles (
    role_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    name text NOT NULL,
    permissions text[] NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'RETIRED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, role_id),
    UNIQUE (tenant_id, name)
);

CREATE TABLE iam.user_role_bindings (
    user_role_binding_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    user_id uuid NOT NULL,
    role_id uuid NOT NULL,
    site_id uuid,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, user_role_binding_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES iam.users(tenant_id, user_id),
    FOREIGN KEY (tenant_id, role_id) REFERENCES iam.roles(tenant_id, role_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE UNIQUE INDEX ux_user_role_scope_active
ON iam.user_role_bindings(tenant_id, user_id, role_id, site_id)
WHERE valid_to IS NULL;

CREATE TABLE device.licenses (
    license_record_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    license_id uuid NOT NULL,
    license_version integer NOT NULL CHECK (license_version > 0),
    terminal_id uuid NOT NULL,
    site_id uuid,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    enabled_features text[] NOT NULL,
    issued_at timestamptz NOT NULL,
    not_before timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    schema_version text NOT NULL,
    key_id text NOT NULL,
    document_json jsonb NOT NULL,
    signature text NOT NULL,
    previous_license_record_id uuid,
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, license_record_id),
    UNIQUE (tenant_id, license_id, license_version),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id),
    FOREIGN KEY (tenant_id, created_by) REFERENCES iam.users(tenant_id, user_id),
    FOREIGN KEY (tenant_id, previous_license_record_id)
        REFERENCES device.licenses(tenant_id, license_record_id),
    CHECK (expires_at > not_before)
);

CREATE INDEX ix_licenses_terminal_latest
ON device.licenses(tenant_id, terminal_id, license_id, license_version DESC);

CREATE TABLE device.upgrade_policies (
    upgrade_policy_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    site_id uuid,
    platform text NOT NULL CHECK (platform IN ('windows', 'macos', 'linux')),
    target_version text NOT NULL,
    minimum_supported_version text NOT NULL,
    rollout_percent integer NOT NULL CHECK (rollout_percent BETWEEN 0 AND 100),
    package_sha256 text NOT NULL CHECK (package_sha256 ~ '^[0-9a-f]{64}$'),
    package_signature text NOT NULL,
    rollback_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('DRAFT', 'ACTIVE', 'PAUSED', 'ROLLED_BACK')),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, upgrade_policy_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id),
    FOREIGN KEY (tenant_id, created_by) REFERENCES iam.users(tenant_id, user_id),
    CHECK (target_version <> rollback_version)
);

CREATE TABLE ops.support_access_grants (
    support_access_grant_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    principal_id uuid NOT NULL,
    site_id uuid,
    data_category text NOT NULL CHECK (
        data_category IN ('RAW_DATA', 'IDENTITY', 'LOGS', 'DIAGNOSTICS')
    ),
    purpose_code text NOT NULL,
    resource_id uuid,
    granted_by uuid NOT NULL,
    granted_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, support_access_grant_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id),
    FOREIGN KEY (tenant_id, granted_by) REFERENCES iam.users(tenant_id, user_id),
    CHECK (expires_at > granted_at),
    CHECK (revoked_at IS NULL OR revoked_at >= granted_at)
);

ALTER TABLE iam.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.users FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.roles FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.user_role_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.user_role_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE device.licenses ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.licenses FORCE ROW LEVEL SECURITY;
ALTER TABLE device.upgrade_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.upgrade_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.support_access_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.support_access_grants FORCE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation ON iam.users
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON iam.roles
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON iam.user_role_bindings
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON device.licenses
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON device.upgrade_policies
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY tenant_isolation ON ops.support_access_grants
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

COMMIT;
