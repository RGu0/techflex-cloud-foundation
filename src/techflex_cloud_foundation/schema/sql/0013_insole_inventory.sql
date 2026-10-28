BEGIN;

-- RAY-778 R1: institutional insole inventory. One row per pair (left master /
-- right slave). Pairs are never deleted: retirement is a state, and the
-- download cursor is a per-tenant revision assigned while the tenant's
-- counter row is locked, so commit order equals revision order. Existing
-- device, sales and terminal tables are not changed.
CREATE TABLE device.insole_revision_counters (
    tenant_id uuid PRIMARY KEY REFERENCES iam.tenants(tenant_id),
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0)
);

CREATE TABLE device.insole_pairs (
    insole_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    institution_number text NOT NULL
        CHECK (char_length(institution_number) BETWEEN 1 AND 32),
    size integer NOT NULL CHECK (size BETWEEN 1 AND 99),
    left_identity_kind text NOT NULL CHECK (left_identity_kind IN ('mac', 'serial')),
    left_identity_value text NOT NULL CHECK (char_length(left_identity_value) BETWEEN 1 AND 64),
    left_identity_provenance text NOT NULL
        CHECK (char_length(left_identity_provenance) BETWEEN 1 AND 64),
    left_firmware_version text CHECK (char_length(left_firmware_version) BETWEEN 1 AND 64),
    left_battery_millivolts integer CHECK (left_battery_millivolts BETWEEN 0 AND 10000),
    left_battery_percent integer CHECK (left_battery_percent BETWEEN 0 AND 100),
    left_battery_read_at timestamptz,
    left_battery_reported_by uuid,
    right_identity_kind text NOT NULL CHECK (right_identity_kind IN ('mac', 'serial')),
    right_identity_value text NOT NULL CHECK (char_length(right_identity_value) BETWEEN 1 AND 64),
    right_identity_provenance text NOT NULL
        CHECK (char_length(right_identity_provenance) BETWEEN 1 AND 64),
    right_firmware_version text CHECK (char_length(right_firmware_version) BETWEEN 1 AND 64),
    right_battery_millivolts integer CHECK (right_battery_millivolts BETWEEN 0 AND 10000),
    right_battery_percent integer CHECK (right_battery_percent BETWEEN 0 AND 100),
    right_battery_read_at timestamptz,
    right_battery_reported_by uuid,
    state text NOT NULL CHECK (state IN ('available', 'in_use', 'unreturned_data', 'retired')),
    state_observed_at timestamptz,
    holder_client_installation_id uuid,
    holder_terminal_name text CHECK (char_length(holder_terminal_name) BETWEEN 1 AND 64),
    registered_at timestamptz NOT NULL,
    registered_by uuid NOT NULL,
    retired_at timestamptz,
    retired_by uuid,
    revision bigint NOT NULL CHECK (revision > 0),
    updated_at timestamptz NOT NULL,
    UNIQUE (tenant_id, insole_id),
    UNIQUE (tenant_id, institution_number),
    UNIQUE (tenant_id, revision),
    CHECK ((left_identity_kind, left_identity_value)
        IS DISTINCT FROM (right_identity_kind, right_identity_value)),
    CHECK ((left_battery_read_at IS NULL) = (left_battery_millivolts IS NULL)
        AND (left_battery_read_at IS NULL) = (left_battery_percent IS NULL)
        AND (left_battery_read_at IS NULL) = (left_battery_reported_by IS NULL)),
    CHECK ((right_battery_read_at IS NULL) = (right_battery_millivolts IS NULL)
        AND (right_battery_read_at IS NULL) = (right_battery_percent IS NULL)
        AND (right_battery_read_at IS NULL) = (right_battery_reported_by IS NULL)),
    CHECK ((state = 'in_use') = (holder_client_installation_id IS NOT NULL)),
    CHECK ((holder_client_installation_id IS NULL) = (holder_terminal_name IS NULL)),
    CHECK ((state = 'retired') = (retired_at IS NOT NULL)),
    CHECK ((retired_at IS NULL) = (retired_by IS NULL))
);

-- Identity uniqueness across both sides of every pair of the tenant.
CREATE TABLE device.insole_identities (
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    identity_kind text NOT NULL CHECK (identity_kind IN ('mac', 'serial')),
    identity_value text NOT NULL,
    insole_id uuid NOT NULL,
    side text NOT NULL CHECK (side IN ('left', 'right')),
    PRIMARY KEY (tenant_id, identity_kind, identity_value),
    UNIQUE (tenant_id, insole_id, side),
    FOREIGN KEY (tenant_id, insole_id) REFERENCES device.insole_pairs(tenant_id, insole_id)
);

-- Registration Idempotency-Key, scoped to the registering terminal.
CREATE TABLE device.insole_registration_keys (
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    client_installation_id uuid NOT NULL,
    idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 1 AND 256),
    request_sha256 bytea NOT NULL CHECK (octet_length(request_sha256) = 32),
    insole_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, client_installation_id, idempotency_key),
    FOREIGN KEY (tenant_id, insole_id) REFERENCES device.insole_pairs(tenant_id, insole_id)
);

ALTER TABLE device.insole_revision_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.insole_revision_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE device.insole_pairs ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.insole_pairs FORCE ROW LEVEL SECURITY;
ALTER TABLE device.insole_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.insole_identities FORCE ROW LEVEL SECURITY;
ALTER TABLE device.insole_registration_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.insole_registration_keys FORCE ROW LEVEL SECURITY;

CREATE POLICY device_insole_revision_counters_tenant_isolation
ON device.insole_revision_counters
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_insole_pairs_tenant_isolation ON device.insole_pairs
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_insole_identities_tenant_isolation ON device.insole_identities
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY device_insole_registration_keys_tenant_isolation
ON device.insole_registration_keys
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

-- No DELETE grant: retirement is the only way a pair leaves service.
GRANT SELECT, INSERT, UPDATE ON device.insole_revision_counters TO ffp_activation_app;
GRANT SELECT, INSERT, UPDATE ON device.insole_pairs TO ffp_activation_app;
GRANT SELECT, INSERT ON device.insole_identities TO ffp_activation_app;
GRANT SELECT, INSERT ON device.insole_registration_keys TO ffp_activation_app;

COMMIT;
