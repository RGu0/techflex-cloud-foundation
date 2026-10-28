BEGIN;

-- A grant is issued for one installation and one future session. The issuance
-- adapter must lock device.client_installations before counting ISSUED grants
-- and inserting replacements in the same transaction; this index supports
-- that count but cannot by itself enforce the per-installation limit of 50.
CREATE TABLE screening.capture_grants (
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    session_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    account_id uuid NOT NULL,
    license_id uuid NOT NULL,
    hardware_id uuid NOT NULL,
    token_sha256 bytea NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now(),
    state text NOT NULL DEFAULT 'ISSUED'
        CHECK (state IN ('ISSUED', 'CONSUMED', 'RETIRED')),
    consumed_request_sha256 text,
    expected_manifest_sha256 text,
    PRIMARY KEY (tenant_id, session_id),
    UNIQUE (token_sha256),
    FOREIGN KEY (tenant_id, installation_id)
        REFERENCES device.client_installations(tenant_id, client_installation_id),
    FOREIGN KEY (tenant_id, account_id)
        REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, license_id)
        REFERENCES device.license_entitlements(tenant_id, license_id),
    FOREIGN KEY (tenant_id, hardware_id)
        REFERENCES device.hardware_assets(tenant_id, hardware_id),
    CHECK (octet_length(token_sha256) = 32),
    CHECK (consumed_request_sha256 IS NULL OR consumed_request_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (expected_manifest_sha256 IS NULL OR expected_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    CHECK (state <> 'CONSUMED' OR
           (consumed_request_sha256 IS NOT NULL AND expected_manifest_sha256 IS NOT NULL))
);

CREATE INDEX ix_capture_grants_unfinished_installation
ON screening.capture_grants (tenant_id, installation_id)
WHERE state = 'ISSUED';

-- A migration permit is signed by a platform owner for a single pre-existing
-- valid session after identity and consent reconciliation. The server stores
-- only the permit digest and the reviewed evidence reference.
CREATE TABLE screening.upload_migration_permits (
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    session_id uuid NOT NULL,
    installation_id uuid NOT NULL,
    account_id uuid NOT NULL,
    license_id uuid NOT NULL,
    hardware_id uuid NOT NULL,
    token_sha256 bytea NOT NULL,
    issued_at timestamptz NOT NULL DEFAULT now(),
    state text NOT NULL DEFAULT 'ISSUED'
        CHECK (state IN ('ISSUED', 'CONSUMED', 'RETIRED')),
    consumed_request_sha256 text NOT NULL
        CHECK (consumed_request_sha256 ~ '^[0-9a-f]{64}$'),
    expected_manifest_sha256 text NOT NULL
        CHECK (expected_manifest_sha256 ~ '^[0-9a-f]{64}$'),
    approver_id uuid NOT NULL REFERENCES iam.platform_identities(platform_identity_id),
    approval_reason text NOT NULL CHECK (length(btrim(approval_reason)) > 0),
    evidence_reference text NOT NULL CHECK (length(btrim(evidence_reference)) > 0),
    PRIMARY KEY (tenant_id, session_id),
    UNIQUE (token_sha256),
    FOREIGN KEY (tenant_id, installation_id)
        REFERENCES device.client_installations(tenant_id, client_installation_id),
    FOREIGN KEY (tenant_id, account_id)
        REFERENCES iam.tenant_accounts(tenant_id, account_id),
    FOREIGN KEY (tenant_id, license_id)
        REFERENCES device.license_entitlements(tenant_id, license_id),
    FOREIGN KEY (tenant_id, hardware_id)
        REFERENCES device.hardware_assets(tenant_id, hardware_id),
    CHECK (octet_length(token_sha256) = 32)
);

-- These events contain references and decisions, never a usable credential,
-- signed License, subject consent, or segment payload.
CREATE TABLE ops.capture_authorization_audit (
    event_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    session_id uuid NOT NULL,
    authorization_kind text NOT NULL CHECK (authorization_kind IN ('GRANT', 'PERMIT')),
    event_kind text NOT NULL CHECK (event_kind IN ('ISSUED', 'CONSUMED', 'RETIRED', 'APPROVED', 'REJECTED')),
    actor_id uuid NOT NULL,
    evidence_reference text,
    decision_code text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX ix_capture_authorization_audit_session
ON ops.capture_authorization_audit (tenant_id, session_id, occurred_at);

-- Database state transitions stay one-way even if a caller issues raw SQL.
-- Identity and digest bindings are immutable after insertion.
CREATE FUNCTION screening.guard_capture_authorization_update()
RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF (to_jsonb(NEW) - 'state' - 'consumed_request_sha256' - 'expected_manifest_sha256')
       IS DISTINCT FROM
       (to_jsonb(OLD) - 'state' - 'consumed_request_sha256' - 'expected_manifest_sha256') THEN
        RAISE EXCEPTION 'capture authorization binding is immutable';
    END IF;
    IF OLD.state <> 'ISSUED' AND NEW IS DISTINCT FROM OLD THEN
        RAISE EXCEPTION 'terminal capture authorization is immutable';
    END IF;
    IF OLD.state = 'ISSUED' AND NEW.state NOT IN ('ISSUED', 'CONSUMED', 'RETIRED') THEN
        RAISE EXCEPTION 'invalid capture authorization state';
    END IF;
    IF OLD.consumed_request_sha256 IS NOT NULL
       AND NEW.consumed_request_sha256 IS DISTINCT FROM OLD.consumed_request_sha256 THEN
        RAISE EXCEPTION 'capture request digest is immutable';
    END IF;
    IF OLD.expected_manifest_sha256 IS NOT NULL
       AND NEW.expected_manifest_sha256 IS DISTINCT FROM OLD.expected_manifest_sha256 THEN
        RAISE EXCEPTION 'capture manifest digest is immutable';
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER guard_capture_grant_update
BEFORE UPDATE ON screening.capture_grants
FOR EACH ROW EXECUTE FUNCTION screening.guard_capture_authorization_update();
CREATE TRIGGER guard_upload_migration_permit_update
BEFORE UPDATE ON screening.upload_migration_permits
FOR EACH ROW EXECUTE FUNCTION screening.guard_capture_authorization_update();

ALTER TABLE screening.capture_grants ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening.capture_grants FORCE ROW LEVEL SECURITY;
ALTER TABLE screening.upload_migration_permits ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening.upload_migration_permits FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.capture_authorization_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.capture_authorization_audit FORCE ROW LEVEL SECURITY;

CREATE POLICY capture_grants_tenant_isolation ON screening.capture_grants
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY upload_migration_permits_tenant_isolation ON screening.upload_migration_permits
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY capture_authorization_audit_tenant_isolation ON ops.capture_authorization_audit
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

REVOKE ALL ON screening.capture_grants FROM PUBLIC;
REVOKE ALL ON screening.upload_migration_permits FROM PUBLIC;
REVOKE ALL ON ops.capture_authorization_audit FROM PUBLIC;

GRANT SELECT, INSERT ON screening.capture_grants TO ffp_tenant_app;
GRANT UPDATE (state, consumed_request_sha256, expected_manifest_sha256) ON screening.capture_grants TO ffp_tenant_app;
GRANT SELECT ON screening.upload_migration_permits TO ffp_tenant_app;
GRANT UPDATE (state) ON screening.upload_migration_permits TO ffp_tenant_app;
GRANT INSERT ON ops.capture_authorization_audit TO ffp_tenant_app;

GRANT SELECT, INSERT ON screening.upload_migration_permits TO ffp_platform_app;
GRANT INSERT ON ops.capture_authorization_audit TO ffp_platform_app;

COMMIT;
