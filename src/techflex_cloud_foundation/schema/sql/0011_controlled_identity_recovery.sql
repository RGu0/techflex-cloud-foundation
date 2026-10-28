BEGIN;

-- The case is bound once to the sealed local session and the existing cloud
-- subject. Plaintext name/contact never enter this table or terminal response.
CREATE TABLE ops.identity_recovery_cases (
    case_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    terminal_id uuid NOT NULL,
    session_id uuid NOT NULL,
    original_subject_uuid uuid NOT NULL,
    cloud_subject_uuid uuid NOT NULL,
    envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    identifier_issuer text NOT NULL,
    identifier_type text NOT NULL,
    external_identifier_id uuid NOT NULL,
    identifier_hmac bytea NOT NULL CHECK (octet_length(identifier_hmac) = 32),
    key_sha256 text NOT NULL CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    masked_clue text,
    status text NOT NULL CHECK (status IN ('PENDING','MATCHED','DENIED','EXPIRED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 3),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, case_id),
    UNIQUE (tenant_id, session_id),
    UNIQUE (tenant_id, key_sha256),
    FOREIGN KEY (tenant_id, cloud_subject_uuid)
        REFERENCES subject.subjects(tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, external_identifier_id)
        REFERENCES subject.external_identifiers(tenant_id, external_identifier_id),
    CHECK (original_subject_uuid <> cloud_subject_uuid)
);

ALTER TABLE ops.identity_recovery_cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.identity_recovery_cases FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_recovery_cases_tenant_isolation ON ops.identity_recovery_cases
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

REVOKE ALL ON ops.identity_recovery_cases FROM PUBLIC;
GRANT SELECT, INSERT ON ops.identity_recovery_cases TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON ops.identity_recovery_cases TO ffp_platform_app;

CREATE TABLE ops.identity_recovery_receipts (
    receipt_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    case_id uuid NOT NULL,
    terminal_id uuid NOT NULL,
    session_id uuid NOT NULL,
    original_subject_uuid uuid NOT NULL,
    cloud_subject_uuid uuid NOT NULL,
    envelope_sha256 text NOT NULL CHECK (envelope_sha256 ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL,
    ticket_sha256 text NOT NULL CHECK (ticket_sha256 ~ '^[0-9a-f]{64}$'),
    consumed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, receipt_id),
    UNIQUE (tenant_id, case_id),
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES ops.identity_recovery_cases(tenant_id, case_id)
);

CREATE TABLE ops.identity_recovery_comparisons (
    comparison_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    case_id uuid NOT NULL,
    actor_id uuid NOT NULL,
    grant_id uuid NOT NULL,
    ticket_sha256 text NOT NULL CHECK (ticket_sha256 ~ '^[0-9a-f]{64}$'),
    decision text NOT NULL CHECK (decision IN ('MATCHED','NOT_VERIFIED')),
    compared_fields text[] NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, comparison_id),
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES ops.identity_recovery_cases(tenant_id, case_id)
);

ALTER TABLE ops.identity_recovery_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.identity_recovery_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_recovery_receipts_tenant_isolation ON ops.identity_recovery_receipts
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
ALTER TABLE ops.identity_recovery_comparisons ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.identity_recovery_comparisons FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_recovery_comparisons_tenant_isolation ON ops.identity_recovery_comparisons
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

REVOKE ALL ON ops.identity_recovery_receipts, ops.identity_recovery_comparisons FROM PUBLIC;
GRANT SELECT ON ops.identity_recovery_receipts TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON ops.identity_recovery_receipts TO ffp_platform_app;
GRANT SELECT, INSERT ON ops.identity_recovery_comparisons TO ffp_platform_app;

-- Platform comparison verifies only current routing status. Column-level
-- grants avoid exposing encrypted identifiers or identity-profile payloads.
GRANT SELECT (tenant_id, subject_uuid, status)
    ON subject.subjects TO ffp_platform_app;
GRANT SELECT (tenant_id, subject_uuid, external_identifier_id, issuer, id_type, normalized_hmac, status)
    ON subject.external_identifiers TO ffp_platform_app;

CREATE TABLE ops.identity_recovery_registrations (
    registration_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    case_id uuid NOT NULL,
    receipt_id uuid NOT NULL,
    key_sha256 text NOT NULL CHECK (key_sha256 ~ '^[0-9a-f]{64}$'),
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    consent_record_id uuid NOT NULL,
    session_id uuid NOT NULL,
    registered_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, registration_id),
    UNIQUE (tenant_id, case_id),
    UNIQUE (tenant_id, key_sha256),
    FOREIGN KEY (tenant_id, case_id)
        REFERENCES ops.identity_recovery_cases(tenant_id, case_id)
);

ALTER TABLE ops.identity_recovery_registrations ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.identity_recovery_registrations FORCE ROW LEVEL SECURITY;
CREATE POLICY identity_recovery_registrations_tenant_isolation ON ops.identity_recovery_registrations
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
REVOKE ALL ON ops.identity_recovery_registrations FROM PUBLIC;
GRANT SELECT, INSERT ON ops.identity_recovery_registrations TO ffp_tenant_app;
GRANT UPDATE ON ops.identity_recovery_receipts TO ffp_tenant_app;

COMMIT;
