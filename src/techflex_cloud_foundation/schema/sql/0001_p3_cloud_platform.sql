BEGIN;

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE SCHEMA IF NOT EXISTS iam;
CREATE SCHEMA IF NOT EXISTS device;
CREATE SCHEMA IF NOT EXISTS subject;
CREATE SCHEMA IF NOT EXISTS screening;
CREATE SCHEMA IF NOT EXISTS ops;

CREATE OR REPLACE FUNCTION ops.current_tenant_id()
RETURNS uuid
LANGUAGE sql
STABLE
AS $$
    SELECT current_setting('app.tenant_id', true)::uuid
$$;

CREATE TABLE iam.tenants (
    tenant_id uuid PRIMARY KEY,
    name text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE iam.sites (
    site_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    site_code text NOT NULL,
    name text NOT NULL,
    timezone text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'CLOSED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, site_id),
    UNIQUE (tenant_id, site_code)
);

CREATE TABLE device.terminals (
    terminal_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    site_id uuid,
    installation_id uuid NOT NULL,
    client_public_key text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'REVOKED')),
    app_version text,
    config_version text,
    protocol_version text,
    last_seen_at timestamptz,
    last_successful_sync_at timestamptz,
    pending_sessions integer NOT NULL DEFAULT 0 CHECK (pending_sessions >= 0),
    pending_bytes bigint NOT NULL DEFAULT 0 CHECK (pending_bytes >= 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, terminal_id),
    UNIQUE (tenant_id, installation_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id)
);

CREATE TABLE device.devices (
    device_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    model text NOT NULL,
    serial_ciphertext bytea,
    serial_hmac bytea,
    capabilities jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUSPENDED', 'RETIRED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, device_id),
    UNIQUE NULLS NOT DISTINCT (tenant_id, serial_hmac)
);

CREATE TABLE device.terminal_device_bindings (
    terminal_device_binding_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    terminal_id uuid NOT NULL,
    device_id uuid NOT NULL,
    valid_from timestamptz NOT NULL,
    valid_to timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, terminal_device_binding_id),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES device.devices(tenant_id, device_id),
    CHECK (valid_to IS NULL OR valid_to > valid_from)
);

CREATE UNIQUE INDEX ux_terminal_device_active
ON device.terminal_device_bindings(tenant_id, terminal_id, device_id)
WHERE valid_to IS NULL;

CREATE TABLE device.enrollment_codes (
    enrollment_code_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    site_id uuid,
    device_id uuid,
    activation_code_hash bytea NOT NULL UNIQUE,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    terminal_id uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES device.devices(tenant_id, device_id),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    CHECK (used_at IS NULL OR terminal_id IS NOT NULL)
);

CREATE TABLE device.terminal_credentials (
    terminal_credential_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    terminal_id uuid NOT NULL,
    key_id text NOT NULL,
    public_key text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'ROTATED', 'REVOKED')),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    UNIQUE (tenant_id, terminal_credential_id),
    UNIQUE (tenant_id, terminal_id, key_id),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    CHECK (expires_at > issued_at)
);

CREATE TABLE device.terminal_heartbeats (
    terminal_heartbeat_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    terminal_id uuid NOT NULL,
    device_id uuid,
    observed_at timestamptz NOT NULL,
    app_version text NOT NULL,
    config_version text NOT NULL,
    protocol_version text NOT NULL,
    connection_state text NOT NULL,
    last_successful_sync_at timestamptz,
    pending_sessions integer NOT NULL CHECK (pending_sessions >= 0),
    pending_bytes bigint NOT NULL CHECK (pending_bytes >= 0),
    disk_free_bytes bigint NOT NULL CHECK (disk_free_bytes >= 0),
    clock_skew_seconds double precision NOT NULL,
    last_error_code text,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, terminal_heartbeat_id),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES device.devices(tenant_id, device_id)
);

CREATE INDEX ix_terminal_heartbeats_recent
ON device.terminal_heartbeats(tenant_id, terminal_id, observed_at DESC);

CREATE TABLE subject.subjects (
    subject_uuid uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    status text NOT NULL CHECK (status IN ('ACTIVE', 'MERGED', 'ARCHIVED', 'RESTRICTED')),
    merged_into_subject_uuid uuid,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, merged_into_subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid)
);

CREATE TABLE subject.external_identifiers (
    external_identifier_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    subject_uuid uuid NOT NULL,
    issuer text NOT NULL,
    id_type text NOT NULL,
    encrypted_value bytea NOT NULL,
    encryption_nonce bytea NOT NULL,
    normalized_hmac bytea NOT NULL,
    masked_value text NOT NULL,
    key_version text NOT NULL,
    status text NOT NULL CHECK (status IN ('ACTIVE', 'SUPERSEDED', 'REVOKED')),
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE (tenant_id, external_identifier_id),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid)
);

CREATE UNIQUE INDEX ux_external_identifier_active
ON subject.external_identifiers(tenant_id, issuer, id_type, normalized_hmac)
WHERE status = 'ACTIVE';

CREATE TABLE subject.identity_profiles (
    subject_uuid uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    identity_ciphertext bytea NOT NULL,
    encryption_nonce bytea NOT NULL,
    key_version text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid)
);

CREATE TABLE subject.analysis_profiles (
    subject_uuid uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    profile_json jsonb NOT NULL,
    schema_version text NOT NULL,
    source text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid)
);

CREATE TABLE subject.consents (
    consent_record_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    subject_uuid uuid NOT NULL,
    policy_version text NOT NULL,
    purpose_codes text[] NOT NULL CHECK (cardinality(purpose_codes) > 0),
    data_categories text[] NOT NULL CHECK (cardinality(data_categories) > 0),
    evidence_type text NOT NULL,
    terminal_id uuid,
    evidence_hash text NOT NULL CHECK (evidence_hash ~ '^[0-9a-f]{64}$'),
    granted_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason_code text,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, consent_record_id),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    CHECK ((revoked_at IS NULL) = (revocation_reason_code IS NULL))
);

CREATE TABLE screening.sessions (
    session_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    site_id uuid,
    terminal_id uuid NOT NULL,
    device_id uuid NOT NULL,
    subject_uuid uuid NOT NULL,
    consent_record_id uuid NOT NULL,
    test_protocol_id text NOT NULL,
    test_protocol_version text NOT NULL,
    validity_status text NOT NULL DEFAULT 'UNKNOWN'
        CHECK (validity_status IN ('UNKNOWN', 'VALID', 'INVALID', 'INCOMPLETE', 'FAILED')),
    ingest_status text NOT NULL DEFAULT 'RECEIVING'
        CHECK (ingest_status IN ('RECEIVING', 'VERIFYING', 'INGESTED', 'QUARANTINED', 'CONFLICT')),
    started_at timestamptz NOT NULL,
    ended_at timestamptz,
    app_version text NOT NULL,
    protocol_profile_version text NOT NULL,
    payload_schema_version text NOT NULL,
    calibration_version text NOT NULL,
    config_snapshot jsonb NOT NULL,
    manifest_sha256 text,
    aggregate_version bigint NOT NULL DEFAULT 1 CHECK (aggregate_version > 0),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, session_id),
    FOREIGN KEY (tenant_id, site_id) REFERENCES iam.sites(tenant_id, site_id),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id),
    FOREIGN KEY (tenant_id, device_id) REFERENCES device.devices(tenant_id, device_id),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, consent_record_id) REFERENCES subject.consents(tenant_id, consent_record_id),
    CHECK (manifest_sha256 IS NULL OR manifest_sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX ix_sessions_subject_time
ON screening.sessions(tenant_id, subject_uuid, started_at DESC);

CREATE INDEX ix_sessions_ingest_status
ON screening.sessions(tenant_id, ingest_status, created_at)
WHERE ingest_status <> 'INGESTED';

CREATE TABLE screening.session_segments (
    session_segment_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    session_id uuid NOT NULL,
    segment_index integer NOT NULL CHECK (segment_index >= 0),
    object_key text NOT NULL,
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL CHECK (size_bytes > 0),
    start_frame_index bigint NOT NULL CHECK (start_frame_index >= 0),
    frame_count integer NOT NULL CHECK (frame_count > 0),
    start_monotonic_ns bigint NOT NULL CHECK (start_monotonic_ns >= 0),
    end_monotonic_ns bigint NOT NULL,
    payload_schema_version text NOT NULL,
    compression text NOT NULL CHECK (compression IN ('none', 'zstd')),
    cipher text NOT NULL CHECK (cipher = 'aes-256-gcm'),
    status text NOT NULL CHECK (status IN ('STAGED', 'VERIFIED', 'CONFLICT', 'QUARANTINED')),
    received_at timestamptz NOT NULL DEFAULT now(),
    verified_at timestamptz,
    UNIQUE (tenant_id, session_segment_id),
    UNIQUE (tenant_id, session_id, segment_index),
    UNIQUE (tenant_id, object_key),
    FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions(tenant_id, session_id),
    CHECK (end_monotonic_ns > start_monotonic_ns)
);

CREATE INDEX ix_segments_session
ON screening.session_segments(tenant_id, session_id, segment_index);

CREATE TABLE screening.session_manifests (
    manifest_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    session_id uuid NOT NULL,
    schema_version text NOT NULL,
    manifest_sha256 text NOT NULL CHECK (manifest_sha256 ~ '^[0-9a-f]{64}$'),
    object_key text NOT NULL,
    segment_count integer NOT NULL CHECK (segment_count > 0),
    total_frames bigint NOT NULL CHECK (total_frames > 0),
    total_bytes bigint NOT NULL CHECK (total_bytes > 0),
    manifest_json jsonb NOT NULL,
    verification_status text NOT NULL CHECK (verification_status IN ('PENDING', 'VERIFIED', 'REJECTED')),
    verified_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, manifest_id),
    UNIQUE (tenant_id, session_id),
    UNIQUE (tenant_id, object_key),
    FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions(tenant_id, session_id)
);

CREATE TABLE screening.ingest_problems (
    ingest_problem_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    session_id uuid NOT NULL,
    segment_index integer,
    problem_type text NOT NULL CHECK (problem_type IN (
        'CONTENT_CONFLICT', 'DIGEST_MISMATCH', 'SIZE_MISMATCH', 'MISSING_SEGMENT',
        'MANIFEST_CONFLICT', 'SCHEMA_UNSUPPORTED', 'AUTHORIZATION_INVALID', 'OBJECT_STORE_FAILURE'
    )),
    safe_evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL CHECK (status IN ('OPEN', 'RESOLVED', 'IGNORED')),
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    UNIQUE (tenant_id, ingest_problem_id),
    FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions(tenant_id, session_id)
);

CREATE TABLE ops.idempotency_keys (
    idempotency_record_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    scope text NOT NULL,
    idempotency_key text NOT NULL,
    request_sha256 text NOT NULL CHECK (request_sha256 ~ '^[0-9a-f]{64}$'),
    response_status integer NOT NULL CHECK (response_status BETWEEN 200 AND 299),
    response_json jsonb NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    UNIQUE (tenant_id, idempotency_record_id),
    UNIQUE (tenant_id, scope, idempotency_key)
);

CREATE TABLE ops.outbox_events (
    event_id uuid PRIMARY KEY,
    event_type text NOT NULL,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    aggregate_type text NOT NULL,
    aggregate_id uuid NOT NULL,
    aggregate_version bigint NOT NULL CHECK (aggregate_version > 0),
    correlation_id uuid,
    causation_id uuid,
    payload jsonb NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, event_id),
    UNIQUE (tenant_id, event_type, aggregate_type, aggregate_id, aggregate_version)
);

COMMENT ON TABLE ops.outbox_events IS
'Transactional outbox. Formal analysis starts only from a committed session.ingested.v1 event.';

CREATE INDEX ix_outbox_unpublished
ON ops.outbox_events(next_attempt_at, occurred_at)
WHERE published_at IS NULL;

CREATE TABLE ops.audit_logs (
    audit_log_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_type text NOT NULL,
    actor_id uuid,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id uuid,
    correlation_id uuid,
    outcome text NOT NULL CHECK (outcome IN ('ALLOWED', 'DENIED', 'FAILED')),
    safe_context jsonb NOT NULL DEFAULT '{}'::jsonb,
    UNIQUE (tenant_id, audit_log_id)
);

CREATE INDEX ix_audit_logs_tenant_time
ON ops.audit_logs(tenant_id, occurred_at DESC);

CREATE TABLE ops.retention_policies (
    retention_policy_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    data_category text NOT NULL,
    policy_version text NOT NULL,
    legal_basis text NOT NULL,
    retention_days integer CHECK (retention_days > 0),
    effective_at timestamptz NOT NULL,
    superseded_at timestamptz,
    approved_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, retention_policy_id),
    UNIQUE (tenant_id, data_category, policy_version)
);

CREATE TABLE ops.data_disposition_jobs (
    data_disposition_job_id uuid PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    retention_policy_id uuid NOT NULL,
    subject_uuid uuid,
    action text NOT NULL CHECK (action IN ('RESTRICT', 'ANONYMIZE', 'DELETE')),
    status text NOT NULL CHECK (status IN ('PLANNED', 'RUNNING', 'SUCCEEDED', 'FAILED')),
    evidence_json jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz,
    UNIQUE (tenant_id, data_disposition_job_id),
    FOREIGN KEY (tenant_id, retention_policy_id) REFERENCES ops.retention_policies(tenant_id, retention_policy_id),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid)
);

ALTER TABLE iam.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.tenants FORCE ROW LEVEL SECURITY;
ALTER TABLE iam.sites ENABLE ROW LEVEL SECURITY;
ALTER TABLE iam.sites FORCE ROW LEVEL SECURITY;
ALTER TABLE device.terminals ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.terminals FORCE ROW LEVEL SECURITY;
ALTER TABLE device.devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.devices FORCE ROW LEVEL SECURITY;
ALTER TABLE device.terminal_device_bindings ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.terminal_device_bindings FORCE ROW LEVEL SECURITY;
ALTER TABLE device.enrollment_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.enrollment_codes FORCE ROW LEVEL SECURITY;
ALTER TABLE device.terminal_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.terminal_credentials FORCE ROW LEVEL SECURITY;
ALTER TABLE device.terminal_heartbeats ENABLE ROW LEVEL SECURITY;
ALTER TABLE device.terminal_heartbeats FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.subjects ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.subjects FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.external_identifiers ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.external_identifiers FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.identity_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.identity_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.analysis_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.analysis_profiles FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.consents ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.consents FORCE ROW LEVEL SECURITY;
ALTER TABLE screening.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening.sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE screening.session_segments ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening.session_segments FORCE ROW LEVEL SECURITY;
ALTER TABLE screening.session_manifests ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening.session_manifests FORCE ROW LEVEL SECURITY;
ALTER TABLE screening.ingest_problems ENABLE ROW LEVEL SECURITY;
ALTER TABLE screening.ingest_problems FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.idempotency_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.idempotency_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.outbox_events FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.audit_logs FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.retention_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.retention_policies FORCE ROW LEVEL SECURITY;
ALTER TABLE ops.data_disposition_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE ops.data_disposition_jobs FORCE ROW LEVEL SECURITY;

DO $policies$
DECLARE
    table_name text;
BEGIN
    FOREACH table_name IN ARRAY ARRAY[
        'iam.tenants',
        'iam.sites',
        'device.terminals',
        'device.devices',
        'device.terminal_device_bindings',
        'device.enrollment_codes',
        'device.terminal_credentials',
        'device.terminal_heartbeats',
        'subject.subjects',
        'subject.external_identifiers',
        'subject.identity_profiles',
        'subject.analysis_profiles',
        'subject.consents',
        'screening.sessions',
        'screening.session_segments',
        'screening.session_manifests',
        'screening.ingest_problems',
        'ops.idempotency_keys',
        'ops.outbox_events',
        'ops.audit_logs',
        'ops.retention_policies',
        'ops.data_disposition_jobs'
    ]
    LOOP
        EXECUTE format(
            'CREATE POLICY tenant_isolation ON %s USING (tenant_id = ops.current_tenant_id()) WITH CHECK (tenant_id = ops.current_tenant_id())',
            table_name
        );
    END LOOP;
END
$policies$;

COMMIT;
