BEGIN;

CREATE SCHEMA IF NOT EXISTS reporting;

CREATE TABLE reporting.local_basic_report_copies (
    tenant_id uuid NOT NULL,
    session_id uuid NOT NULL,
    report_id text NOT NULL CHECK (report_id ~ '^[A-Za-z0-9-]{1,64}$'),
    version integer NOT NULL CHECK (version = 1),
    source text NOT NULL CHECK (source = 'LOCAL_BASIC_COPY'),
    subject_uuid uuid NOT NULL,
    consent_record_id uuid NOT NULL,
    terminal_id uuid NOT NULL,
    document_json text NOT NULL
        CHECK (octet_length(document_json) <= 1048576
               AND jsonb_typeof(document_json::jsonb) = 'object'),
    document_sha256 text NOT NULL CHECK (document_sha256 ~ '^[0-9a-f]{64}$'),
    pdf_sha256 text NOT NULL CHECK (pdf_sha256 ~ '^[0-9a-f]{64}$'),
    pdf_object_key text NOT NULL,
    pdf_size_bytes integer NOT NULL CHECK (pdf_size_bytes > 0 AND pdf_size_bytes <= 8388608),
    idempotency_key_sha256 text NOT NULL CHECK (idempotency_key_sha256 ~ '^[0-9a-f]{64}$'),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, session_id),
    UNIQUE (tenant_id, report_id, version),
    UNIQUE (tenant_id, idempotency_key_sha256),
    FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions(tenant_id, session_id),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, consent_record_id) REFERENCES subject.consents(tenant_id, consent_record_id),
    FOREIGN KEY (tenant_id, terminal_id) REFERENCES device.terminals(tenant_id, terminal_id)
);

CREATE INDEX ix_local_basic_report_copies_recent
ON reporting.local_basic_report_copies (tenant_id, created_at DESC);

ALTER TABLE reporting.local_basic_report_copies ENABLE ROW LEVEL SECURITY;
ALTER TABLE reporting.local_basic_report_copies FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON reporting.local_basic_report_copies
    USING (tenant_id = ops.current_tenant_id()) WITH CHECK (tenant_id = ops.current_tenant_id());

GRANT USAGE ON SCHEMA reporting TO ffp_tenant_app;
GRANT SELECT, INSERT ON reporting.local_basic_report_copies TO ffp_tenant_app;
GRANT USAGE ON SCHEMA reporting TO ffp_seed_backup;
GRANT SELECT ON reporting.local_basic_report_copies TO ffp_seed_backup;

COMMIT;
