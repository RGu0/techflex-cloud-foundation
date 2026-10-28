BEGIN;

ALTER TABLE screening.upload_migration_permits
    ADD COLUMN original_envelope_sha256 text
        CHECK (original_envelope_sha256 IS NULL OR original_envelope_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN original_subject_uuid uuid,
    ADD COLUMN final_subject_uuid uuid,
    ADD COLUMN consent_record_id uuid,
    ADD COLUMN consent_sha256 text
        CHECK (consent_sha256 IS NULL OR consent_sha256 ~ '^[0-9a-f]{64}$'),
    ADD COLUMN reconciliation_case_id uuid;

ALTER TABLE screening.upload_migration_permits
    ADD CONSTRAINT upload_migration_permits_recovery_case_fk
        FOREIGN KEY (tenant_id, reconciliation_case_id)
        REFERENCES ops.identity_recovery_cases(tenant_id, case_id),
    ADD CONSTRAINT upload_migration_permits_recovery_binding_check
        CHECK (reconciliation_case_id IS NULL OR (
            original_envelope_sha256 IS NOT NULL
            AND original_subject_uuid IS NOT NULL
            AND final_subject_uuid IS NOT NULL
            AND consent_record_id IS NOT NULL
            AND consent_sha256 IS NOT NULL
        ));

-- New permits always carry final identity and consent bindings. The columns
-- remain nullable so already-issued permits retain their historical meaning.
ALTER TABLE screening.upload_migration_permits
    ADD CONSTRAINT upload_migration_permits_final_binding_check
        CHECK ((final_subject_uuid IS NULL AND consent_record_id IS NULL AND consent_sha256 IS NULL)
            OR (final_subject_uuid IS NOT NULL AND consent_record_id IS NOT NULL AND consent_sha256 IS NOT NULL));

COMMIT;
