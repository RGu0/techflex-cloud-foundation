BEGIN;

ALTER TABLE device.license_entitlements
    DROP CONSTRAINT IF EXISTS license_entitlements_document_state_check;

DO $migration$
DECLARE
    legacy_constraint_name text;
BEGIN
    SELECT constraint_row.conname
      INTO legacy_constraint_name
      FROM pg_constraint AS constraint_row
     WHERE constraint_row.conrelid = 'device.license_entitlements'::regclass
       AND constraint_row.contype = 'c'
       AND pg_get_constraintdef(constraint_row.oid) LIKE '%PENDING_ACTIVATION%'
       AND pg_get_constraintdef(constraint_row.oid) LIKE '%document_json%'
     LIMIT 1;

    IF legacy_constraint_name IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE device.license_entitlements DROP CONSTRAINT %I',
            legacy_constraint_name
        );
    END IF;
END
$migration$;

ALTER TABLE device.license_entitlements
    ADD CONSTRAINT license_entitlements_document_state_check
    CHECK (
        status = 'REVOKED'
        OR ((status = 'PENDING_ACTIVATION') = (document_json IS NULL))
    );

COMMIT;
