BEGIN;

ALTER TABLE screening.sessions
ADD COLUMN expected_manifest_sha256 text
    CHECK (expected_manifest_sha256 IS NULL OR expected_manifest_sha256 ~ '^[0-9a-f]{64}$');

COMMIT;
