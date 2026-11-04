BEGIN;

-- Preserve legacy measurements while storing registry documents without inventing
-- a device, subject, consent, protocol, frame count or calibration.
ALTER TABLE screening.sessions ADD COLUMN IF NOT EXISTS registered_document jsonb;
ALTER TABLE screening.sessions
    ALTER COLUMN device_id DROP NOT NULL,
    ALTER COLUMN subject_uuid DROP NOT NULL,
    ALTER COLUMN consent_record_id DROP NOT NULL,
    ALTER COLUMN test_protocol_id DROP NOT NULL,
    ALTER COLUMN test_protocol_version DROP NOT NULL,
    ALTER COLUMN protocol_profile_version DROP NOT NULL,
    ALTER COLUMN calibration_version DROP NOT NULL;
ALTER TABLE screening.sessions DROP CONSTRAINT IF EXISTS sessions_registered_shape;
ALTER TABLE screening.sessions ADD CONSTRAINT sessions_registered_shape CHECK (
    CASE WHEN registered_document IS NULL THEN
        device_id IS NOT NULL AND subject_uuid IS NOT NULL AND consent_record_id IS NOT NULL
        AND test_protocol_id IS NOT NULL AND test_protocol_version IS NOT NULL
        AND protocol_profile_version IS NOT NULL AND calibration_version IS NOT NULL
    ELSE
        payload_schema_version NOT IN ('raw-segment/1','insole-session-archive/1')
        AND device_id IS NULL AND subject_uuid IS NULL AND consent_record_id IS NULL
        AND test_protocol_id IS NULL AND test_protocol_version IS NULL
        AND protocol_profile_version IS NULL AND calibration_version IS NULL
        AND jsonb_typeof(registered_document) = 'object'
        AND ((registered_document->>'session_id')::uuid = session_id) IS TRUE
        AND ((registered_document->>'client_installation_id')::uuid = terminal_id) IS TRUE
        AND (registered_document->'versions'->>'payload_schema' = payload_schema_version) IS TRUE
    END
);

ALTER TABLE screening.session_segments ADD COLUMN IF NOT EXISTS metadata_json jsonb;
ALTER TABLE screening.session_segments DROP CONSTRAINT IF EXISTS session_segments_shape_by_schema;
ALTER TABLE screening.session_segments ADD CONSTRAINT session_segments_shape_by_schema CHECK (
    CASE WHEN metadata_json IS NOT NULL THEN
        payload_schema_version NOT IN ('raw-segment/1','insole-session-archive/1')
        AND jsonb_typeof(metadata_json) = 'object'
        AND (metadata_json->>'payload_schema_version' = payload_schema_version) IS TRUE
        AND (metadata_json->>'sha256' = sha256) IS TRUE
        AND ((metadata_json->>'segment_index')::integer = segment_index) IS TRUE
        AND ((metadata_json->>'size_bytes')::bigint = size_bytes) IS TRUE
        AND start_frame_index IS NULL AND frame_count IS NULL
        AND start_monotonic_ns IS NULL AND end_monotonic_ns IS NULL
        AND compression IS NULL AND cipher IS NULL
    WHEN payload_schema_version = 'insole-session-archive/1' THEN
        start_frame_index IS NULL AND frame_count IS NULL
        AND start_monotonic_ns IS NULL AND end_monotonic_ns IS NULL
        AND compression IS NULL AND cipher IS NULL
    ELSE
        start_frame_index IS NOT NULL AND frame_count IS NOT NULL
        AND start_monotonic_ns IS NOT NULL AND end_monotonic_ns IS NOT NULL
        AND compression IS NOT NULL AND cipher IS NOT NULL
    END
);

ALTER TABLE screening.session_manifests ADD COLUMN IF NOT EXISTS registered_manifest boolean NOT NULL DEFAULT false;
ALTER TABLE screening.session_manifests DROP CONSTRAINT IF EXISTS session_manifests_shape_by_schema;
ALTER TABLE screening.session_manifests ADD CONSTRAINT session_manifests_shape_by_schema CHECK (
    CASE WHEN registered_manifest THEN
        schema_version NOT IN ('session-manifest/1','insole-session-manifest/1')
        AND total_frames IS NULL
    WHEN schema_version = 'insole-session-manifest/1' THEN total_frames IS NULL
    ELSE total_frames IS NOT NULL END
);

COMMIT;
