BEGIN;

ALTER TABLE screening.sessions
    ADD COLUMN IF NOT EXISTS input_format text NOT NULL DEFAULT 'legacy',
    ADD COLUMN IF NOT EXISTS request_document text,
    ADD COLUMN IF NOT EXISTS request_sha256 text,
    ALTER COLUMN started_at DROP NOT NULL,
    ALTER COLUMN device_id DROP NOT NULL,
    ALTER COLUMN subject_uuid DROP NOT NULL,
    ALTER COLUMN consent_record_id DROP NOT NULL,
    ALTER COLUMN test_protocol_id DROP NOT NULL,
    ALTER COLUMN test_protocol_version DROP NOT NULL,
    ALTER COLUMN protocol_profile_version DROP NOT NULL,
    ALTER COLUMN calibration_version DROP NOT NULL;

ALTER TABLE screening.sessions DROP CONSTRAINT IF EXISTS sessions_input_shape;
ALTER TABLE screening.sessions ADD CONSTRAINT sessions_input_shape CHECK (
    (input_format = 'legacy' AND started_at IS NOT NULL
        AND device_id IS NOT NULL AND subject_uuid IS NOT NULL
        AND consent_record_id IS NOT NULL AND test_protocol_id IS NOT NULL
        AND test_protocol_version IS NOT NULL AND protocol_profile_version IS NOT NULL
        AND calibration_version IS NOT NULL)
    OR (input_format = 'registry' AND payload_schema_version <> 'raw-segment/1'
        AND device_id IS NULL AND subject_uuid IS NULL AND consent_record_id IS NULL
        AND test_protocol_id IS NULL AND test_protocol_version IS NULL
        AND protocol_profile_version IS NULL AND calibration_version IS NULL
        AND request_document IS NOT NULL
        AND jsonb_typeof(request_document::jsonb) = 'object'
        AND request_sha256 ~ '^[0-9a-f]{64}$' AND request_sha256 IS NOT NULL)
);

ALTER TABLE screening.session_segments
    ADD COLUMN IF NOT EXISTS segment_profile text,
    ADD COLUMN IF NOT EXISTS metadata_document text;
ALTER TABLE screening.session_manifests ADD COLUMN IF NOT EXISTS segment_profile text;

-- Existing writers keep their raw/insole defaults; new schemas must supply a
-- known profile explicitly. No future product identifier belongs in this CHECK.
ALTER TABLE screening.session_segments DROP CONSTRAINT IF EXISTS session_segments_shape_by_schema;
ALTER TABLE screening.session_segments ADD CONSTRAINT session_segments_shape_by_schema CHECK (
    (payload_schema_version <> 'raw-segment/1' OR segment_profile IS NULL
        OR segment_profile = 'frame-segment')
    AND (payload_schema_version <> 'insole-session-archive/1' OR segment_profile IS NULL
        OR segment_profile = 'byte-segment')
    AND
    CASE COALESCE(segment_profile,
        CASE WHEN payload_schema_version = 'insole-session-archive/1'
             THEN 'byte-segment' WHEN payload_schema_version = 'raw-segment/1'
             THEN 'frame-segment' ELSE 'unknown' END)
    WHEN 'byte-segment' THEN
        start_frame_index IS NULL AND frame_count IS NULL
        AND start_monotonic_ns IS NULL AND end_monotonic_ns IS NULL
        AND compression IS NULL AND cipher IS NULL
    WHEN 'frame-segment' THEN
        start_frame_index IS NOT NULL AND frame_count IS NOT NULL
        AND start_monotonic_ns IS NOT NULL AND end_monotonic_ns IS NOT NULL
        AND compression IS NOT NULL AND cipher IS NOT NULL
    ELSE false END
);
ALTER TABLE screening.session_manifests DROP CONSTRAINT IF EXISTS session_manifests_shape_by_schema;
ALTER TABLE screening.session_manifests ADD CONSTRAINT session_manifests_shape_by_schema CHECK (
    (schema_version <> 'session-manifest/1' OR segment_profile IS NULL
        OR segment_profile = 'frame-segment')
    AND (schema_version <> 'insole-session-manifest/1' OR segment_profile IS NULL
        OR segment_profile = 'byte-segment')
    AND
    CASE COALESCE(segment_profile,
        CASE WHEN schema_version = 'insole-session-manifest/1'
             THEN 'byte-segment' WHEN schema_version = 'session-manifest/1'
             THEN 'frame-segment' ELSE 'unknown' END)
    WHEN 'byte-segment' THEN total_frames IS NULL
    WHEN 'frame-segment' THEN total_frames IS NOT NULL
    ELSE false END
);

COMMIT;
