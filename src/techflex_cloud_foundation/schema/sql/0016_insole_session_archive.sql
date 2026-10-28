BEGIN;

-- RAY-825 R1: insole-session-archive/1 parts and insole-session-manifest/1
-- manifests have no frame range, monotonic clock, compression, cipher or frame
-- total. Those columns become nullable, and a shape check per schema keeps
-- every other schema (raw-segment/1 rows included) exactly as strict as
-- before. Existing rows all satisfy the checks. Re-running is safe: every
-- statement converges.

ALTER TABLE screening.session_segments
    ALTER COLUMN start_frame_index DROP NOT NULL,
    ALTER COLUMN frame_count DROP NOT NULL,
    ALTER COLUMN start_monotonic_ns DROP NOT NULL,
    ALTER COLUMN end_monotonic_ns DROP NOT NULL,
    ALTER COLUMN compression DROP NOT NULL,
    ALTER COLUMN cipher DROP NOT NULL;

DO $$
BEGIN
IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'session_segments_shape_by_schema'
      AND conrelid = 'screening.session_segments'::regclass
) THEN
ALTER TABLE screening.session_segments
    ADD CONSTRAINT session_segments_shape_by_schema CHECK (
        CASE WHEN payload_schema_version = 'insole-session-archive/1' THEN
            start_frame_index IS NULL AND frame_count IS NULL
            AND start_monotonic_ns IS NULL AND end_monotonic_ns IS NULL
            AND compression IS NULL AND cipher IS NULL
        ELSE
            start_frame_index IS NOT NULL AND frame_count IS NOT NULL
            AND start_monotonic_ns IS NOT NULL AND end_monotonic_ns IS NOT NULL
            AND compression IS NOT NULL AND cipher IS NOT NULL
        END
    );
END IF;
END
$$;

ALTER TABLE screening.session_manifests
    ALTER COLUMN total_frames DROP NOT NULL;

DO $$
BEGIN
IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'session_manifests_shape_by_schema'
      AND conrelid = 'screening.session_manifests'::regclass
) THEN
ALTER TABLE screening.session_manifests
    ADD CONSTRAINT session_manifests_shape_by_schema CHECK (
        CASE WHEN schema_version = 'insole-session-manifest/1'
            THEN total_frames IS NULL
            ELSE total_frames IS NOT NULL
        END
    );
END IF;
END
$$;

COMMIT;
