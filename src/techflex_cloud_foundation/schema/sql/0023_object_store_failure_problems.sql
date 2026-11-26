BEGIN;

-- RAY-1028: an object store failure while ingesting is recorded as one OPEN
-- OBJECT_STORE_FAILURE problem per session and segment (a NULL segment is the
-- manifest).  A repeat failure refreshes it and a later success resolves it,
-- so the tenant role may update exactly those columns.  Row level security
-- already confines the role to its own tenant.  Both statements are safe to
-- run again.
GRANT UPDATE (last_seen_at, safe_evidence, status, resolved_at)
    ON screening.ingest_problems TO ffp_tenant_app;

CREATE UNIQUE INDEX IF NOT EXISTS ingest_problems_open_object_store_failure
    ON screening.ingest_problems (tenant_id, session_id, (COALESCE(segment_index, -1)))
    WHERE problem_type = 'OBJECT_STORE_FAILURE' AND status = 'OPEN';

COMMIT;
