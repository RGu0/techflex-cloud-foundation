BEGIN;

-- CP-06 completion receipt facts (RAY-407): a completed manifest records the
-- eligibility decision, the policy version that produced it, the completion
-- timestamp, and the idempotency key, so the canonical digest of the
-- completion receipt is independently re-derivable.  Completions from before
-- this contract are backfilled from verified_at and marked as not
-- re-derivable rather than inventing an eligibility decision after the fact.
ALTER TABLE screening.session_manifests
    ADD COLUMN IF NOT EXISTS eligibility_reason text,
    ADD COLUMN IF NOT EXISTS eligibility_policy_version text,
    ADD COLUMN IF NOT EXISTS completed_at timestamptz,
    ADD COLUMN IF NOT EXISTS idempotency_key text;

UPDATE screening.session_manifests
SET completed_at = verified_at,
    eligibility_reason = 'completed before receipt fields existed; not re-derivable',
    eligibility_policy_version = 'pre-receipt-contract/0',
    idempotency_key = ''
WHERE verification_status = 'VERIFIED' AND completed_at IS NULL;

COMMIT;
