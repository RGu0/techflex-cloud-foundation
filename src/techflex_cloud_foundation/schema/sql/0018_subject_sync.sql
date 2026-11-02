BEGIN;

-- RAY-907 R1: institutional subject sync. Every change to a subject, its
-- identity, analysis profile, institution number, consents or tag set gives
-- the subject a new per-tenant revision; the incremental download pages by
-- that revision. Revisions are assigned by trigger from a counter row that
-- the assigning transaction keeps locked until it commits, so commit order
-- equals revision order and a reader that has seen revision N has also seen
-- every lower one. Existing rows are backfilled in creation order. Subjects
-- are never deleted; the existing columns, constraints and grants are kept.

CREATE TABLE subject.subject_revision_counters (
    tenant_id uuid PRIMARY KEY REFERENCES iam.tenants(tenant_id) ON DELETE CASCADE,
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0)
);

ALTER TABLE subject.subjects ADD COLUMN revision bigint;

UPDATE subject.subjects s
SET revision = ordered.revision
FROM (
    SELECT subject_uuid,
           row_number() OVER (PARTITION BY tenant_id ORDER BY created_at, subject_uuid)
               AS revision
    FROM subject.subjects
) ordered
WHERE s.subject_uuid = ordered.subject_uuid;

ALTER TABLE subject.subjects
    ALTER COLUMN revision SET NOT NULL,
    ADD CONSTRAINT subjects_revision_positive CHECK (revision > 0);

-- Unique per tenant, as a partial index on purpose: a column of a plain
-- unique index is a key column, so every revision bump would conflict with
-- the FOR KEY SHARE locks that concurrent consent and session inserts take on
-- the subject through their foreign keys, and two such writers would
-- deadlock. The predicate is always true (CHECK above); queries that should
-- use the index repeat it.
CREATE UNIQUE INDEX ux_subjects_tenant_revision
ON subject.subjects (tenant_id, revision)
WHERE revision > 0;

INSERT INTO subject.subject_revision_counters (tenant_id, last_revision)
SELECT tenant_id, max(revision) FROM subject.subjects GROUP BY tenant_id;

-- D6: the exact-name lookup key. Rows written before this migration stay
-- NULL until the subject's identity is next written; no key-holding backfill.
ALTER TABLE subject.identity_profiles
    ADD COLUMN name_lookup_hmac bytea CHECK (octet_length(name_lookup_hmac) = 32);

CREATE INDEX ix_identity_profiles_name_lookup
ON subject.identity_profiles (tenant_id, name_lookup_hmac)
WHERE name_lookup_hmac IS NOT NULL;

-- Tag dictionary with its own revision sequence. Tags are never deleted in
-- R1; rename, retire and merge are RAY-914.
CREATE TABLE subject.tag_revision_counters (
    tenant_id uuid PRIMARY KEY REFERENCES iam.tenants(tenant_id) ON DELETE CASCADE,
    last_revision bigint NOT NULL DEFAULT 0 CHECK (last_revision >= 0)
);

CREATE TABLE subject.tags (
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    tag_id uuid NOT NULL,
    name text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 32),
    -- NFKC, trimmed and case folded; one tag per normalized name.
    name_key text NOT NULL CHECK (char_length(name_key) >= 1),
    created_by uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revision bigint NOT NULL CHECK (revision > 0),
    PRIMARY KEY (tenant_id, tag_id),
    UNIQUE (tenant_id, name_key),
    UNIQUE (tenant_id, revision)
);

CREATE TABLE subject.subject_tags (
    tenant_id uuid NOT NULL REFERENCES iam.tenants(tenant_id),
    subject_uuid uuid NOT NULL,
    tag_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, subject_uuid, tag_id),
    FOREIGN KEY (tenant_id, subject_uuid) REFERENCES subject.subjects(tenant_id, subject_uuid),
    FOREIGN KEY (tenant_id, tag_id) REFERENCES subject.tags(tenant_id, tag_id)
);

CREATE INDEX ix_subject_tags_tag ON subject.subject_tags (tenant_id, tag_id);

ALTER TABLE subject.subject_revision_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.subject_revision_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.tag_revision_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.tag_revision_counters FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.tags FORCE ROW LEVEL SECURITY;
ALTER TABLE subject.subject_tags ENABLE ROW LEVEL SECURITY;
ALTER TABLE subject.subject_tags FORCE ROW LEVEL SECURITY;

CREATE POLICY subject_revision_counters_tenant_isolation
ON subject.subject_revision_counters
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY subject_tag_revision_counters_tenant_isolation
ON subject.tag_revision_counters
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY subject_tags_tenant_isolation ON subject.tags
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());
CREATE POLICY subject_subject_tags_tenant_isolation ON subject.subject_tags
USING (tenant_id = ops.current_tenant_id())
WITH CHECK (tenant_id = ops.current_tenant_id());

-- Every insert or update of a subject takes the next revision. The UPDATE on
-- the counter row holds its lock until commit, which serializes the tenant's
-- subject writers. A client cannot choose the revision: it is overwritten.
CREATE FUNCTION subject.assign_subject_revision() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO subject.subject_revision_counters AS counter (tenant_id, last_revision)
    VALUES (NEW.tenant_id, 1)
    ON CONFLICT (tenant_id)
    DO UPDATE SET last_revision = counter.last_revision + 1
    RETURNING counter.last_revision INTO NEW.revision;
    IF TG_OP = 'UPDATE' THEN
        NEW.updated_at := now();
    END IF;
    RETURN NEW;
END
$$;

-- A change to a dependent row touches its subject, which assigns the
-- subject a new revision through the trigger above.
CREATE FUNCTION subject.touch_subject() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        UPDATE subject.subjects SET updated_at = now()
        WHERE tenant_id = OLD.tenant_id AND subject_uuid = OLD.subject_uuid;
    ELSE
        UPDATE subject.subjects SET updated_at = now()
        WHERE tenant_id = NEW.tenant_id AND subject_uuid = NEW.subject_uuid;
    END IF;
    RETURN NULL;
END
$$;

-- Created after the backfill so it keeps the creation-order revisions.
CREATE TRIGGER subjects_assign_revision
BEFORE INSERT OR UPDATE ON subject.subjects
FOR EACH ROW EXECUTE FUNCTION subject.assign_subject_revision();

CREATE TRIGGER identity_profiles_touch_subject
AFTER INSERT OR UPDATE OR DELETE ON subject.identity_profiles
FOR EACH ROW EXECUTE FUNCTION subject.touch_subject();
CREATE TRIGGER analysis_profiles_touch_subject
AFTER INSERT OR UPDATE OR DELETE ON subject.analysis_profiles
FOR EACH ROW EXECUTE FUNCTION subject.touch_subject();
CREATE TRIGGER external_identifiers_touch_subject
AFTER INSERT OR UPDATE OR DELETE ON subject.external_identifiers
FOR EACH ROW EXECUTE FUNCTION subject.touch_subject();
CREATE TRIGGER consents_touch_subject
AFTER INSERT OR UPDATE OR DELETE ON subject.consents
FOR EACH ROW EXECUTE FUNCTION subject.touch_subject();
CREATE TRIGGER subject_tags_touch_subject
AFTER INSERT OR UPDATE OR DELETE ON subject.subject_tags
FOR EACH ROW EXECUTE FUNCTION subject.touch_subject();

-- Same role as the existing subject tables (0003). No DELETE on tags: R1
-- never removes one; a subject's tag set is replaced row by row.
GRANT SELECT, INSERT, UPDATE ON subject.subject_revision_counters TO ffp_tenant_app;
GRANT SELECT, INSERT, UPDATE ON subject.tag_revision_counters TO ffp_tenant_app;
GRANT SELECT, INSERT ON subject.tags TO ffp_tenant_app;
GRANT SELECT, INSERT, DELETE ON subject.subject_tags TO ffp_tenant_app;

COMMIT;
