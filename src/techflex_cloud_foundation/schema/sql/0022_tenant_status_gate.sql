BEGIN;

-- RAY-963: capture-session authorisation refuses a CLOSED tenant, so the
-- tenant role needs to read the status of its own tenant row.  Row level
-- security already confines every role to the current tenant, and no other
-- column or privilege changes.
GRANT SELECT ON iam.tenants TO ffp_tenant_app;

COMMIT;
