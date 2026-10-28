from __future__ import annotations

from pathlib import Path
import re
import unittest

MIGRATION = Path(__file__).parents[1] / "src" / "techflex_cloud_foundation" / "schema" / "sql" / "0001_p3_cloud_platform.sql"
CAPTURE_GRANTS = Path(__file__).parents[1] / "src" / "techflex_cloud_foundation" / "schema" / "sql" / "0009_capture_grants.sql"
HOLD_MIGRATION = Path(__file__).parents[1] / "src" / "techflex_cloud_foundation" / "schema" / "sql" / "0009_unverified_session_holds.sql"
COPY_MIGRATION = Path(__file__).parents[1] / "src" / "techflex_cloud_foundation" / "schema" / "sql" / "0010_local_basic_report_copies.sql"
RECOVERY_PERMIT_MIGRATION = Path(__file__).parents[1] / "src" / "techflex_cloud_foundation" / "schema" / "sql" / "0014_recovery_bound_migration_permits.sql"


class MigrationContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sql = MIGRATION.read_text(encoding="utf-8")

    def test_declares_owned_schemas_and_security_domains(self) -> None:
        for schema in ("iam", "device", "subject", "screening", "ops"):
            self.assertIn(f"CREATE SCHEMA IF NOT EXISTS {schema};", self.sql)

    def test_declares_ingestion_unique_keys_and_approved_status(self) -> None:
        self.assertRegex(
            self.sql,
            re.compile(r"UNIQUE\s*\(tenant_id,\s*session_id,\s*segment_index\)", re.I),
        )
        self.assertIn("'INGESTED'", self.sql)
        self.assertIn("manifest_sha256", self.sql)

    def test_tenant_tables_enable_and_force_rls(self) -> None:
        tenant_tables = (
            "iam.tenants",
            "iam.sites",
            "device.terminals",
            "device.devices",
            "device.terminal_device_bindings",
            "device.terminal_heartbeats",
            "subject.subjects",
            "subject.external_identifiers",
            "subject.analysis_profiles",
            "subject.consents",
            "screening.sessions",
            "screening.session_segments",
            "screening.session_manifests",
            "screening.ingest_problems",
            "ops.idempotency_keys",
            "ops.outbox_events",
            "ops.audit_logs",
        )
        for table in tenant_tables:
            self.assertIn(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;", self.sql)
            self.assertIn(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;", self.sql)
        self.assertIn("current_setting('app.tenant_id', true)::uuid", self.sql)

    def test_outbox_and_idempotency_are_first_class(self) -> None:
        self.assertIn("CREATE TABLE ops.idempotency_keys", self.sql)
        self.assertIn("request_sha256", self.sql)
        self.assertIn("CREATE TABLE ops.outbox_events", self.sql)
        self.assertIn("session.ingested.v1", self.sql)
        self.assertIn("WHERE published_at IS NULL", self.sql)

    def test_enrollment_code_can_prebind_an_approved_device(self) -> None:
        enrollment_table = self.sql.split(
            "CREATE TABLE device.enrollment_codes",
            maxsplit=1,
        )[1].split(");", maxsplit=1)[0]

        self.assertIn("device_id uuid", enrollment_table)
        self.assertIn(
            "FOREIGN KEY (tenant_id, device_id) REFERENCES device.devices(tenant_id, device_id)",
            enrollment_table,
        )

    def test_raw_identity_and_audit_records_are_separate_tables(self) -> None:
        self.assertIn("CREATE TABLE subject.identity_profiles", self.sql)
        self.assertIn("CREATE TABLE screening.session_segments", self.sql)
        self.assertIn("CREATE TABLE ops.audit_logs", self.sql)
        self.assertNotIn("external_id_plaintext", self.sql)

    def test_capture_grants_do_not_store_reusable_credential_or_raw_data(self) -> None:
        sql = CAPTURE_GRANTS.read_text(encoding="utf-8")
        self.assertIn("token_sha256 bytea", sql)
        for forbidden in ("token_plaintext", "license_document_json", "raw_segment", "consent_details"):
            self.assertNotIn(forbidden, sql)
        for required in (
            "account_id uuid NOT NULL", "license_id uuid NOT NULL",
            "hardware_id uuid NOT NULL", "installation_id uuid NOT NULL",
            "consumed_request_sha256 text", "expected_manifest_sha256 text",
            "approver_id uuid NOT NULL", "approval_reason text NOT NULL",
            "evidence_reference text NOT NULL",
        ):
            self.assertIn(required, sql)

    def test_hold_tables_are_tenant_scoped_and_append_only(self) -> None:
        sql = HOLD_MIGRATION.read_text(encoding="utf-8")
        for table in ("ops.session_holds", "ops.session_hold_events", "ops.session_hold_idempotency"):
            self.assertIn(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;", sql)
            self.assertIn(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;", sql)
        self.assertIn("UNIQUE (tenant_id, session_id)", sql)
        self.assertIn("tenant_id = ops.current_tenant_id()", sql)
        self.assertIn("request_sha256", sql)
        self.assertIn("FOREIGN KEY (tenant_id, session_id) REFERENCES screening.sessions", sql)
        self.assertIn("CREATE TABLE ops.session_hold_dispositions", sql)
        self.assertIn("GRANT SELECT, INSERT ON ops.session_hold_dispositions TO ffp_platform_app", sql)

    def test_local_basic_copy_is_separate_and_rls_guarded(self) -> None:
        sql = COPY_MIGRATION.read_text(encoding="utf-8")
        self.assertNotIn("TO ffp_platform_app", sql)
        self.assertIn("CREATE TABLE reporting.local_basic_report_copies", sql)
        self.assertIn("PRIMARY KEY (tenant_id, session_id)", sql)
        self.assertIn("UNIQUE (tenant_id, report_id, version)", sql)
        self.assertIn("ENABLE ROW LEVEL SECURITY", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("tenant_id = ops.current_tenant_id()", sql)
        self.assertIn("GRANT USAGE ON SCHEMA reporting TO ffp_seed_backup;", sql)
        self.assertIn(
            "GRANT SELECT ON reporting.local_basic_report_copies TO ffp_seed_backup;", sql,
        )
        self.assertNotIn("ALTER TABLE screening.sessions", sql)


if __name__ == "__main__":
    unittest.main()


class IdentityRecoveryMigrationContractTests(unittest.TestCase):
    def test_case_table_is_tenant_isolated_and_has_no_plaintext_identity(self) -> None:
        sql = (MIGRATION.parent / "0011_controlled_identity_recovery.sql").read_text(encoding="utf-8")
        self.assertIn("UNIQUE (tenant_id, session_id)", sql)
        self.assertIn("UNIQUE (tenant_id, key_sha256)", sql)
        self.assertIn("FORCE ROW LEVEL SECURITY", sql)
        self.assertIn("ops.current_tenant_id()", sql)
        self.assertIn("GRANT SELECT (tenant_id, subject_uuid, status)", sql)
        self.assertIn(
            "GRANT SELECT (tenant_id, subject_uuid, external_identifier_id, "
            "issuer, id_type, normalized_hmac, status)", sql,
        )
        self.assertIn("identifier_hmac bytea NOT NULL", sql)
        self.assertIn("CREATE TABLE ops.identity_recovery_receipts", sql)
        self.assertIn("CREATE TABLE ops.identity_recovery_registrations", sql)
        self.assertIn("ALTER TABLE ops.identity_recovery_registrations FORCE ROW LEVEL SECURITY", sql)
        self.assertNotIn("display_name text", sql)
        self.assertNotIn("contact text", sql)

    def test_migration_permit_binds_reconciliation_and_final_consent(self) -> None:
        sql = RECOVERY_PERMIT_MIGRATION.read_text(encoding="utf-8")
        for column in (
            "original_envelope_sha256", "original_subject_uuid", "final_subject_uuid",
            "consent_record_id", "consent_sha256", "reconciliation_case_id",
        ):
            self.assertIn(column, sql)
        self.assertIn("REFERENCES ops.identity_recovery_cases(tenant_id, case_id)", sql)
