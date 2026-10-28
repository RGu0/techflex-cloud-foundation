from __future__ import annotations

from pathlib import Path
import unittest

MIGRATION = Path(__file__).parents[1] / "src" / "techflex_cloud_foundation" / "schema" / "sql" / "0002_p5_device_operations.sql"


class OperationsMigrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sql = MIGRATION.read_text(encoding="utf-8")

    def test_declares_iam_license_upgrade_and_support_tables(self) -> None:
        for table in (
            "iam.users",
            "iam.roles",
            "iam.user_role_bindings",
            "device.licenses",
            "device.upgrade_policies",
            "ops.support_access_grants",
        ):
            self.assertIn(f"CREATE TABLE {table}", self.sql)
            self.assertIn(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY", self.sql)
            self.assertIn(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY", self.sql)

    def test_license_versions_and_access_categories_are_constrained(self) -> None:
        self.assertIn("UNIQUE (tenant_id, license_id, license_version)", self.sql)
        self.assertIn("RAW_DATA", self.sql)
        self.assertIn("IDENTITY", self.sql)
        self.assertIn("LOGS", self.sql)
        self.assertIn("DIAGNOSTICS", self.sql)

    def test_operations_schema_has_no_public_report_link(self) -> None:
        self.assertNotIn("public_report", self.sql.lower())
        self.assertNotIn("permanent_url", self.sql.lower())


if __name__ == "__main__":
    unittest.main()
