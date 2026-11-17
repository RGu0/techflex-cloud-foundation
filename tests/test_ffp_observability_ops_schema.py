from pathlib import Path
import re
import unittest

OPS = (
    Path(__file__).resolve().parents[1]
    / "src/techflex_cloud_foundation/server/observability/migrations/0001_ops.sql"
)


def normalized(path: Path) -> str:
    return re.sub(r"\s+", " ", path.read_text(encoding="utf-8")).lower()


class OpsMigrationContractTests(unittest.TestCase):
    def test_ops_migration_does_not_modify_ingestion_tables(self) -> None:
        self.assertTrue(OPS.exists(), OPS)
        sql = normalized(OPS)
        self.assertNotIn("create table screening.", sql)
        self.assertNotIn("alter table screening.", sql)
        self.assertNotIn("create table device.", sql)

    def test_ops_migration_covers_outbox_telemetry_alerts_diagnostics_and_audit(self) -> None:
        sql = normalized(OPS)

        for table in (
            "outbox_events",
            "telemetry_batches",
            "alert_incidents",
            "diagnostic_packages",
            "support_audit_logs",
        ):
            self.assertIn(f"create table ops.{table}", sql)
        self.assertIn("unique (tenant_id, batch_id)", sql)
        self.assertIn("plaintext_sha256", sql)
        self.assertIn("ciphertext_sha256", sql)
        self.assertIn("runbook", sql)
        self.assertIn("enable row level security", sql)


if __name__ == "__main__":
    unittest.main()
