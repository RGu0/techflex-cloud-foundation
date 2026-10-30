from pathlib import Path

MIGRATION = (
    Path(__file__).parents[1] / "src/techflex_cloud_foundation/schema/sql/0006_inventory_activation_pairing.sql"
)
POSTGRES_REPOSITORY = Path(__file__).parents[1] / "src/techflex_cloud_foundation/server/access_control/postgres.py"
ROLE_GRANTS = (
    Path(__file__).parents[1]
    / "deploy"
    / "aliyun"
    / "seed"
    / "postgresql-role-grants.sql"
)


def test_inventory_migration_preserves_independent_pools_until_first_activation() -> None:
    sql = MIGRATION.read_text(encoding="utf-8")

    assert sql.startswith("BEGIN;")
    assert sql.rstrip().endswith("COMMIT;")
    assert "ADD COLUMN activation_binding_mode" in sql
    assert "AT_FIRST_ACTIVATION" in sql
    assert "Never infer or pre-bind a device-to-code pair" in sql
    assert "device_inventory_id uuid REFERENCES" not in sql
    assert "GRANT SELECT, UPDATE ON sales.device_inventory, sales.license_inventory TO ffp_activation_app" in sql


def test_inventory_activation_sets_tenant_context_before_installation_lookup() -> None:
    text = POSTGRES_REPOSITORY.read_text(encoding="utf-8")
    activation = text[text.index("async def activate_inventory_atomically") :]

    assert activation.index("SELECT set_config('app.tenant_id'") < activation.index(
        "SELECT EXISTS (SELECT 1 FROM device.client_installations"
    )


def test_inventory_activation_can_materialize_new_account_and_license_rows() -> None:
    required_grant = (
        "GRANT INSERT ON iam.account_login_directory, device.license_entitlements "
        "TO ffp_activation_app;"
    )

    assert required_grant in MIGRATION.read_text(encoding="utf-8")
    assert required_grant in ROLE_GRANTS.read_text(encoding="utf-8")
