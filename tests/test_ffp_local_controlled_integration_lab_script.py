from __future__ import annotations

from importlib.util import module_from_spec, spec_from_file_location
import os
from pathlib import Path

import pytest

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPOSITORY_ROOT / "scripts" / "local_controlled_integration_lab.py"


def _module():
    specification = spec_from_file_location("local_controlled_integration_lab", SCRIPT_PATH)
    assert specification is not None and specification.loader is not None
    module = module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def test_operator_entrypoint_is_committed() -> None:
    assert SCRIPT_PATH.is_file()


def test_preflight_rejects_non_loopback_postgres_administration_dsn(tmp_path: Path) -> None:
    module = _module()

    with pytest.raises(ValueError, match="loopback"):
        module.preflight(
            tmp_path / "local-lab", "127.0.0.1", "postgresql://operator@db.example.test/lab"
        )


def test_parser_requires_local_postgres_administration_dsn() -> None:
    module = _module()

    parsed = module.build_parser().parse_args(
        ["preflight", "--runtime-root", "C:/local-lab", "--administration-dsn", "postgresql://operator@127.0.0.1/lab"]
    )

    assert parsed.administration_dsn == "postgresql://operator@127.0.0.1/lab"


def test_parser_exposes_repeatable_local_exercise_phase() -> None:
    module = _module()

    parsed = module.build_parser().parse_args(
        ["exercise", "--runtime-root", "C:/local-lab", "--administration-dsn", "postgresql://operator@127.0.0.1/lab"]
    )

    assert parsed.phase == "exercise"


def test_bootstrap_derives_four_distinct_local_service_dsns() -> None:
    module = _module()

    dsns = module.service_dsns("postgresql://ffp_ray428_lab_admin@127.0.0.1:5442/ffp_ray428_lab")

    assert set(dsns) == {"migration", "tenant", "activation", "platform"}
    assert len(set(dsns.values())) == 4
    assert all(value.endswith("@127.0.0.1:5442/ffp_ray428_lab") for value in dsns.values())


def test_bootstrap_uses_inheriting_non_superuser_service_roles() -> None:
    source = SCRIPT_PATH.read_text(encoding="utf-8")

    assert "NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS" in source
    assert "ALTER ROLE {role} INHERIT" in source
    assert "WITH INHERIT TRUE" in source


def test_bootstrap_applies_to_opt_in_local_postgres() -> None:
    dsn = os.environ.get("FFP_LOCAL_LAB_LIVE_DSN")
    if dsn is None:
        pytest.skip("local fault-lab PostgreSQL is not enabled")

    dsns = _module().bootstrap(dsn)

    assert len(set(dsns.values())) == 4


def test_tls_material_is_created_only_inside_private_lab_root(tmp_path: Path) -> None:
    module = _module()
    paths = module.preflight(
        tmp_path / "local-lab", "127.0.0.1", "postgresql://operator@127.0.0.1/lab"
    )

    certificate, private_key = module.ensure_tls_material(paths, "127.0.0.1")

    assert certificate.is_file()
    assert private_key.is_file()
    assert certificate.is_relative_to(paths.secrets)
    assert private_key.is_relative_to(paths.secrets)
