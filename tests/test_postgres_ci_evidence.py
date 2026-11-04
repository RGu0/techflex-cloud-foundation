"""CI evidence must fail when coverage was skipped or nothing ran."""
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("case", [
    '<testcase classname="tests.test_schema_migrations" name="upgrade"><skipped/></testcase>',
    '<testcase classname="tests.test_registry_postgres_invariants" '
    'name="rls"><skipped/></testcase>',
    '',
])
def test_missing_core_coverage_rejected(case, tmp_path):
    report = tmp_path / "results.xml"
    report.write_text(f'<testsuites><testsuite>{case}</testsuite></testsuites>')
    result = subprocess.run(
        [sys.executable, "scripts/check_postgres_ci_evidence.py", str(report)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 1
    assert "PostgreSQL CI evidence rejected" in result.stdout


def test_only_named_experiment_skip_allowed(tmp_path):
    report = tmp_path / "results.xml"
    cases = ''.join(
        f'<testcase classname="tests.{module}" name="{name}"/>' for module, name in (
            ('test_schema_migrations',
             'test_empty_database_reaches_the_end_and_records_every_step'),
            ('test_schema_migrations',
             'test_sql_ascii_database_takes_raw_utf8_jsonb_but_not_escaped_non_ascii'),
            ('test_registry_0020_upgrade',
             'test_0020_completed_receipt_replays_without_another_event[SQL_ASCII]'),
            ('test_registry_postgres_invariants',
             'test_nullable_business_columns_do_not_weaken_tenant_rls_or_foreign_keys'),
            ('test_ffp_postgres_platform_live',
             'test_the_tenant_context_does_not_leak_between_transactions'),
            ('test_ffp_subject_sync_postgres_live',
             'test_migration_backfills_existing_subjects_in_creation_order'),
            ('test_ffp_registry_postgres', 'test_registered_http_postgres_round_trip[UTF8]'),
            ('test_ffp_registry_postgres', 'test_registered_http_postgres_round_trip[SQL_ASCII]'),
        )
    )
    report.write_text('<testsuites><testsuite>' + cases +
        '<testcase classname="tests.test_ffp_local_controlled_integration_lab_script" '
        'name="test_bootstrap_applies_to_opt_in_local_postgres"><skipped/></testcase>'
        '</testsuite></testsuites>')
    result = subprocess.run(
        [sys.executable, "scripts/check_postgres_ci_evidence.py", str(report)],
        cwd=ROOT, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
