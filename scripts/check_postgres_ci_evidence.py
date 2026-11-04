"""Reject incomplete mandatory Linux PostgreSQL test results (no credentials)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

# These are separate operator/artifact acceptances, never substitutes for core PG tests.
OPTIONAL = {
    ('tests.test_ffp_local_controlled_integration_lab_script',
     'test_bootstrap_applies_to_opt_in_local_postgres'),
    ('tests.test_release_server_wheel', 'test_retained_server_wheel'),
}
REQUIRED = {
    ('tests.test_schema_migrations', 'test_empty_database_reaches_the_end_and_records_every_step'),
    ('tests.test_schema_migrations',
     'test_sql_ascii_database_takes_raw_utf8_jsonb_but_not_escaped_non_ascii'),
    ('tests.test_registry_0020_upgrade',
     'test_0020_completed_receipt_replays_without_another_event[SQL_ASCII]'),
    ('tests.test_registry_postgres_invariants',
     'test_nullable_business_columns_do_not_weaken_tenant_rls_or_foreign_keys'),
    ('tests.test_ffp_postgres_platform_live',
     'test_the_tenant_context_does_not_leak_between_transactions'),
    ('tests.test_ffp_subject_sync_postgres_live',
     'test_migration_backfills_existing_subjects_in_creation_order'),
    ('tests.test_ffp_registry_postgres', 'test_registered_http_postgres_round_trip[UTF8]'),
    ('tests.test_ffp_registry_postgres', 'test_registered_http_postgres_round_trip[SQL_ASCII]'),
}


def check(path: Path) -> int:
    try:
        cases = ET.parse(path).getroot().findall('.//testcase')
    except (OSError, ET.ParseError) as error:
        print(f'PostgreSQL CI evidence rejected: {error}')
        return 1
    passed = set()
    errors = []
    counts: Counter[str] = Counter()
    for case in cases:
        identity = (case.get('classname', ''), case.get('name', ''))
        if case.find('failure') is not None or case.find('error') is not None:
            errors.append(f'failed: {identity}')
        elif case.find('skipped') is not None:
            if identity not in OPTIONAL:
                errors.append(f'unexpected skip: {identity}')
            else:
                print(f'Explicit opt-in acceptance not run: {identity}')
        else:
            passed.add(identity)
            counts[identity[0]] += 1
    for missing in sorted(REQUIRED - passed):
        errors.append(f'missing passed database witness: {missing}')
    if errors:
        print('PostgreSQL CI evidence rejected:\n' + '\n'.join(errors))
        return 1
    print(f'PostgreSQL CI evidence accepted: {len(passed)} passed test cases')
    for module, count in sorted(counts.items()):
        if 'postgres' in module or 'schema' in module or 'registry' in module:
            print(f'{module}: {count} passed')
    return 0


if __name__ == '__main__':
    raise SystemExit(check(Path(sys.argv[1])))
