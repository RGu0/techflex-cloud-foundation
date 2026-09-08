"""Validate the captured RLS introspection snapshot against the CP-08 contract.

Reads the evidence snapshot captured from the live deployment catalog, builds
the deployment's RLS contract (every tenant-plane table the deployment commits
to keeping RLS-forced and tenant-constrained), and runs tenancy.parse_introspection_snapshot
+ RlsContract.validate exactly as ReleaseGate's RlsSnapshotValidator will.
"""

import json
from pathlib import Path
import sys

from techflex_cloud_foundation.tenancy import RlsContract, parse_introspection_snapshot

BASE = Path(__file__).resolve().parent.parent
snapshot_path = BASE / "acceptance" / "rls-introspection-snapshot.json"
contract_tables_path = BASE / "acceptance" / "rls-contract-required-tables.json"

raw = json.loads(snapshot_path.read_text())
document = {"application_role": raw["application_role"], "tables": raw["tables"]}
required_tables = tuple(json.loads(contract_tables_path.read_text()))
TENANT_SETTING = "ops.current_tenant_id()"

parsed = parse_introspection_snapshot(document)
contract = RlsContract(tenant_setting=TENANT_SETTING, required_tables=required_tables)
report = contract.validate(parsed)

print(f"snapshot tables: {len(parsed.tables)}")
print(f"contract tables: {len(required_tables)}")
print(f"tenant_setting: {TENANT_SETTING}")
print(f"application_role: {parsed.application_role.name}")
if report.satisfied:
    print("RESULT: SATISFIED — every contract clause passes on live catalog facts")
else:
    print(f"RESULT: VIOLATIONS — {len(report.findings)} finding(s)")
    for finding in report.findings:
        print(f"  [{finding.code}] {finding.subject}: {finding.detail}")
    sys.exit(1)
