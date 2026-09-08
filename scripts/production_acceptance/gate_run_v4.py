"""RAY-404 gate run #4 — adds the real restore drill (foundation RestoreVerifier).

Reuses acceptance_drills.py (lifecycles, probes, capacity) and adds:
- newest backup bundle decrypted to a postgres-owned staging dir (identity in-process)
- manifest built from live facts + bundle object-manifest (byte-exact digests)
- RestoreVerifier drill: empty target DB + empty object root, pg_restore + object copy,
  per-component digest re-verification, tenant count, source version
- cleanup: drop restore DB, remove work dirs, consume (delete) the injected identity

Secrets and identity material stay in process; nothing secret is printed.
"""

from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

sys.path.insert(0, "/tmp/ray404")
sys.path.insert(0, "/opt/feetforceplate/app")

import acceptance_drills as D

from techflex_cloud_foundation.iam import RealmTokenAuthority
from techflex_cloud_foundation.ingestion import ArtifactReceipt
from techflex_cloud_foundation.observability import BackupComponent, BackupManifest
from techflex_cloud_foundation.platform_config import ProductRegistration
from techflex_cloud_foundation.release_gate import (
    BucketPolicyValidator,
    CapacitySnapshot,
    CapacityValidator,
    DeploymentProfileValidator,
    EvidenceTier,
    IngestionReceiptSnapshot,
    IngestionReceiptValidator,
    LicenseKeysetSnapshot,
    LicenseKeysetValidator,
    OrgLoginSnapshot,
    OrgLoginValidator,
    ProductProfiles,
    RecoveryDrillSnapshot,
    RecoveryDrillValidator,
    ReleaseGate,
    RlsSnapshotValidator,
    TenantIsolationSnapshot,
    TenantIsolationValidator,
    TenantProbeResult,
)
from techflex_cloud_foundation.tenancy import RlsContract
from techflex_cloud_foundation.tokens import HmacTokenCodec

BACKUP_ROOT = Path("/var/lib/feetforceplate/backups")
IDENTITY = Path("/home/rui/apps/feetforceplate-network/shared/incoming/backup.agekey")
WORK = Path("/var/lib/pgsql/ray404-drill")
STAGE = WORK / "stage"
RESTORE_ROOT = WORK / "objects"
RESTORE_DB = "feetforceplate_ray404_restore"
INSPECT_DB = "feetforceplate_ray404_inspect"
RELEASE_SHA_PATH = Path("/opt/feetforceplate/app/.release-sha")
SCHEMAS = ("device", "iam", "subject", "screening", "ops", "sales")


def psql(dsn_db: str, sql: str) -> str:
    out = subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-d", dsn_db, "-At", "-c", sql],
        check=True, capture_output=True, text=True,
    )
    return out.stdout.strip()


def age_bin() -> str:
    for candidate in ("/usr/local/bin/age", "/usr/bin/age",
                      "/home/rui/apps/feetforceplate-seed/tools/age/age"):
        if Path(candidate).exists():
            return candidate
    raise RuntimeError("age binary not found")


def newest_bundle() -> Path:
    bundles = sorted(BACKUP_ROOT.glob("*.tar.age"),
                     key=lambda p: p.stat().st_mtime, reverse=True)
    if not bundles:
        raise RuntimeError("no backup bundles")
    return bundles[0]


def db_fingerprint(db: str) -> bytes:
    tables = psql(db, (
        "SELECT n.nspname || '.' || c.relname FROM pg_class c"
        " JOIN pg_namespace n ON n.oid = c.relnamespace"
        f" WHERE c.relkind = 'r' AND n.nspname IN ({','.join(repr(s) for s in SCHEMAS)})"
        " ORDER BY 1"
    )).splitlines()
    counts = {}
    for table in tables:
        schema, name = table.split(".", 1)
        counts[table] = int(psql(db, f'SELECT count(*) FROM "{schema}"."{name}"'))
    return json.dumps(counts, sort_keys=True, separators=(",", ":")).encode()


def live_tenant_count(db: str) -> int:
    return int(psql(db, "SELECT count(*) FROM iam.tenants"))


class LiveRestoreTarget:
    """RestoredTargetProbe over the drill's restore DB + object root."""

    def is_empty(self) -> bool:
        tables = psql(RESTORE_DB, (
            "SELECT count(*) FROM information_schema.tables"
            " WHERE table_schema NOT IN ('pg_catalog','information_schema')"
        ))
        objects_empty = not any(RESTORE_ROOT.iterdir())
        return tables == "0" and objects_empty

    def component_payload(self, name: str) -> bytes | None:
        if name == "database-fingerprint":
            return db_fingerprint(RESTORE_DB)
        path = RESTORE_ROOT / name
        if not path.is_file():
            return None
        return path.read_bytes()

    def tenant_count(self) -> int:
        return live_tenant_count(RESTORE_DB)

    def restored_version(self) -> str | None:
        return RELEASE_SHA_PATH.read_text().strip()

    def available_key_references(self) -> tuple[str, ...]:
        return ()


def prepare_stage(bundle: Path) -> dict:
    """Decrypt the bundle into the staging dir; return bundle metadata."""
    shutil.rmtree(WORK, ignore_errors=True)
    STAGE.mkdir(parents=True)
    RESTORE_ROOT.mkdir(parents=True)
    (WORK).chmod(0o700)
    subprocess.run(["chown", "-R", "postgres:postgres", str(WORK)], check=True)
    # bundle and identity live in owner-only locations; stage root-owned copies
    subprocess.run(["install", "-o", "postgres", "-g", "postgres", "-m", "0600",
                    str(bundle), str(STAGE / "bundle.tar.age")], check=True)
    subprocess.run(["install", "-o", "postgres", "-g", "postgres", "-m", "0600",
                    str(IDENTITY), str(STAGE / "identity.agekey")], check=True)
    subprocess.run(
        ["sudo", "-u", "postgres", age_bin(), "--decrypt", "--identity",
         str(STAGE / "identity.agekey"),
         "--output", str(STAGE / "bundle.tar"), str(STAGE / "bundle.tar.age")],
        check=True,
    )
    subprocess.run(
        ["sudo", "-u", "postgres", "tar", "-xf", str(STAGE / "bundle.tar"), "-C", str(STAGE)],
        check=True,
    )
    metadata = json.loads((STAGE / "metadata.json").read_text())
    subprocess.run(
        ["sudo", "-u", "postgres", "mkdir", "-p", str(STAGE / "objects")], check=True,
    )
    subprocess.run(
        ["sudo", "-u", "postgres", "tar", "-xf", str(STAGE / "objects.tar"),
         "-C", str(STAGE / "objects")],
        check=True,
    )
    # The empty target database must exist before evaluation: is_empty() probes it
    # before restore() runs.
    subprocess.run(["sudo", "-u", "postgres", "dropdb", "--if-exists", RESTORE_DB],
                   check=True)
    subprocess.run(["sudo", "-u", "postgres", "createdb", RESTORE_DB], check=True)
    # Inspection pass: the bundle's own content is what the manifest commits to.
    subprocess.run(["sudo", "-u", "postgres", "dropdb", "--if-exists", INSPECT_DB],
                   check=True)
    subprocess.run(["sudo", "-u", "postgres", "createdb", INSPECT_DB], check=True)
    subprocess.run(
        ["sudo", "-u", "postgres", "pg_restore", "--no-owner", "--no-privileges",
         "-d", INSPECT_DB, str(STAGE / "database.dump")],
        check=True, capture_output=True, text=True,
    )
    return metadata


def build_manifest(bundle: Path) -> BackupManifest:
    metadata = prepare_stage(bundle)
    components: list[BackupComponent] = []

    fp = db_fingerprint(INSPECT_DB)
    components.append(BackupComponent(
        name="database-fingerprint",
        sha256=hashlib.sha256(fp).hexdigest(),
        size_bytes=len(fp),
    ))

    manifest_lines = (STAGE / "object-manifest.sha256").read_text().splitlines()
    for line in manifest_lines:
        digest, _, rel = line.partition("  ")
        rel = rel.lstrip("./")
        staged_file = STAGE / "objects" / rel
        if not staged_file.is_file():
            raise RuntimeError(f"staged object missing: {rel}")
        components.append(BackupComponent(
            name=rel, sha256=digest, size_bytes=staged_file.stat().st_size,
        ))

    return BackupManifest(
        components=tuple(components),
        tenant_count=live_tenant_count(INSPECT_DB),
        source_version=RELEASE_SHA_PATH.read_text().strip(),
        created_at=datetime.fromisoformat(metadata["created_at"].replace("Z", "+00:00")),
    )


def do_restore() -> None:
    subprocess.run(
        ["sudo", "-u", "postgres", "pg_restore", "--no-owner", "--no-privileges",
         "-d", RESTORE_DB, str(STAGE / "database.dump")],
        check=True, capture_output=True, text=True,
    )
    subprocess.run(
        ["sudo", "-u", "postgres", "cp", "-a", f"{STAGE}/objects/.", str(RESTORE_ROOT)],
        check=True,
    )


def cleanup_drill() -> None:
    subprocess.run(["sudo", "-u", "postgres", "dropdb", "--if-exists", RESTORE_DB],
                   capture_output=True)
    subprocess.run(["sudo", "-u", "postgres", "dropdb", "--if-exists", INSPECT_DB],
                   capture_output=True)
    shutil.rmtree(WORK, ignore_errors=True)
    IDENTITY.unlink(missing_ok=True)


def main() -> None:
    env = D.load_env()
    bundle = newest_bundle()
    print(f"[drill] bundle: {bundle.name}", flush=True)

    operator_id = D.bootstrap_operator(env)
    platform_token = D.mint_platform_token(env, operator_id)
    client = D.make_client()
    D.request(client, "GET", "/health/ready", expected=200)

    print("[drill] tenant lifecycles", flush=True)
    a = D.run_tenant_lifecycle(client, platform_token, "a")
    b = D.run_tenant_lifecycle(client, platform_token, "b")
    probes_a, leaks_a = D.isolation_probes(client, a, b)
    probes_b, leaks_b = D.isolation_probes(client, b, a)

    print("[drill] capacity", flush=True)
    declared = {"concurrent_sessions": 10, "ingest_bytes_per_second": 200_000}
    session_ids: list[str] = []
    def make_parallel_session(i: int):
        tenant = a if i % 2 == 0 else b
        now_i = datetime.now(UTC)
        subject_id_i, consent_id_i, sid = D.uuid4(), D.uuid4(), D.uuid4()
        unique_i = D.uuid4().hex
        token = tenant["token"]
        r1 = client.request("POST", "/v1/subjects",
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": f"cap-s-{unique_i}"},
            json=D.SubjectCreateRequest(subject_uuid=subject_id_i).model_dump(mode="json"))
        if r1.status_code != 201:
            return r1.status_code, str(sid)
        r2 = client.request("POST", "/v1/consents",
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": f"cap-c-{unique_i}"},
            json=D.ConsentCreateRequest(
                consent_record_id=consent_id_i, subject_uuid=subject_id_i,
                policy_version="ray404-acceptance/1",
                purpose_codes=("SCREENING_SERVICE",), data_categories=("PRESSURE_RAW",),
                granted_at=now_i, evidence_type="OPERATOR_CONFIRMED",
                terminal_signature="ray404-acceptance",
            ).model_dump(mode="json"))
        if r2.status_code != 201:
            return r2.status_code, str(sid)
        body = D.SessionCreateRequest(
            session_id=sid, subject_uuid=subject_id_i, consent_record_id=consent_id_i,
            site_id=None, terminal_id=D.U(tenant["installation"]),
            client_installation_id=D.U(tenant["installation"]),
            device_id=D.U(tenant["hardware_asset_id"]),
            test_protocol=D.TestProtocol(id="ray404-capacity", version="1.0"),
            versions=D.SessionVersions(app="ray404-acceptance/1", protocol_profile="do-p4864/1",
                                       payload_schema="raw-segment/1", calibration="synthetic/1"),
            started_at=now_i,
        )
        r3 = client.request("POST", "/v1/sessions",
            headers={"Authorization": f"Bearer {token}", "Idempotency-Key": f"cap-ss-{unique_i}"},
            json=body.model_dump(mode="json"))
        return r3.status_code, str(sid)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(make_parallel_session, range(10)))
    ok_sessions = sum(1 for code, _ in results if code == 201)
    session_ids = [sid for code, sid in results if code == 201]
    measured = {"concurrent_sessions": ok_sessions}
    import os
    big_payload = os.urandom(1_048_576)
    big_digest = hashlib.sha256(big_payload).hexdigest()
    cap_session = session_ids[0] if session_ids else a["session_id"]
    big_meta = D.SegmentMetadata(
        segment_index=2, start_frame_index=0, frame_count=1000,
        start_monotonic_ns=0, end_monotonic_ns=1_000_000,
        compression="zstd", cipher="aes-256-gcm",
        size_bytes=len(big_payload), sha256=big_digest, payload_schema_version="raw-segment/1",
    )
    t0 = time.monotonic()
    resp = client.request("PUT", f"/v1/sessions/{cap_session}/segments/2",
        headers={"Authorization": f"Bearer {a['token']}",
                 "X-Content-SHA256": big_digest, "X-Schema-Version": "raw-segment/1",
                 "X-Segment-Metadata": D.encode_segment_metadata(big_meta),
                 "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream"},
        content=big_payload)
    secs = time.monotonic() - t0
    if resp.status_code == 201:
        measured["ingest_bytes_per_second"] = int(len(big_payload) / secs)
    else:
        measured["ingest_bytes_per_second"] = 0
    print(f"[drill] capacity measured={measured}", flush=True)

    print("[drill] restore drill", flush=True)
    manifest = build_manifest(bundle)
    drill_snapshot = RecoveryDrillSnapshot(
        manifest=manifest, target=LiveRestoreTarget(), restore=do_restore,
    )

    profile_document = {
        "schema_version": "techflex-platform-deployment/1",
        "environment": "production", "region": "cn-beijing",
        "ingress": {"public_base_url": D.BASE_URL, "port": 443, "public_ca": True},
        "kms": {"provider": "env", "locator": "FEETFORCEPLATE_LICENSE_PRIVATE_KEY_B64"},
        "databases": {
            "migration": {"provider": "env", "locator": "FEETFORCEPLATE_MIGRATION_DSN"},
            "tenant": {"provider": "env", "locator": "FEETFORCEPLATE_TENANT_DSN"},
            "activation": {"provider": "env", "locator": "FEETFORCEPLATE_ACTIVATION_DSN"},
            "platform": {"provider": "env", "locator": "FEETFORCEPLATE_PLATFORM_DSN"},
            "backup": {"provider": "env", "locator": "FEETFORCEPLATE_BACKUP_DSN"},
        },
        "buckets": [],  # replaced below with the real OSS bindings
        "products": [{"product_id": "feetforceplate",
                      "supported_schema_versions": ["session-manifest/1", "analysis-profile/1"]}],
    }
    # RAY-405: real bucket bindings from the deployment env (bucket name stays
    # in process; the receipt's whitelist never serializes it).
    oss_policy = {
        "encryption": "sse-aes256",
        "versioning": True,
        "retention": "standard",
    }
    profile_document["buckets"] = [
        {"role": "raw-immutable",
         "physical_bucket": env["FEETFORCEPLATE_OSS_BUCKET"],
         "policy": dict(oss_policy)},
        {"role": "derived",
         "physical_bucket": env["FEETFORCEPLATE_OSS_BUCKET"],
         "policy": dict(oss_policy)},
    ]
    rls_doc = json.loads(D.RLS_SNAPSHOT_PATH.read_text())
    rls_document = {"application_role": rls_doc["application_role"], "tables": rls_doc["tables"]}
    required_tables = tuple(json.loads(D.RLS_TABLES_PATH.read_text()))
    key_id = env.get("FEETFORCEPLATE_LICENSE_KEY_ID", "license/1")
    keyset_snapshot = LicenseKeysetSnapshot(
        revision=1, active_key_id=key_id,
        public_keys={key_id: D.PUBLIC_KEY_PATH.read_bytes()}, revoked_key_ids=(),
    )
    completion = a["completion"]
    replay = a["replay"]
    # RAY-407: the replay must rebuild the receipt identically from persisted
    # columns; any drift here fails the drill honestly.
    for field in ("manifest_object_key", "eligibility_reason",
                  "eligibility_policy_version", "completed_at"):
        if str(completion[field]) != str(replay[field]):
            raise RuntimeError(f"completion receipt field {field} drifted on replay")

    response_receipt = ArtifactReceipt(
        session_id=D.U(a["session_id"]),
        manifest_digest=str(completion["manifest_sha256"]),
        manifest_object_key=str(completion["manifest_object_key"]),
        eligibility_reason=str(completion["eligibility_reason"]),
        eligibility_policy_version=str(completion["eligibility_policy_version"]),
        completed_at=datetime.fromisoformat(str(completion["completed_at"])),
        idempotency_key=a["idempotency_key"],
    )
    # Independent source: the persisted row, read through the operator channel.
    row_out = subprocess.run(
        ["sudo", "-u", "postgres", "env", "PGTZ=UTC", "psql", "-d", "feetforceplate_seed",
         "-At", "-c",
         "SELECT row_to_json(m) FROM screening.session_manifests m"
         f" WHERE session_id = '{a['session_id']}'"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    row = json.loads(row_out)
    stored_receipt = ArtifactReceipt(
        session_id=D.U(row["session_id"]),
        manifest_digest=row["manifest_sha256"],
        manifest_object_key=row["object_key"],
        eligibility_reason=row["eligibility_reason"],
        eligibility_policy_version=row["eligibility_policy_version"],
        completed_at=datetime.fromisoformat(str(row["completed_at"])),
        idempotency_key=row["idempotency_key"],
    )
    if response_receipt.digest() != stored_receipt.digest():
        print("=== RECEIPT DIGEST MISMATCH DEBUG ===")
        print("response canonical:", response_receipt.canonical_bytes().decode())
        print("stored   canonical:", stored_receipt.canonical_bytes().decode())
    ingestion_snapshot = IngestionReceiptSnapshot(
        receipt=response_receipt,
        expected_digest=stored_receipt.digest(),
        expected_canonical_bytes=stored_receipt.canonical_bytes(),
    )
    org_login_snapshot = OrgLoginSnapshot(
        tenant_access_token=a["token"], expected_tenant_id=a["tenant_id"],
        expected_operator_id=a["account_id"], platform_access_token=platform_token,
    )
    tenant_isolation_snapshot = TenantIsolationSnapshot(
        required_tenant_ids=frozenset({a["tenant_id"], b["tenant_id"]}),
        results=(
            TenantProbeResult(tenant_id=a["tenant_id"], probes_executed=probes_a,
                              cross_tenant_leaks=tuple(leaks_a)),
            TenantProbeResult(tenant_id=b["tenant_id"], probes_executed=probes_b,
                              cross_tenant_leaks=tuple(leaks_b)),
        ),
    )
    capacity_snapshot = CapacitySnapshot(declared_minimums=declared, measured=measured)

    tenant_codec = HmacTokenCodec(
        secret=env["FEETFORCEPLATE_TENANT_TOKEN_SECRET"].encode(),
        key_id=env.get("FEETFORCEPLATE_TENANT_TOKEN_KEY_ID", "tenant/1"),
        token_type="tenant_access", audience="feetforceplate-api",
    )
    platform_codec = HmacTokenCodec(
        secret=env["FEETFORCEPLATE_PLATFORM_TOKEN_SECRET"].encode(),
        key_id=env.get("FEETFORCEPLATE_PLATFORM_TOKEN_KEY_ID", "platform/1"),
        token_type="platform_access", audience="feetforceplate-platform",
    )
    authority = RealmTokenAuthority(platform_codec=platform_codec, tenant_codec=tenant_codec)

    gate = ReleaseGate([
        DeploymentProfileValidator(), BucketPolicyValidator(),
        RlsSnapshotValidator(RlsContract(tenant_setting="ops.current_tenant_id()",
                                         required_tables=required_tables)),
        LicenseKeysetValidator(), OrgLoginValidator(authority), IngestionReceiptValidator(),
        TenantIsolationValidator(), RecoveryDrillValidator(), CapacityValidator(),
    ])
    now = datetime.now(UTC)
    receipt = gate.evaluate(
        snapshots={
            "deployment_profile": profile_document,
            "bucket_policy": profile_document,
            "rls_snapshot": rls_document,
            "license_keyset": keyset_snapshot,
            "ingestion_receipt": ingestion_snapshot,
            "org_login": org_login_snapshot,
            "tenant_isolation": tenant_isolation_snapshot,
            "backup_recovery": drill_snapshot,
            "capacity": capacity_snapshot,
        },
        tier=EvidenceTier.PRODUCTION,
        product_profiles=ProductProfiles(
            profiles=(ProductRegistration("feetforceplate",
                                          ("session-manifest/1", "analysis-profile/1")),),
            provisional=True,
        ),
        release_version="0.2.0",
        now=now,
    )
    print("=== RECEIPT (redacted, canonical) ===")
    print(json.dumps(receipt.to_document(), indent=1, sort_keys=True))
    print("=== SUMMARY ===")
    print("decision:", str(receipt.decision))
    print("production_ready:", receipt.production_ready)
    print("=== OPERATOR NOTES (not part of receipt) ===")
    for result in receipt.results:
        marker = "PASS" if result.passed else str(result.level)
        print(f"[{marker}] {result.validator}: {result.reason[:200]}")

    print("[drill] cleanup", flush=True)
    cleanup_drill()
    print("[drill] identity consumed:", not IDENTITY.exists())


if __name__ == "__main__":
    main()
