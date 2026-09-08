"""RAY-404 acceptance drills + gate run #3, executed on the deployment host.

All credentials (platform secret, generated passwords, activation codes,
tokens) live in process memory only.  Output: redacted receipt + facts.
"""

from base64 import urlsafe_b64decode
import concurrent.futures
from datetime import UTC, datetime, timedelta
import hashlib
import hmac as hmac_mod
import json
from pathlib import Path
import sys
import time
from uuid import UUID as U
from uuid import uuid4

sys.path.insert(0, "/opt/feetforceplate/app")

from cloud.access_control.passwords import hash_password
from cloud.api.access_auth import PlatformAccessTokenIssuer
import httpx
from shared.contracts.access_control import PlatformRole
from shared.contracts.client_sync import canonical_sha256, encode_segment_metadata
from shared.contracts.cloud import (
    ConsentCreateRequest,
    ManifestSegment,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    SubjectCreateRequest,
    TestProtocol,
)

from techflex_cloud_foundation.iam import RealmTokenAuthority
from techflex_cloud_foundation.platform_config import ProductRegistration
from techflex_cloud_foundation.release_gate import (
    BucketPolicyValidator,
    CapacitySnapshot,
    CapacityValidator,
    DeploymentProfileValidator,
    EvidenceTier,
    IngestionReceiptValidator,
    LicenseKeysetSnapshot,
    LicenseKeysetValidator,
    OrgLoginSnapshot,
    OrgLoginValidator,
    ProductProfiles,
    RecoveryDrillValidator,
    ReleaseGate,
    RlsSnapshotValidator,
    TenantIsolationSnapshot,
    TenantIsolationValidator,
    TenantProbeResult,
)
from techflex_cloud_foundation.tenancy import RlsContract
from techflex_cloud_foundation.tokens import HmacTokenCodec

ENV_PATH = Path("/etc/feetforceplate/seed.env")
PUBLIC_KEY_PATH = Path(
    "/srv/feetforceplate/acceptance-public/ray-99-integration/license-public.key"
)
RLS_SNAPSHOT_PATH = Path("/tmp/ray404/rls-introspection-snapshot.json")
RLS_TABLES_PATH = Path("/tmp/ray404/rls-contract-required-tables.json")
BASE_URL = "https://api.gu0.tech"
OPERATOR_LOGIN = "acceptance-operator"


def load_env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in ENV_PATH.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, value = line.partition("=")
            values[key] = value
    return values


def b64payload(token: str) -> dict:
    part = token.split(".")[1]
    part += "=" * (-len(part) % 4)
    return json.loads(urlsafe_b64decode(part))


def make_client() -> httpx.Client:
    return httpx.Client(base_url=BASE_URL, trust_env=False, timeout=60.0)


def request(client, method, path, *, expected, token=None, headers=None,
            json_body=None, content=None):
    req_headers = dict(headers or {})
    if token is not None:
        req_headers["Authorization"] = f"Bearer {token}"
    accepted = (expected,) if isinstance(expected, int) else expected
    for attempt in range(7):
        response = client.request(method, path, headers=req_headers,
                                  json=json_body, content=content)
        if response.status_code != 429 or 429 in accepted or attempt == 6:
            break
        time.sleep(max(float(response.headers.get("Retry-After", 13)), 1.0))
    if response.status_code not in accepted:
        raise RuntimeError(
            f"{method} {path} -> HTTP {response.status_code}: {response.text[:200]}"
        )
    payload = response.json() if response.content else None
    if isinstance(payload, dict) and "data" in payload:
        payload = payload["data"]
    return payload


def bootstrap_operator(env: dict[str, str]) -> str:
    """Create (or reset) the acceptance platform operator via postgres superuser."""
    import subprocess
    import unicodedata

    password = __import__("secrets").token_urlsafe(18)  # hashed immediately, never stored
    normalized = unicodedata.normalize("NFKC", OPERATOR_LOGIN).strip().lower()
    login_hmac_hex = hmac_mod.new(
        env["FEETFORCEPLATE_PLATFORM_LOGIN_HMAC_KEY"].encode(), normalized.encode(), hashlib.sha256
    ).hexdigest()
    password_hash = hash_password(password).replace("'", "''")
    operator_id = str(uuid4())
    binding_id = str(uuid4())
    sql = f"""
    DELETE FROM iam.platform_identity_role_bindings WHERE platform_identity_id IN
      (SELECT platform_identity_id FROM iam.platform_identities
        WHERE login_name_hmac = decode('{login_hmac_hex}','hex'));
    DELETE FROM iam.platform_identities WHERE login_name_hmac = decode('{login_hmac_hex}','hex');
    INSERT INTO iam.platform_identities
      (platform_identity_id, login_name_hmac, display_name, password_hash, status,
       token_version, created_at)
    VALUES ('{operator_id}', decode('{login_hmac_hex}','hex'),
            'RAY-404 acceptance operator', '{password_hash}', 'ACTIVE', 1, now());
    INSERT INTO iam.platform_identity_role_bindings
      (platform_identity_role_binding_id, platform_identity_id, platform_role_id,
       valid_from, created_at)
    SELECT '{binding_id}', i.platform_identity_id, r.platform_role_id, now(), now()
      FROM iam.platform_identities i
      CROSS JOIN (SELECT platform_role_id FROM iam.platform_roles
                   WHERE role_name = 'PLATFORM_OWNER') r
     WHERE i.login_name_hmac = decode('{login_hmac_hex}','hex');
    """
    subprocess.run(
        ["sudo", "-u", "postgres", "psql", "-d", "feetforceplate_seed", "-v", "ON_ERROR_STOP=1",
         "-c", sql],
        check=True, capture_output=True, text=True,
    )
    return operator_id


def mint_platform_token(env, operator_id):
    issuer = PlatformAccessTokenIssuer(
        secret=env["FEETFORCEPLATE_PLATFORM_TOKEN_SECRET"].encode(),
        key_id=env.get("FEETFORCEPLATE_PLATFORM_TOKEN_KEY_ID", "platform/1"),
    )
    return issuer.issue(
        platform_identity_id=__import__("uuid").UUID(operator_id),
        roles=(PlatformRole.OWNER,),
        token_version=1,
    )


def run_tenant_lifecycle(client, platform_token, label: str) -> dict:
    unique = uuid4().hex
    account_name = f"ray404-{label}-{unique[:10]}"
    hardware_id = "usb-serial-" + uuid4().hex[:20]
    password = __import__("secrets").token_urlsafe(18)
    installation = str(uuid4())

    provisioned = request(
        client, "POST", "/v1/platform/tenants", expected=201,
        token=platform_token,
        json_body={
            "tenant_name": f"RAY-404 acceptance {label} {unique[:8]}",
            "account_name": account_name,
            "hardware_id": hardware_id,
            "license_period_months": 6,
        },
    )
    request(
        client, "POST", "/v1/access/activate", expected=201,
        json_body={
            "account_name": account_name,
            "activation_code": provisioned["activation_code"],
            "password": password,
            "password_confirmation": password,
            "hardware_id": hardware_id,
            "client_installation_id": installation,
        },
    )
    logged_in = request(
        client, "POST", "/v1/access/login", expected=200,
        json_body={"account_name": account_name, "password": password,
                   "client_installation_id": installation},
    )
    token = str(logged_in["access_token"])
    tenant_id = b64payload(token)["tenant_id"]
    account_id = b64payload(token)["account_id"]
    hardware_asset_id = str(logged_in["hardware_asset_id"])

    now = datetime.now(UTC)
    subject_id, consent_id, session_id = uuid4(), uuid4(), uuid4()
    request(client, "POST", "/v1/subjects", expected=201, token=token,
            headers={"Idempotency-Key": f"subject-{unique}"},
            json_body=SubjectCreateRequest(subject_uuid=subject_id).model_dump(mode="json"))
    request(client, "POST", "/v1/consents", expected=201, token=token,
            headers={"Idempotency-Key": f"consent-{unique}"},
            json_body=ConsentCreateRequest(
                consent_record_id=consent_id, subject_uuid=subject_id,
                policy_version="ray404-acceptance/1",
                purpose_codes=("SCREENING_SERVICE",), data_categories=("PRESSURE_RAW",),
                granted_at=now, evidence_type="OPERATOR_CONFIRMED",
                terminal_signature="ray404-acceptance",
            ).model_dump(mode="json"))
    session_body = SessionCreateRequest(
        session_id=session_id, subject_uuid=subject_id, consent_record_id=consent_id,
        site_id=None, terminal_id=U(installation), client_installation_id=U(installation),
        device_id=U(hardware_asset_id),
        test_protocol=TestProtocol(id="ray404-acceptance", version="1.0"),
        versions=SessionVersions(app="ray404-acceptance/1", protocol_profile="do-p4864/1",
                                 payload_schema="raw-segment/1", calibration="synthetic/1"),
        started_at=now,
    )
    request(client, "POST", "/v1/sessions", expected=201, token=token,
            headers={"Idempotency-Key": f"session-{unique}"},
            json_body=session_body.model_dump(mode="json"))

    payload = b"ray404-acceptance-segment-placeholder" * 128
    digest = hashlib.sha256(payload).hexdigest()
    metadata = SegmentMetadata(
        segment_index=0, start_frame_index=0, frame_count=10,
        start_monotonic_ns=100, end_monotonic_ns=200,
        compression="zstd", cipher="aes-256-gcm",
        size_bytes=len(payload), sha256=digest, payload_schema_version="raw-segment/1",
    )
    request(client, "PUT", f"/v1/sessions/{session_id}/segments/0", expected=201, token=token,
            headers={"X-Content-SHA256": digest, "X-Schema-Version": "raw-segment/1",
                     "X-Segment-Metadata": encode_segment_metadata(metadata),
                     "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream"},
            content=payload)
    manifest = SessionManifest(
        segment_count=1, total_frames=10, total_bytes=len(payload),
        segments=(
            ManifestSegment(
                index=0, sha256=digest, size_bytes=len(payload), frame_count=10
            ),
        ),
        ended_at=now + timedelta(seconds=1), local_quality_outcome="VALID",
    )
    completion = request(client, "POST", f"/v1/sessions/{session_id}/complete", expected=200,
                         token=token,
                         headers={"Idempotency-Key": f"complete-{unique}",
                                  "X-Content-SHA256": canonical_sha256(manifest),
                                  "X-Schema-Version": "session-manifest/1"},
                         json_body=manifest.model_dump(mode="json"))
    # Replay with a different idempotency key: exercises the existing-VERIFIED
    # branch that rebuilds the receipt from the persisted columns (RAY-407).
    replay = request(client, "POST", f"/v1/sessions/{session_id}/complete", expected=200,
                     token=token,
                     headers={"Idempotency-Key": f"complete-replay-{unique}",
                              "X-Content-SHA256": canonical_sha256(manifest),
                              "X-Schema-Version": "session-manifest/1"},
                     json_body=manifest.model_dump(mode="json"))
    status = request(client, "GET", f"/v1/sessions/{session_id}/status", expected=200, token=token)
    return {
        "label": label, "tenant_id": tenant_id, "account_id": account_id,
        "token": token, "installation": installation,
        "session_id": str(session_id), "completion": completion, "replay": replay,
        "status": status, "hardware_asset_id": hardware_asset_id,
        "idempotency_key": f"complete-{unique}",
    }


def isolation_probes(client, attacker: dict, victim: dict) -> tuple[int, list[str]]:
    probes = 0
    leaks: list[str] = []
    victim_session = victim["session_id"]
    attempts = [
        ("GET", f"/v1/sessions/{victim_session}/status", None, None),
        ("GET", f"/v1/sessions/{victim_session}/segments", None, None),
        ("PUT", f"/v1/sessions/{victim_session}/segments/1", {}, b"ray404-cross-tenant-probe"),
        ("POST", f"/v1/sessions/{victim_session}/complete", {}, None),
    ]
    for method, path, body, content in attempts:
        probes += 1
        try:
            resp = client.request(
                method, path,
                headers={"Authorization": f"Bearer {attacker['token']}"},
                json=body, content=content,
            )
            if 200 <= resp.status_code < 300:
                leaks.append(f"{method} {path.split('/')[-1]} -> {resp.status_code}")
        except Exception as exc:  # noqa: BLE001
            probes += 1
            leaks.append(f"probe-error {type(exc).__name__}")
    return probes, leaks


def main() -> None:
    env = load_env()
    facts: dict = {}

    print("[1/6] bootstrap acceptance operator", flush=True)
    operator_id = bootstrap_operator(env)
    platform_token = mint_platform_token(env, operator_id)
    facts["operator_id"] = operator_id

    client = make_client()
    ready = request(client, "GET", "/health/ready", expected=200)
    ready_label = ready if not isinstance(ready, dict) else ready.get("status", ready)
    print("    readiness:", ready_label, flush=True)

    print("[2/6] tenant A lifecycle", flush=True)
    a = run_tenant_lifecycle(client, platform_token, "a")
    print("[3/6] tenant B lifecycle", flush=True)
    b = run_tenant_lifecycle(client, platform_token, "b")

    print("[4/6] isolation probes", flush=True)
    probes_a, leaks_a = isolation_probes(client, a, b)
    probes_b, leaks_b = isolation_probes(client, b, a)
    facts["isolation"] = {"probes": probes_a + probes_b, "leaks": leaks_a + leaks_b}
    print(f"    probes={probes_a + probes_b} leaks={len(leaks_a + leaks_b)}", flush=True)

    print("[5/6] capacity measurement", flush=True)
    declared = {"concurrent_sessions": 10, "ingest_bytes_per_second": 200_000}
    session_ids: list[str] = []

    def make_parallel_session(i: int):
        tenant = a if i % 2 == 0 else b
        token = tenant["token"]
        now_i = datetime.now(UTC)
        subject_id_i, consent_id_i, sid = uuid4(), uuid4(), uuid4()
        unique_i = uuid4().hex
        r1 = client.request(
            "POST", "/v1/subjects",
            headers={"Authorization": f"Bearer {token}",
                     "Idempotency-Key": f"cap-subject-{unique_i}"},
            json=SubjectCreateRequest(subject_uuid=subject_id_i).model_dump(mode="json"),
        )
        if r1.status_code != 201:
            return r1.status_code, str(sid)
        r2 = client.request(
            "POST", "/v1/consents",
            headers={"Authorization": f"Bearer {token}",
                     "Idempotency-Key": f"cap-consent-{unique_i}"},
            json=ConsentCreateRequest(
                consent_record_id=consent_id_i, subject_uuid=subject_id_i,
                policy_version="ray404-acceptance/1",
                purpose_codes=("SCREENING_SERVICE",), data_categories=("PRESSURE_RAW",),
                granted_at=now_i, evidence_type="OPERATOR_CONFIRMED",
                terminal_signature="ray404-acceptance",
            ).model_dump(mode="json"),
        )
        if r2.status_code != 201:
            return r2.status_code, str(sid)
        body = SessionCreateRequest(
            session_id=sid, subject_uuid=subject_id_i, consent_record_id=consent_id_i,
            site_id=None, terminal_id=U(tenant["installation"]),
            device_id=U(tenant["hardware_asset_id"]),
            test_protocol=TestProtocol(id="ray404-capacity", version="1.0"),
            versions=SessionVersions(app="ray404-acceptance/1", protocol_profile="do-p4864/1",
                                     payload_schema="raw-segment/1", calibration="synthetic/1"),
            started_at=now_i,
        )
        r3 = client.request(
            "POST", "/v1/sessions",
            headers={"Authorization": f"Bearer {token}",
                     "Idempotency-Key": f"cap-session-{unique_i}"},
            json=body.model_dump(mode="json"),
        )
        return r3.status_code, str(sid)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(make_parallel_session, range(10)))
    ok_sessions = sum(1 for code, _ in results if code == 201)
    session_ids = [sid for code, sid in results if code == 201]
    measured = {"concurrent_sessions": ok_sessions}

    big_payload = __import__("os").urandom(1_048_576)
    big_digest = hashlib.sha256(big_payload).hexdigest()
    cap_session = session_ids[0] if session_ids else a["session_id"]
    big_meta = SegmentMetadata(
        segment_index=2, start_frame_index=0, frame_count=1000,
        start_monotonic_ns=0, end_monotonic_ns=1_000_000,
        compression="zstd", cipher="aes-256-gcm",
        size_bytes=len(big_payload), sha256=big_digest, payload_schema_version="raw-segment/1",
    )
    upload_start = time.monotonic()
    resp = client.request(
        "PUT", f"/v1/sessions/{cap_session}/segments/2",
        headers={"Authorization": f"Bearer {a['token']}",
                 "X-Content-SHA256": big_digest, "X-Schema-Version": "raw-segment/1",
                 "X-Segment-Metadata": encode_segment_metadata(big_meta),
                 "Content-Type": "application/vnd.feetforceplate.segment.v1+octet-stream"},
        content=big_payload,
    )
    upload_seconds = time.monotonic() - upload_start
    if resp.status_code == 201:
        measured["ingest_bytes_per_second"] = int(len(big_payload) / upload_seconds)
    else:
        measured["ingest_bytes_per_second"] = 0
    facts["capacity"] = {"declared": declared, "measured": measured,
                          "upload_seconds": round(upload_seconds, 3),
                          "upload_status": resp.status_code}
    print(f"    measured={measured}", flush=True)

    print("[6/6] gate evaluation", flush=True)
    profile_document = {
        "schema_version": "techflex-platform-deployment/1",
        "environment": "production",
        "region": "cn-beijing",
        "ingress": {"public_base_url": BASE_URL, "port": 443, "public_ca": True},
        "kms": {"provider": "env", "locator": "FEETFORCEPLATE_LICENSE_PRIVATE_KEY_B64"},
        "databases": {
            "migration": {"provider": "env", "locator": "FEETFORCEPLATE_MIGRATION_DSN"},
            "tenant": {"provider": "env", "locator": "FEETFORCEPLATE_TENANT_DSN"},
            "activation": {"provider": "env", "locator": "FEETFORCEPLATE_ACTIVATION_DSN"},
            "platform": {"provider": "env", "locator": "FEETFORCEPLATE_PLATFORM_DSN"},
            "backup": {"provider": "env", "locator": "FEETFORCEPLATE_BACKUP_DSN"},
        },
        "buckets": [],
        "products": [{"product_id": "feetforceplate",
                      "supported_schema_versions": ["session-manifest/1", "analysis-profile/1"]}],
    }
    rls_doc = json.loads(RLS_SNAPSHOT_PATH.read_text())
    rls_document = {"application_role": rls_doc["application_role"], "tables": rls_doc["tables"]}
    required_tables = tuple(json.loads(RLS_TABLES_PATH.read_text()))
    key_id = env.get("FEETFORCEPLATE_LICENSE_KEY_ID", "license/1")
    keyset_snapshot = LicenseKeysetSnapshot(
        revision=1, active_key_id=key_id,
        public_keys={key_id: PUBLIC_KEY_PATH.read_bytes()}, revoked_key_ids=(),
    )
    org_login_snapshot = OrgLoginSnapshot(
        tenant_access_token=a["token"], expected_tenant_id=a["tenant_id"],
        expected_operator_id=a["account_id"], platform_access_token=platform_token,
    )
    completion = a["completion"]  # noqa: F841 - retained for drill debugging
    # NOTE: the deployment's completion record (ManifestCompletionResponse +
    # session_manifests) does not carry the foundation CP-06 eligibility receipt
    # fields, so an honest ArtifactReceipt cannot be assembled here; the
    # ingestion_receipt validator stays registered without a snapshot and must
    # record a blocking finding (absent evidence).
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
        DeploymentProfileValidator(),
        BucketPolicyValidator(),
        RlsSnapshotValidator(RlsContract(
            tenant_setting="ops.current_tenant_id()", required_tables=required_tables)),
        LicenseKeysetValidator(),
        OrgLoginValidator(authority),
        IngestionReceiptValidator(),
        TenantIsolationValidator(),
        RecoveryDrillValidator(),
        CapacityValidator(),
    ])
    from datetime import datetime as dt
    now = dt.now(UTC)
    release_receipt = gate.evaluate(
        snapshots={
            "deployment_profile": profile_document,
            "bucket_policy": profile_document,
            "rls_snapshot": rls_document,
            "license_keyset": keyset_snapshot,
            "org_login": org_login_snapshot,
            "tenant_isolation": tenant_isolation_snapshot,
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
    print(json.dumps(release_receipt.to_document(), indent=1, sort_keys=True))
    print("=== SUMMARY ===")
    print("decision:", str(release_receipt.decision))
    print("production_ready:", release_receipt.production_ready)
    print("=== OPERATOR NOTES (not part of receipt) ===")
    for result in release_receipt.results:
        marker = "PASS" if result.passed else str(result.level)
        print(f"[{marker}] {result.validator}: {result.reason[:200]}")

    facts_out = {k: v for k, v in facts.items()}
    facts_out["tenants"] = {t: {kk: vv for kk, vv in t_vars.items() if kk != "token"}
                            for t, t_vars in (("a", a), ("b", b))}
    Path("/tmp/ray404/drill-facts.json").write_text(json.dumps(facts_out, indent=1, default=str))


if __name__ == "__main__":
    main()
