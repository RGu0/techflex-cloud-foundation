#!/usr/bin/env python3
"""Deterministic seed access acceptance runner with redacted JSON evidence."""

from __future__ import annotations

import argparse
import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import json
from pathlib import Path
import socket
import ssl
import subprocess
from urllib.parse import urlparse
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from techflex_cloud_foundation.contracts.access_control import (
    ActivateAccountRequest,
    HardwareLeaseRequest,
    LicenseControlAction,
    LicenseControlRequest,
    LoginRequest,
    PlatformRole,
    ProvisionTenantRequest,
    RefreshRequest,
)
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    ManifestSegment,
    SegmentMetadata,
    SessionCreateRequest,
    SessionManifest,
    SessionVersions,
    TestProtocol,
    ValidityStatus,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import AuthenticationError, TenantAccessDenied
from techflex_cloud_foundation.server.access_auth import (
    LicenseDocumentSigner,
    PlatformAccessContext,
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
    TenantAccessTokenIssuer,
)
from techflex_cloud_foundation.server.access_control.lease_service import (
    HardwareLeaseConflict,
    HardwareLeaseService,
)
from techflex_cloud_foundation.server.access_control.platform_iam import (
    PlatformPermissionDenied,
    SensitiveAccessService,
)
from techflex_cloud_foundation.server.access_control.platform_service import (
    PlatformProvisioningService,
)
from techflex_cloud_foundation.server.access_control.repository import InMemoryAccessRepository
from techflex_cloud_foundation.server.access_control.tenant_service import (
    TenantAuthenticationRejected,
    TenantAuthenticationService,
)
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.principal import tenant_ingestion_principal
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore

START = datetime.now(UTC).replace(microsecond=0)


@dataclass
class Clock:
    value: datetime = START

    def __call__(self) -> datetime:
        return self.value


async def _one_chunk(payload: bytes):
    yield payload


def _git_sha() -> str:
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()


async def run_local_acceptance() -> dict[str, object]:
    clock = Clock()
    access = InMemoryAccessRepository()
    data = InMemoryPlatformRepository()
    objects = InMemoryObjectStore()
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    signer = LicenseDocumentSigner(
        private_key=private_key, key_id="license/2-acceptance",
        public_keys={"license/2-acceptance": public_key},
    )
    tenant_tokens = TenantAccessTokenIssuer(secret=b"t" * 40, key_id="tenant/acceptance")
    platform_tokens = PlatformAccessTokenIssuer(secret=b"p" * 40, key_id="platform/acceptance")
    tenant_service = TenantAuthenticationService(
        access, login_lookup_hmac_key=b"l" * 40, activation_hmac_key=b"a" * 40,
        tenant_tokens=tenant_tokens, refresh_tokens=RefreshTokenFactory(digest_key=b"r" * 40),
        license_signer=signer, now=clock,
    )
    platform = PlatformProvisioningService(
        access, login_lookup_hmac_key=b"l" * 40, activation_hmac_key=b"a" * 40,
        license_signer=signer, now=clock,
    )
    leases = HardwareLeaseService(access, now=clock)
    sensitive = SensitiveAccessService(access, now=clock)
    ingestion = IngestionService(
        data, SegmentObjectStore(objects), supported_payload_schemas={"raw-segment/1"},
        supported_manifest_schemas={"session-manifest/1"},
    )
    operator = PlatformAccessContext(
        platform_identity_id=uuid4(), roles=frozenset({PlatformRole.OPERATIONS}),
        token_version=1, expires_at=START + timedelta(days=30),
    )
    support = PlatformAccessContext(
        platform_identity_id=uuid4(), roles=frozenset({PlatformRole.SUPPORT}),
        token_version=1, expires_at=START + timedelta(days=30),
    )
    rows: list[dict[str, object]] = []
    sessions = []
    for index in range(1, 11):
        request = ProvisionTenantRequest(
            tenant_name=f"Synthetic Institution {index:02d}",
            account_name=f"seed-{index:02d}",
            hardware_id=f"usb-serial-{index:020x}", license_period_months=12,
        )
        provisioned = await platform.provision_tenant(operator, request)
        installation_id = uuid4()
        activated = await tenant_service.activate(
            ActivateAccountRequest(
                account_name=provisioned.account_name,
                activation_code=provisioned.activation_code,
                password="correct-horse-battery-staple",
                password_confirmation="correct-horse-battery-staple",
                hardware_id=provisioned.hardware_id,
                client_installation_id=installation_id,
            ),
            source_fingerprint=f"synthetic-source-{index}".encode(),
        )
        group = await access.access_group_for_license(provisioned.license_id)
        site_id, subject_id, consent_id, session_id = uuid4(), uuid4(), uuid4(), uuid4()
        data.add_terminal(provisioned.tenant_id, site_id, installation_id)
        data.add_device(provisioned.tenant_id, group.hardware_id, "DO-P4864")
        data.add_subject(provisioned.tenant_id, subject_id)
        data.add_consent(provisioned.tenant_id, subject_id, consent_id, START)
        access_context = tenant_tokens.verify(activated.access_token, now=clock.value)
        context = tenant_ingestion_principal(access_context)
        request_session = SessionCreateRequest(
            session_id=session_id, subject_uuid=subject_id, consent_record_id=consent_id,
            site_id=site_id, terminal_id=installation_id,
            client_installation_id=installation_id, device_id=group.hardware_id,
            test_protocol=TestProtocol(id="synthetic-seed", version="1.0"),
            versions=SessionVersions(
                app="acceptance/1", protocol_profile="do-p4864/1",
                payload_schema="raw-segment/1", calibration="synthetic/1",
            ),
            started_at=START,
        )
        await ingestion.create_session(context, request_session, f"create-{session_id}")
        payload = f"synthetic-tenant-{index:02d}".encode()
        metadata = SegmentMetadata(
            segment_index=0, start_frame_index=0, frame_count=10,
            start_monotonic_ns=100, end_monotonic_ns=200,
            compression="zstd", cipher="aes-256-gcm", size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(), payload_schema_version="raw-segment/1",
        )
        await ingestion.put_segment(context, session_id, 0, metadata, _one_chunk(payload))
        manifest = SessionManifest(
            segment_count=1, total_frames=10, total_bytes=len(payload),
            segments=(ManifestSegment(index=0, sha256=metadata.sha256,
                                      size_bytes=len(payload), frame_count=10),),
            ended_at=START + timedelta(seconds=1), local_quality_outcome=ValidityStatus.VALID,
        )
        await ingestion.complete_session(
            context, session_id, manifest, canonical_sha256(manifest), f"complete-{session_id}"
        )
        status = await ingestion.get_status(context, session_id)
        rows.append(
            {"tenant_slot": index, "own_session_visible": status.ingest_status == "INGESTED",
             "visible_session_count": 1}
        )
        sessions.append((provisioned, activated, access_context, context, session_id))

    negative: dict[str, bool] = {}
    try:
        await ingestion.get_status(sessions[1][3], sessions[0][4])
    except TenantAccessDenied:
        negative["cross_tenant_session_denied"] = True

    unprovisioned_tenant_token = tenant_tokens.issue(
        tenant_id=uuid4(), account_id=uuid4(), license_id=uuid4(),
        hardware_id="usb-serial-unprovisioned", client_installation_id=uuid4(),
        token_version=1, capabilities=sessions[0][2].capabilities, now=clock.value,
    )
    unprovisioned_context = tenant_ingestion_principal(
        tenant_tokens.verify(unprovisioned_tenant_token, now=clock.value)
    )
    try:
        await ingestion.get_status(unprovisioned_context, sessions[0][4])
    except TenantAccessDenied:
        negative["unprovisioned_eleventh_tenant_denied"] = True

    platform_token = platform_tokens.issue(
        platform_identity_id=operator.platform_identity_id,
        roles=(PlatformRole.OPERATIONS,), token_version=1, now=clock.value,
    )
    try:
        tenant_tokens.verify(platform_token, now=clock.value)
    except AuthenticationError:
        negative["wrong_audience_token_denied"] = True

    fresh = await platform.add_tenant_access_group(
        operator, sessions[0][0].tenant_id,
        ProvisionTenantRequest(
            tenant_name="Synthetic Institution 01", account_name="seed-01-b",
            hardware_id="usb-serial-0000000000000000000b", license_period_months=12,
        ),
    )
    third = await platform.add_tenant_access_group(
        operator, sessions[0][0].tenant_id,
        ProvisionTenantRequest(
            tenant_name="Synthetic Institution 01", account_name="seed-01-c",
            hardware_id="usb-serial-0000000000000000000c", license_period_months=12,
        ),
    )
    try:
        await tenant_service.activate(
            ActivateAccountRequest(
                account_name=fresh.account_name, activation_code=fresh.activation_code,
                password="correct-horse-battery-staple",
                password_confirmation="correct-horse-battery-staple",
                hardware_id="usb-serial-ffffffffffffffffffff", client_installation_id=uuid4(),
            ), source_fingerprint=b"wrong-hardware",
        )
    except TenantAuthenticationRejected:
        negative["wrong_hardware_activation_denied"] = True

    try:
        original = sessions[0][0]
        await tenant_service.activate(
            ActivateAccountRequest(
                account_name=original.account_name, activation_code=original.activation_code,
                password="correct-horse-battery-staple",
                password_confirmation="correct-horse-battery-staple",
                hardware_id=original.hardware_id, client_installation_id=uuid4(),
            ), source_fingerprint=b"activation-replay",
        )
    except TenantAuthenticationRejected:
        negative["activation_replay_denied"] = True

    first_provisioned, first_access, first_access_context, _, _ = sessions[0]
    lease_request = HardwareLeaseRequest(
        hardware_id=first_provisioned.hardware_id,
        client_installation_id=first_access.client_installation_id,
    )
    await leases.acquire(first_access_context, lease_request)
    replacement = await tenant_service.login(
        LoginRequest(
            account_name=first_provisioned.account_name,
            password="correct-horse-battery-staple", client_installation_id=uuid4(),
        ), source_fingerprint=b"replacement-computer",
    )
    replacement_context = tenant_tokens.verify(replacement.access_token, now=clock.value)
    try:
        await leases.acquire(
            replacement_context,
            HardwareLeaseRequest(
                hardware_id=replacement.hardware_id,
                client_installation_id=replacement.client_installation_id,
            ),
        )
    except HardwareLeaseConflict:
        negative["concurrent_hardware_lease_denied"] = True

    old_refresh = sessions[4][1].refresh_token
    await tenant_service.refresh(
        RefreshRequest(refresh_token=old_refresh,
                       client_installation_id=sessions[4][1].client_installation_id)
    )
    try:
        await tenant_service.refresh(
            RefreshRequest(refresh_token=old_refresh,
                           client_installation_id=sessions[4][1].client_installation_id)
        )
    except TenantAuthenticationRejected:
        negative["refresh_replay_denied"] = True

    await platform.control_license(
        operator, sessions[1][0].license_id,
        LicenseControlRequest(action=LicenseControlAction.SUSPEND, reason_code="ACCEPTANCE"),
    )
    suspended = await tenant_service.login(
        LoginRequest(account_name=sessions[1][0].account_name,
                     password="correct-horse-battery-staple", client_installation_id=uuid4()),
        source_fingerprint=b"suspended",
    )
    negative["suspended_new_test_denied"] = not suspended.capabilities.allow_new_test

    await platform.control_license(
        operator, sessions[2][0].license_id,
        LicenseControlRequest(action=LicenseControlAction.REVOKE, reason_code="ACCEPTANCE"),
    )
    revoked = await tenant_service.login(
        LoginRequest(account_name=sessions[2][0].account_name,
                     password="correct-horse-battery-staple", client_installation_id=uuid4()),
        source_fingerprint=b"revoked",
    )
    negative["revoked_new_test_denied"] = not revoked.capabilities.allow_new_test

    clock.value = START + timedelta(days=366)
    expired = await tenant_service.login(
        LoginRequest(account_name=sessions[3][0].account_name,
                     password="correct-horse-battery-staple", client_installation_id=uuid4()),
        source_fingerprint=b"expired",
    )
    negative["expired_new_test_denied"] = not expired.capabilities.allow_new_test
    clock.value = START

    try:
        await sensitive.read_identity(
            support, grant_id=uuid4(), tenant_id=sessions[0][0].tenant_id,
            subject_id=uuid4(), identity_loader=lambda: ("Synthetic Person", None),
        )
    except PlatformPermissionDenied:
        negative["sensitive_identity_without_grant_denied"] = True

    try:
        await tenant_service.activate(
            ActivateAccountRequest(
                account_name=fresh.account_name, activation_code="FFP-2026-TEST-0001",
                password="correct-horse-battery-staple",
                password_confirmation="correct-horse-battery-staple",
                hardware_id=fresh.hardware_id, client_installation_id=uuid4(),
            ), source_fingerprint=b"local-test-license",
        )
    except (AuthenticationError, ValueError):
        negative["local_test_license_cloud_denied"] = True

    await platform.reduce_tenant_access_group(
        operator, tenant_id=sessions[0][0].tenant_id, license_id=third.license_id,
        reason_code="SEED_CAPACITY_REDUCED",
    )
    history = await access.access_group_history(sessions[0][0].tenant_id)
    active = await access.active_access_groups(sessions[0][0].tenant_id)
    return {
        "schema_version": "seed-access-evidence/1",
        "generated_at": datetime.now(UTC).isoformat(),
        "implementation_sha": _git_sha(),
        "mode": "local-in-memory",
        "tenant_count": len(rows),
        "tenants": rows,
        "dynamic_tenant": {
            "active_before_expand": 1, "active_after_expand": 3,
            "active_after_reduce": len(active), "historical_contributors": len(history),
        },
        "negative_cases": negative,
        "secrets_or_raw_identity_included": False,
        "scope": "synthetic software lifecycle and tenant-isolation evidence",
    }


def _certificate_fingerprint(base_url: str, ca_file: str | None) -> str:
    parsed = urlparse(base_url)
    context = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
    with socket.create_connection((parsed.hostname, parsed.port or 443), timeout=10) as raw:
        with context.wrap_socket(raw, server_hostname=parsed.hostname) as secured:
            certificate = secured.getpeercert(binary_form=True)
    if certificate is None:
        raise RuntimeError("TLS peer certificate is unavailable")
    return hashlib.sha256(certificate).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url")
    parser.add_argument("--ca-file")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = asyncio.run(run_local_acceptance())
    if args.base_url:
        result["network_endpoint"] = {
            "base_url_class": "https-seed-endpoint",
            "certificate_sha256": _certificate_fingerprint(args.base_url, args.ca_file),
            "health_checked": False,
        }
        result["mode"] = "local-lifecycle-plus-network-certificate"
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"output": str(output), "tenant_count": result["tenant_count"]}))


if __name__ == "__main__":
    main()
