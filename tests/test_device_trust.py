from __future__ import annotations

from dataclasses import fields
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from techflex_cloud_foundation import (
    ClientInstallation,
    DeviceAttestationProvider,
    DeviceBinding,
    DeviceCombinationPolicy,
    DeviceIdentityClaim,
    DeviceTrustAccessDenied,
    DeviceTrustConflict,
    DeviceTrustMalformed,
    DeviceTrustService,
    DeviceTrustStateError,
    DeviceTrustVersionUnsupported,
    HardwareLeaseService,
    HeartbeatSummary,
    InMemoryDeviceTrustStore,
    InstallationPrincipal,
    LeaseState,
    PhysicalDeviceIdentity,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


NOW = datetime(2026, 9, 6, tzinfo=UTC)
TTL = timedelta(minutes=10)
CLAIM_VERSION = "device-claim/1"
FINGERPRINT_A = "aa" * 32
FINGERPRINT_B = "bb" * 32


class RejectingAttestation:
    """The claim proves nothing; platform hints alone never bind."""

    def attest(
        self, claim: DeviceIdentityClaim, *, now: datetime
    ) -> PhysicalDeviceIdentity | None:
        return None


class EchoAttestation:
    """A dishonest provider that echoes the platform UUID as the identity."""

    def attest(
        self, claim: DeviceIdentityClaim, *, now: datetime
    ) -> PhysicalDeviceIdentity | None:
        assert claim.platform_uuid is not None
        return PhysicalDeviceIdentity(
            stable_identity=claim.platform_uuid, proof_reference="proof-echo"
        )


class FixedAttestation:
    def attest(
        self, claim: DeviceIdentityClaim, *, now: datetime
    ) -> PhysicalDeviceIdentity | None:
        return PhysicalDeviceIdentity(
            stable_identity="physical-device-0001", proof_reference="attestation-1"
        )


class AllowAllCombinations:
    def allows(
        self, installation: ClientInstallation, identity: PhysicalDeviceIdentity
    ) -> bool:
        return True


class RefusingCombinations:
    def allows(
        self, installation: ClientInstallation, identity: PhysicalDeviceIdentity
    ) -> bool:
        return False


def _service(
    store: InMemoryDeviceTrustStore | None = None,
    attestation: DeviceAttestationProvider | None = None,
    policy: DeviceCombinationPolicy | None = None,
) -> DeviceTrustService:
    return DeviceTrustService(
        store or InMemoryDeviceTrustStore(),
        attestation=attestation or FixedAttestation(),
        combination_policy=policy or AllowAllCombinations(),
        supported_claim_versions=frozenset({CLAIM_VERSION}),
    )


def _stack() -> tuple[DeviceTrustService, HardwareLeaseService]:
    store = InMemoryDeviceTrustStore()
    return _service(store=store), HardwareLeaseService(store, lease_ttl=TTL)


async def _registered(
    service: DeviceTrustService, *, tenant_id: str = "tenant-a"
) -> tuple[ClientInstallation, str]:
    installation, _ = await service.register_installation(
        tenant_id=tenant_id,
        platform_hint="platform-hint-1",
        secret_fingerprint=FINGERPRINT_A,
        now=NOW,
    )
    return installation, FINGERPRINT_A


def _principal(installation: ClientInstallation) -> InstallationPrincipal:
    return InstallationPrincipal(
        installation_id=installation.installation_id,
        tenant_id=installation.tenant_id,
        credential_version=1,
    )


async def test_register_and_authenticate() -> None:
    service = _service()
    installation, fingerprint = await _registered(service)
    principal = await service.authenticate(
        installation_id=installation.installation_id,
        secret_fingerprint=fingerprint,
        now=NOW,
    )
    assert principal.installation_id == installation.installation_id
    assert principal.tenant_id == "tenant-a"
    assert principal.credential_version == 1


async def test_authenticate_refuses_wrong_or_unknown_with_one_message() -> None:
    service = _service()
    installation, _ = await _registered(service)
    with pytest.raises(DeviceTrustAccessDenied, match="installation credential refused"):
        await service.authenticate(
            installation_id=installation.installation_id,
            secret_fingerprint=FINGERPRINT_B,
            now=NOW,
        )
    with pytest.raises(DeviceTrustAccessDenied, match="installation credential refused"):
        await service.authenticate(
            installation_id=uuid4(), secret_fingerprint=FINGERPRINT_A, now=NOW
        )


async def test_rotation_refuses_old_credential() -> None:
    service = _service()
    installation, old_fingerprint = await _registered(service)
    rotated = await service.rotate_credential(
        installation_id=installation.installation_id,
        current_secret_fingerprint=old_fingerprint,
        new_secret_fingerprint=FINGERPRINT_B,
        now=NOW + timedelta(minutes=1),
    )
    assert rotated.version == 2
    with pytest.raises(DeviceTrustAccessDenied):
        await service.authenticate(
            installation_id=installation.installation_id,
            secret_fingerprint=old_fingerprint,
            now=NOW + timedelta(minutes=2),
        )
    principal = await service.authenticate(
        installation_id=installation.installation_id,
        secret_fingerprint=FINGERPRINT_B,
        now=NOW + timedelta(minutes=2),
    )
    assert principal.credential_version == 2


async def test_rotation_must_change_the_fingerprint() -> None:
    service = _service()
    installation, fingerprint = await _registered(service)
    with pytest.raises(DeviceTrustMalformed, match="rotation must change"):
        await service.rotate_credential(
            installation_id=installation.installation_id,
            current_secret_fingerprint=fingerprint,
            new_secret_fingerprint=fingerprint,
            now=NOW,
        )


async def test_rotation_requires_the_current_credential() -> None:
    service = _service()
    installation, _ = await _registered(service)
    with pytest.raises(DeviceTrustAccessDenied):
        await service.rotate_credential(
            installation_id=installation.installation_id,
            current_secret_fingerprint=FINGERPRINT_B,
            new_secret_fingerprint="cc" * 32,
            now=NOW,
        )


async def test_revocation_is_immediate() -> None:
    service = _service()
    installation, fingerprint = await _registered(service)
    revoked = await service.revoke_credential(
        installation_id=installation.installation_id, now=NOW
    )
    assert revoked.revoked_at == NOW
    with pytest.raises(DeviceTrustAccessDenied):
        await service.authenticate(
            installation_id=installation.installation_id,
            secret_fingerprint=fingerprint,
            now=NOW,
        )
    with pytest.raises(DeviceTrustAccessDenied):
        await service.revoke_credential(
            installation_id=installation.installation_id, now=NOW
        )


async def test_concurrent_lease_is_refused() -> None:
    service, leases = _stack()
    installation, _ = await _registered(service)
    other, _ = await _registered(service, tenant_id="tenant-b")
    await leases.acquire(_principal(installation), asset_id="asset-1", now=NOW)
    with pytest.raises(DeviceTrustConflict, match="effective lease"):
        await leases.acquire(_principal(other), asset_id="asset-1", now=NOW)
    second = await leases.acquire(_principal(other), asset_id="asset-2", now=NOW)
    assert second.asset_id == "asset-2"


async def test_expired_lease_frees_the_asset() -> None:
    service, leases = _stack()
    installation, _ = await _registered(service)
    await leases.acquire(_principal(installation), asset_id="asset-1", now=NOW)
    after_expiry = NOW + TTL
    renewed = await leases.acquire(
        _principal(installation), asset_id="asset-1", now=after_expiry
    )
    assert renewed.expires_at == after_expiry + TTL


async def test_renew_extends_and_expired_renew_is_refused() -> None:
    service, leases = _stack()
    installation, _ = await _registered(service)
    lease = await leases.acquire(_principal(installation), asset_id="asset-1", now=NOW)
    renewed = await leases.renew(
        _principal(installation), lease.lease_id, now=NOW + timedelta(minutes=4)
    )
    assert renewed.renewed_at == NOW + timedelta(minutes=4)
    assert renewed.expires_at == NOW + timedelta(minutes=4) + TTL
    with pytest.raises(DeviceTrustStateError, match="expired"):
        await leases.renew(
            _principal(installation),
            lease.lease_id,
            now=renewed.expires_at + timedelta(seconds=1),
        )


async def test_release_is_terminal_and_frees_the_asset() -> None:
    service, leases = _stack()
    installation, _ = await _registered(service)
    other, _ = await _registered(service, tenant_id="tenant-b")
    lease = await leases.acquire(_principal(installation), asset_id="asset-1", now=NOW)
    released = await leases.release(
        _principal(installation), lease.lease_id, now=NOW + timedelta(minutes=1)
    )
    assert released.state is LeaseState.RELEASED
    with pytest.raises(DeviceTrustStateError, match="terminal"):
        await leases.renew(
            _principal(installation), lease.lease_id, now=NOW + timedelta(minutes=2)
        )
    with pytest.raises(DeviceTrustStateError, match="terminal"):
        await leases.release(
            _principal(installation), lease.lease_id, now=NOW + timedelta(minutes=2)
        )
    takeover = await leases.acquire(
        _principal(other), asset_id="asset-1", now=NOW + timedelta(minutes=2)
    )
    assert takeover.installation_id == other.installation_id


async def test_lease_only_moves_for_its_holder() -> None:
    service, leases = _stack()
    installation, _ = await _registered(service)
    other, _ = await _registered(service, tenant_id="tenant-b")
    lease = await leases.acquire(_principal(installation), asset_id="asset-1", now=NOW)
    with pytest.raises(DeviceTrustAccessDenied):
        await leases.renew(_principal(other), lease.lease_id, now=NOW)
    with pytest.raises(DeviceTrustAccessDenied):
        await leases.release(_principal(other), lease.lease_id, now=NOW)


def test_installation_never_owns_a_license() -> None:
    field_names = {field.name for field in fields(ClientInstallation)}
    assert not any("license" in name for name in field_names)
    with pytest.raises(TypeError):
        ClientInstallation(  # type: ignore[call-arg]
            installation_id=uuid4(),
            tenant_id="tenant-a",
            platform_hint="hint",
            registered_at=NOW,
            license_id=uuid4(),
        )


async def test_platform_uuid_alone_cannot_bind() -> None:
    service = _service(attestation=RejectingAttestation())
    installation, _ = await _registered(service)
    claim = DeviceIdentityClaim(
        claim_version=CLAIM_VERSION, platform_uuid="platform-uuid-1", rssi_dbm=-42
    )
    with pytest.raises(DeviceTrustAccessDenied, match="attestation is required"):
        await service.bind_device(_principal(installation), claim, now=NOW)


async def test_attestation_echoing_platform_uuid_is_refused() -> None:
    service = _service(attestation=EchoAttestation())
    installation, _ = await _registered(service)
    claim = DeviceIdentityClaim(
        claim_version=CLAIM_VERSION, platform_uuid="platform-uuid-1"
    )
    with pytest.raises(DeviceTrustAccessDenied, match="echoes the platform UUID"):
        await service.bind_device(_principal(installation), claim, now=NOW)


async def test_binding_records_attested_identity() -> None:
    service = _service()
    installation, _ = await _registered(service)
    claim = DeviceIdentityClaim(
        claim_version=CLAIM_VERSION, platform_uuid="platform-uuid-1", rssi_dbm=-42
    )
    binding = await service.bind_device(_principal(installation), claim, now=NOW)
    assert isinstance(binding, DeviceBinding)
    assert binding.installation_id == installation.installation_id
    assert binding.stable_identity == "physical-device-0001"
    assert binding.stable_identity != claim.platform_uuid


async def test_unknown_claim_version_is_refused() -> None:
    service = _service()
    installation, _ = await _registered(service)
    claim = DeviceIdentityClaim(claim_version="device-claim/99")
    with pytest.raises(DeviceTrustVersionUnsupported):
        await service.bind_device(_principal(installation), claim, now=NOW)


async def test_combination_policy_may_refuse() -> None:
    service = _service(policy=RefusingCombinations())
    installation, _ = await _registered(service)
    claim = DeviceIdentityClaim(claim_version=CLAIM_VERSION)
    with pytest.raises(DeviceTrustAccessDenied, match="combination policy"):
        await service.bind_device(_principal(installation), claim, now=NOW)


async def test_heartbeat_summary_carries_no_sensitive_fields() -> None:
    service = _service()
    installation, _ = await _registered(service)
    await service.record_heartbeat(
        _principal(installation),
        declared_client_version="1.2.0",
        declared_schema_version="schema/3",
        now=NOW,
    )
    summary = await service.heartbeat_summary(installation.installation_id)
    assert summary.heartbeat_count == 1
    assert summary.declared_client_version == "1.2.0"
    summary_field_names = {field.name for field in fields(HeartbeatSummary)}
    assert not any("fingerprint" in name for name in summary_field_names)
    assert not any("platform" in name for name in summary_field_names)
    rendered = repr(summary)
    assert FINGERPRINT_A not in rendered
    assert installation.platform_hint not in rendered


async def test_version_status_directory_is_queryable() -> None:
    service = _service()
    first, _ = await _registered(service)
    second, _ = await _registered(service, tenant_id="tenant-b")
    await service.record_heartbeat(
        _principal(first),
        declared_client_version="1.2.0",
        declared_schema_version="schema/3",
        now=NOW,
    )
    directory = await service.version_status_directory()
    assert {entry.installation_id for entry in directory} == {
        first.installation_id,
        second.installation_id,
    }
    by_id = {entry.installation_id: entry for entry in directory}
    assert by_id[first.installation_id].declared_client_version == "1.2.0"
    assert by_id[second.installation_id].heartbeat_count == 0
    assert by_id[second.installation_id].last_received_at is None


async def test_entities_register_separately() -> None:
    service = _service()
    terminal = await service.register_terminal(
        tenant_id="tenant-a", site_id="site-1", label="front desk"
    )
    device = await service.register_measurement_device(
        tenant_id="tenant-a", model="plate-x", serial_hint="sn-1"
    )
    installation, _ = await _registered(service)
    ids = {terminal.terminal_id, device.device_id, installation.installation_id}
    assert len(ids) == 3
