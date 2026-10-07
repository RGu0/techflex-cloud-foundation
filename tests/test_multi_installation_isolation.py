"""Public primitive compatibility, not institution HTTP/seat-policy acceptance."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from techflex_cloud_foundation import (
    ClientInstallation,
    DeviceIdentityClaim,
    DeviceTrustAccessDenied,
    DeviceTrustService,
    HardwareLeaseService,
    IamRealm,
    IamSessionRefused,
    IamSessionReplayed,
    InMemoryDeviceTrustStore,
    InMemoryRefreshSessionStore,
    PhysicalDeviceIdentity,
    RefreshSessionService,
)

NOW = datetime(2026, 10, 7, tzinfo=UTC)


class _NoAttestation:
    def attest(
        self, claim: DeviceIdentityClaim, *, now: datetime
    ) -> PhysicalDeviceIdentity | None:
        return None


class _NoDeviceBinding:
    def allows(self, installation: ClientInstallation, identity: PhysicalDeviceIdentity) -> bool:
        return False


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_three_installations_rotate_and_revoke_independently_with_tenant_guards() -> None:
    store = InMemoryDeviceTrustStore()
    service = DeviceTrustService(
        store, attestation=_NoAttestation(), combination_policy=_NoDeviceBinding(),
        supported_claim_versions=frozenset({"device-claim/1"}),
    )
    registrations = []
    for platform, old, new in [
        ("ios", "11" * 32, "44" * 32),
        ("android", "22" * 32, "55" * 32),
        ("ios", "33" * 32, "66" * 32),
    ]:
        installation, _ = await service.register_installation(
            tenant_id="institution-a", platform_hint=platform,
            secret_fingerprint=old, now=NOW,
        )
        registrations.append((installation, old, new))
    assert len({installation.installation_id for installation, _, _ in registrations}) == 3
    for installation, old, new in registrations:
        await service.rotate_credential(
            installation_id=installation.installation_id, current_secret_fingerprint=old,
            new_secret_fingerprint=new, now=NOW,
        )
        with pytest.raises(DeviceTrustAccessDenied):
            await service.authenticate(
                installation_id=installation.installation_id, secret_fingerprint=old, now=NOW,
            )
        principal = await service.authenticate(
            installation_id=installation.installation_id, secret_fingerprint=new, now=NOW,
        )
        assert principal.tenant_id == "institution-a" and principal.credential_version == 2
    revoked, _, revoked_secret = registrations[1]
    await service.revoke_credential(installation_id=revoked.installation_id, now=NOW)
    with pytest.raises(DeviceTrustAccessDenied):
        await service.authenticate(
            installation_id=revoked.installation_id, secret_fingerprint=revoked_secret, now=NOW,
        )
    survivors = []
    for installation, _, secret in (registrations[0], registrations[2]):
        survivors.append(await service.authenticate(
            installation_id=installation.installation_id, secret_fingerprint=secret, now=NOW,
        ))
    outsider, _ = await service.register_installation(
        tenant_id="institution-b", platform_hint="android",
        secret_fingerprint="77" * 32, now=NOW,
    )
    outsider_principal = await service.authenticate(
        installation_id=outsider.installation_id, secret_fingerprint="77" * 32, now=NOW,
    )
    leases = HardwareLeaseService(store, lease_ttl=timedelta(minutes=10))
    lease = await leases.acquire(survivors[0], asset_id="instrument-a", now=NOW)
    with pytest.raises(DeviceTrustAccessDenied):
        await leases.renew(outsider_principal, lease.lease_id, now=NOW)
    with pytest.raises(DeviceTrustAccessDenied):
        await leases.release(outsider_principal, lease.lease_id, now=NOW)
    renewed = await leases.renew(survivors[0], lease.lease_id, now=NOW)
    assert renewed.installation_id == survivors[0].installation_id


@pytest.mark.parametrize("disposition", ["revoke", "replay"])
def test_three_refresh_families_isolate_rotation_revocation_and_replay(disposition: str) -> None:
    service = RefreshSessionService(InMemoryRefreshSessionStore(), lifetime_seconds=3600)
    first = [service.issue(
        realm=IamRealm.TENANT, subject_id="institution-account", tenant_id="institution-a", now=NOW,
    ) for _ in range(3)]
    assert len({session.family_id for session, _ in first}) == 3
    successors = [service.rotate(raw, realm=IamRealm.TENANT, now=NOW) for _, raw in first]
    for (original, _), (successor, _) in zip(first, successors, strict=True):
        assert successor.family_id == original.family_id
        assert successor.tenant_id == "institution-a"
    outsider, outsider_raw = service.issue(
        realm=IamRealm.TENANT, subject_id="other-account", tenant_id="institution-b", now=NOW,
    )
    if disposition == "revoke":
        service.revoke_family(successors[1][0].family_id)
    else:
        with pytest.raises(IamSessionReplayed):
            service.rotate(first[1][1], realm=IamRealm.TENANT, now=NOW)
    with pytest.raises(IamSessionRefused):
        service.rotate(successors[1][1], realm=IamRealm.TENANT, now=NOW)
    for index in (0, 2):
        current, _ = service.rotate(successors[index][1], realm=IamRealm.TENANT, now=NOW)
        assert current.family_id == first[index][0].family_id
        assert current.tenant_id == "institution-a"
    current_outsider, _ = service.rotate(outsider_raw, realm=IamRealm.TENANT, now=NOW)
    assert current_outsider.family_id == outsider.family_id
    assert current_outsider.tenant_id == "institution-b"
