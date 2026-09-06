"""Client installation trust, hardware leases, and device binding (CP-05).

The device-trust plane keeps three entities deliberately separate: a
`ClientInstallation` is one installed software instance, a `Terminal` is an
operator-facing station, and a `MeasurementDevice` is a physical instrument.
An installation never owns a License — entitlement facts live in
``entitlement`` and are only ever referenced by product policy, never held
here.

Invariants carried over from the reference implementations:

- Credentials are versioned and only their fingerprints are stored, never
  the secrets; rotation refuses the previous version immediately, and
  revocation takes effect the moment it is recorded.
- An asset holds at most one effective hardware lease at any moment;
  concurrent acquisition is refused.  Every lease expires, and time is
  always injected as ``now``.
- Heartbeat summaries carry no sensitive fields: no credential material and
  no platform-reported identifiers.
- A platform UUID or RSSI reading is an advisory hint, never a physical
  identity; a device binding exists only through product-injected
  attestation, and an attestation that merely echoes the platform UUID is
  refused.
- Device recognition, calibration, and allowed-combination rules are
  injected product policy; the foundation hosts the binding records and the
  validation skeleton only.  Unknown claim versions are refused, never
  guessed.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
import hmac
import re
from typing import Protocol
from uuid import UUID, uuid4

_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}")

_CREDENTIAL_REFUSED = "installation credential refused"


class DeviceTrustError(Exception):
    """Base class for device-trust plane failures."""


class DeviceTrustMalformed(DeviceTrustError):
    """A request, record, or claim is structurally invalid."""


class DeviceTrustVersionUnsupported(DeviceTrustError):
    """A device identity claim declares a version this deployment refuses."""


class DeviceTrustAccessDenied(DeviceTrustError):
    """The credential, attestation, or product policy refuses this operation."""


class DeviceTrustConflict(DeviceTrustError):
    """A uniqueness or single-lease invariant would be violated."""


class DeviceTrustStateError(DeviceTrustError):
    """The entity or lease state does not allow this operation."""


def _require_text(value: str, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise DeviceTrustMalformed(f"{field_name} must be non-empty text")
    return value


def _require_aware(value: datetime, *, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise DeviceTrustMalformed(f"{field_name} must be a timezone-aware datetime")


def _require_fingerprint(value: str, *, field_name: str = "credential fingerprint") -> str:
    if not isinstance(value, str) or not _FINGERPRINT_RE.fullmatch(value):
        raise DeviceTrustMalformed(
            f"{field_name} must be a complete lowercase hex SHA-256 digest of the "
            "secret; the secret itself is never stored or accepted"
        )
    return value


@dataclass(frozen=True)
class ClientInstallation:
    """One installed software instance; it never owns a License.

    ``platform_hint`` is whatever the host platform reported at registration
    (a UUID, a hostname-derived value, ...).  It is advisory only and never
    serves as the identity of a physical device — see `bind_device`.
    """

    installation_id: UUID
    tenant_id: str
    platform_hint: str
    registered_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.platform_hint, field_name="platform hint")
        _require_aware(self.registered_at, field_name="registered_at")


@dataclass(frozen=True)
class Terminal:
    """One operator-facing station; distinct from installations and devices."""

    terminal_id: UUID
    tenant_id: str
    site_id: str
    label: str

    def __post_init__(self) -> None:
        if not isinstance(self.terminal_id, UUID):
            raise DeviceTrustMalformed("terminal_id must be a UUID")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.site_id, field_name="site id")
        _require_text(self.label, field_name="terminal label")


@dataclass(frozen=True)
class MeasurementDevice:
    """One physical instrument; distinct from installations and terminals."""

    device_id: UUID
    tenant_id: str
    model: str
    serial_hint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, UUID):
            raise DeviceTrustMalformed("device_id must be a UUID")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.model, field_name="device model")
        if self.serial_hint is not None:
            _require_text(self.serial_hint, field_name="serial hint")


@dataclass(frozen=True)
class InstallationCredential:
    """One credential version for an installation; only the fingerprint is held."""

    installation_id: UUID
    version: int
    secret_fingerprint: str
    issued_at: datetime
    revoked_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        if (
            not isinstance(self.version, int)
            or isinstance(self.version, bool)
            or self.version < 1
        ):
            raise DeviceTrustMalformed("credential version must be a positive integer")
        _require_fingerprint(self.secret_fingerprint)
        _require_aware(self.issued_at, field_name="issued_at")
        if self.revoked_at is not None:
            _require_aware(self.revoked_at, field_name="revoked_at")


@dataclass(frozen=True)
class InstallationPrincipal:
    """An authenticated installation, carrying the credential version it used."""

    installation_id: UUID
    tenant_id: str
    credential_version: int

    def __post_init__(self) -> None:
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        _require_text(self.tenant_id, field_name="tenant id")
        if (
            not isinstance(self.credential_version, int)
            or isinstance(self.credential_version, bool)
            or self.credential_version < 1
        ):
            raise DeviceTrustMalformed("credential_version must be a positive integer")


@dataclass(frozen=True)
class DeviceIdentityClaim:
    """Advisory platform-reported hints about a device; never an identity."""

    claim_version: str
    platform_uuid: str | None = None
    rssi_dbm: int | None = None

    def __post_init__(self) -> None:
        _require_text(self.claim_version, field_name="claim version")
        if self.platform_uuid is not None:
            _require_text(self.platform_uuid, field_name="platform uuid")
        if self.rssi_dbm is not None and (
            not isinstance(self.rssi_dbm, int) or isinstance(self.rssi_dbm, bool)
        ):
            raise DeviceTrustMalformed("rssi_dbm must be an integer")


@dataclass(frozen=True)
class PhysicalDeviceIdentity:
    """A product-attested stable identity; the foundation treats it as opaque."""

    stable_identity: str
    proof_reference: str

    def __post_init__(self) -> None:
        _require_text(self.stable_identity, field_name="stable identity")
        _require_text(self.proof_reference, field_name="proof reference")


class DeviceAttestationProvider(Protocol):
    """Product-injected proof that a claim belongs to a physical device."""

    def attest(
        self, claim: DeviceIdentityClaim, *, now: datetime
    ) -> PhysicalDeviceIdentity | None:
        """Return the attested identity, or ``None`` when the claim proves nothing."""
        ...


class DeviceCombinationPolicy(Protocol):
    """Product rules for which device may bind which installation."""

    def allows(
        self, installation: ClientInstallation, identity: PhysicalDeviceIdentity
    ) -> bool:
        """Whether this installation may bind a device with this identity."""
        ...


@dataclass(frozen=True)
class DeviceBinding:
    """The record that one installation is bound to one attested physical device."""

    binding_id: UUID
    installation_id: UUID
    stable_identity: str
    proof_reference: str
    bound_at: datetime

    def __post_init__(self) -> None:
        if not isinstance(self.binding_id, UUID):
            raise DeviceTrustMalformed("binding_id must be a UUID")
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        _require_text(self.stable_identity, field_name="stable identity")
        _require_text(self.proof_reference, field_name="proof reference")
        _require_aware(self.bound_at, field_name="bound_at")


@dataclass(frozen=True)
class HeartbeatRecord:
    """One authenticated heartbeat: when it arrived and what versions it declared."""

    installation_id: UUID
    received_at: datetime
    declared_client_version: str
    declared_schema_version: str

    def __post_init__(self) -> None:
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        _require_aware(self.received_at, field_name="received_at")
        _require_text(self.declared_client_version, field_name="declared client version")
        _require_text(self.declared_schema_version, field_name="declared schema version")


@dataclass(frozen=True)
class HeartbeatSummary:
    """The queryable roll-up of heartbeats; it carries no sensitive fields.

    Deliberately absent: credential material, credential versions, and the
    platform hint — a summary that exposed them would turn a status directory
    into an enumeration source.
    """

    installation_id: UUID
    heartbeat_count: int
    last_received_at: datetime | None
    declared_client_version: str | None
    declared_schema_version: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        if (
            not isinstance(self.heartbeat_count, int)
            or isinstance(self.heartbeat_count, bool)
            or self.heartbeat_count < 0
        ):
            raise DeviceTrustMalformed("heartbeat_count must be a non-negative integer")
        if self.last_received_at is not None:
            _require_aware(self.last_received_at, field_name="last_received_at")
        if self.heartbeat_count == 0 and self.last_received_at is not None:
            raise DeviceTrustMalformed(
                "a summary with no heartbeats cannot name a last reception"
            )


class LeaseState(StrEnum):
    ACTIVE = "active"
    RELEASED = "released"


@dataclass(frozen=True)
class HardwareLease:
    """One short-lived lease binding an installation to one asset.

    The state machine has exactly two states: ACTIVE leases can be renewed or
    released; RELEASED is terminal.  Expiry is derived from ``expires_at``
    against injected time — an expired lease is never renewed, and the asset
    becomes leasable again.
    """

    lease_id: UUID
    asset_id: str
    installation_id: UUID
    state: LeaseState
    acquired_at: datetime
    renewed_at: datetime
    expires_at: datetime
    released_at: datetime | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.lease_id, UUID):
            raise DeviceTrustMalformed("lease_id must be a UUID")
        _require_text(self.asset_id, field_name="asset id")
        if not isinstance(self.installation_id, UUID):
            raise DeviceTrustMalformed("installation_id must be a UUID")
        if not isinstance(self.state, LeaseState):
            raise DeviceTrustMalformed("lease state must be a LeaseState")
        _require_aware(self.acquired_at, field_name="acquired_at")
        _require_aware(self.renewed_at, field_name="renewed_at")
        _require_aware(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.acquired_at:
            raise DeviceTrustMalformed("a lease must expire after it was acquired")
        if self.renewed_at < self.acquired_at:
            raise DeviceTrustMalformed("a lease cannot be renewed before it was acquired")
        if self.state is LeaseState.RELEASED:
            if self.released_at is None:
                raise DeviceTrustMalformed("a released lease must record when")
            _require_aware(self.released_at, field_name="released_at")
            if self.released_at < self.acquired_at:
                raise DeviceTrustMalformed("a lease cannot be released before acquisition")
        elif self.released_at is not None:
            raise DeviceTrustMalformed("an active lease carries no release timestamp")

    def is_effective(self, now: datetime) -> bool:
        """Whether this lease currently excludes another lease on the asset."""
        _require_aware(now, field_name="now")
        return self.state is LeaseState.ACTIVE and self.expires_at > now


class DeviceTrustStore(Protocol):
    """Persistence boundary; production binds a database, tests use memory.

    ``insert_lease`` must check-and-insert atomically: the single-effective-
    lease-per-asset invariant holds only if the check cannot interleave with
    another insertion.
    """

    async def insert_installation(self, record: ClientInstallation) -> None: ...

    async def get_installation(self, installation_id: UUID) -> ClientInstallation: ...

    async def installation_ids(self) -> tuple[UUID, ...]: ...

    async def insert_terminal(self, record: Terminal) -> None: ...

    async def insert_measurement_device(self, record: MeasurementDevice) -> None: ...

    async def insert_credential(self, credential: InstallationCredential) -> None: ...

    async def save_credential(self, credential: InstallationCredential) -> None: ...

    async def current_credential(self, installation_id: UUID) -> InstallationCredential: ...

    async def insert_lease(self, lease: HardwareLease, *, now: datetime) -> None: ...

    async def save_lease(self, lease: HardwareLease) -> None: ...

    async def get_lease(self, lease_id: UUID) -> HardwareLease: ...

    async def append_heartbeat(self, record: HeartbeatRecord) -> None: ...

    async def heartbeats(self, installation_id: UUID) -> tuple[HeartbeatRecord, ...]: ...

    async def insert_binding(self, binding: DeviceBinding) -> None: ...


class InMemoryDeviceTrustStore:
    """Volatile reference store, suitable for tests and integration runs."""

    def __init__(self) -> None:
        self._installations: dict[UUID, ClientInstallation] = {}
        self._terminals: dict[UUID, Terminal] = {}
        self._devices: dict[UUID, MeasurementDevice] = {}
        self._credentials: dict[UUID, dict[int, InstallationCredential]] = {}
        self._leases: dict[UUID, HardwareLease] = {}
        self._heartbeats: dict[UUID, list[HeartbeatRecord]] = {}
        self._bindings: list[DeviceBinding] = []

    async def insert_installation(self, record: ClientInstallation) -> None:
        if record.installation_id in self._installations:
            raise DeviceTrustConflict(
                f"installation {record.installation_id} is already registered"
            )
        self._installations[record.installation_id] = record

    async def get_installation(self, installation_id: UUID) -> ClientInstallation:
        try:
            return self._installations[installation_id]
        except KeyError:
            raise DeviceTrustMalformed(f"unknown installation {installation_id}") from None

    async def installation_ids(self) -> tuple[UUID, ...]:
        return tuple(sorted(self._installations, key=int))

    async def insert_terminal(self, record: Terminal) -> None:
        if record.terminal_id in self._terminals:
            raise DeviceTrustConflict(f"terminal {record.terminal_id} is already registered")
        self._terminals[record.terminal_id] = record

    async def insert_measurement_device(self, record: MeasurementDevice) -> None:
        if record.device_id in self._devices:
            raise DeviceTrustConflict(f"device {record.device_id} is already registered")
        self._devices[record.device_id] = record

    async def insert_credential(self, credential: InstallationCredential) -> None:
        versions = self._credentials.setdefault(credential.installation_id, {})
        if credential.version in versions:
            raise DeviceTrustConflict(
                f"credential version {credential.version} already exists for "
                f"installation {credential.installation_id}"
            )
        versions[credential.version] = credential

    async def save_credential(self, credential: InstallationCredential) -> None:
        versions = self._credentials.get(credential.installation_id, {})
        if credential.version not in versions:
            raise DeviceTrustMalformed(
                f"no credential version {credential.version} for installation "
                f"{credential.installation_id}"
            )
        versions[credential.version] = credential

    async def current_credential(self, installation_id: UUID) -> InstallationCredential:
        versions = self._credentials.get(installation_id)
        if not versions:
            raise DeviceTrustMalformed(
                f"installation {installation_id} holds no credential"
            )
        return versions[max(versions)]

    async def insert_lease(self, lease: HardwareLease, *, now: datetime) -> None:
        if lease.lease_id in self._leases:
            raise DeviceTrustConflict(f"lease {lease.lease_id} already exists")
        for existing in self._leases.values():
            if existing.asset_id == lease.asset_id and existing.is_effective(now):
                raise DeviceTrustConflict(
                    f"asset {lease.asset_id!r} already holds an effective lease; "
                    "concurrent leases on one asset are refused"
                )
        self._leases[lease.lease_id] = lease

    async def save_lease(self, lease: HardwareLease) -> None:
        if lease.lease_id not in self._leases:
            raise DeviceTrustMalformed(f"unknown lease {lease.lease_id}")
        self._leases[lease.lease_id] = lease

    async def get_lease(self, lease_id: UUID) -> HardwareLease:
        try:
            return self._leases[lease_id]
        except KeyError:
            raise DeviceTrustMalformed(f"unknown lease {lease_id}") from None

    async def append_heartbeat(self, record: HeartbeatRecord) -> None:
        self._heartbeats.setdefault(record.installation_id, []).append(record)

    async def heartbeats(self, installation_id: UUID) -> tuple[HeartbeatRecord, ...]:
        return tuple(self._heartbeats.get(installation_id, ()))

    async def insert_binding(self, binding: DeviceBinding) -> None:
        self._bindings.append(binding)


class DeviceTrustService:
    """Registration, versioned credentials, heartbeats, and device binding."""

    def __init__(
        self,
        store: DeviceTrustStore,
        *,
        attestation: DeviceAttestationProvider,
        combination_policy: DeviceCombinationPolicy,
        supported_claim_versions: frozenset[str],
    ) -> None:
        if not supported_claim_versions:
            raise DeviceTrustMalformed(
                "at least one supported claim version is required"
            )
        self._store = store
        self._attestation = attestation
        self._combination_policy = combination_policy
        self._supported_claim_versions = supported_claim_versions

    async def register_installation(
        self,
        *,
        tenant_id: str,
        platform_hint: str,
        secret_fingerprint: str,
        now: datetime,
    ) -> tuple[ClientInstallation, InstallationCredential]:
        """Register an installation and issue its first credential version.

        The installation carries no License reference; entitlement is a
        separate concern the product resolves on its own side.
        """
        _require_aware(now, field_name="now")
        installation = ClientInstallation(
            installation_id=uuid4(),
            tenant_id=tenant_id,
            platform_hint=platform_hint,
            registered_at=now,
        )
        credential = InstallationCredential(
            installation_id=installation.installation_id,
            version=1,
            secret_fingerprint=secret_fingerprint,
            issued_at=now,
        )
        await self._store.insert_installation(installation)
        await self._store.insert_credential(credential)
        return installation, credential

    async def register_terminal(
        self, *, tenant_id: str, site_id: str, label: str
    ) -> Terminal:
        terminal = Terminal(
            terminal_id=uuid4(), tenant_id=tenant_id, site_id=site_id, label=label
        )
        await self._store.insert_terminal(terminal)
        return terminal

    async def register_measurement_device(
        self, *, tenant_id: str, model: str, serial_hint: str | None = None
    ) -> MeasurementDevice:
        device = MeasurementDevice(
            device_id=uuid4(), tenant_id=tenant_id, model=model, serial_hint=serial_hint
        )
        await self._store.insert_measurement_device(device)
        return device

    async def _current_credential(
        self, installation_id: UUID, *, now: datetime
    ) -> InstallationCredential:
        try:
            credential = await self._store.current_credential(installation_id)
        except DeviceTrustMalformed as exc:
            raise DeviceTrustAccessDenied(_CREDENTIAL_REFUSED) from exc
        if credential.revoked_at is not None and credential.revoked_at <= now:
            raise DeviceTrustAccessDenied(_CREDENTIAL_REFUSED)
        return credential

    async def authenticate(
        self,
        *,
        installation_id: UUID,
        secret_fingerprint: str,
        now: datetime,
    ) -> InstallationPrincipal:
        """Authenticate against the current credential version.

        Every refusal — unknown installation, revoked credential, wrong
        fingerprint — raises the same error with the same message, so the
        boundary is not an enumeration oracle.
        """
        _require_aware(now, field_name="now")
        fingerprint = _require_fingerprint(secret_fingerprint)
        try:
            installation = await self._store.get_installation(installation_id)
        except DeviceTrustMalformed as exc:
            raise DeviceTrustAccessDenied(_CREDENTIAL_REFUSED) from exc
        credential = await self._current_credential(installation_id, now=now)
        if not hmac.compare_digest(credential.secret_fingerprint, fingerprint):
            raise DeviceTrustAccessDenied(_CREDENTIAL_REFUSED)
        return InstallationPrincipal(
            installation_id=installation.installation_id,
            tenant_id=installation.tenant_id,
            credential_version=credential.version,
        )

    async def rotate_credential(
        self,
        *,
        installation_id: UUID,
        current_secret_fingerprint: str,
        new_secret_fingerprint: str,
        now: datetime,
    ) -> InstallationCredential:
        """Replace the credential with a new version; the old one is refused at once."""
        _require_aware(now, field_name="now")
        current_fingerprint = _require_fingerprint(
            current_secret_fingerprint, field_name="current credential fingerprint"
        )
        new_fingerprint = _require_fingerprint(
            new_secret_fingerprint, field_name="new credential fingerprint"
        )
        if hmac.compare_digest(current_fingerprint, new_fingerprint):
            raise DeviceTrustMalformed("rotation must change the credential fingerprint")
        credential = await self._current_credential(installation_id, now=now)
        if not hmac.compare_digest(credential.secret_fingerprint, current_fingerprint):
            raise DeviceTrustAccessDenied(_CREDENTIAL_REFUSED)
        rotated = InstallationCredential(
            installation_id=installation_id,
            version=credential.version + 1,
            secret_fingerprint=new_fingerprint,
            issued_at=now,
        )
        await self._store.insert_credential(rotated)
        return rotated

    async def revoke_credential(
        self, *, installation_id: UUID, now: datetime
    ) -> InstallationCredential:
        """Revoke the current credential; authentication is refused from ``now`` on."""
        _require_aware(now, field_name="now")
        credential = await self._current_credential(installation_id, now=now)
        revoked = replace(credential, revoked_at=now)
        await self._store.save_credential(revoked)
        return revoked

    async def record_heartbeat(
        self,
        principal: InstallationPrincipal,
        *,
        declared_client_version: str,
        declared_schema_version: str,
        now: datetime,
    ) -> HeartbeatRecord:
        """Record an authenticated heartbeat with its version declaration."""
        record = HeartbeatRecord(
            installation_id=principal.installation_id,
            received_at=now,
            declared_client_version=declared_client_version,
            declared_schema_version=declared_schema_version,
        )
        await self._store.append_heartbeat(record)
        return record

    async def heartbeat_summary(self, installation_id: UUID) -> HeartbeatSummary:
        """Roll up one installation's heartbeats without any sensitive field."""
        await self._store.get_installation(installation_id)
        records = await self._store.heartbeats(installation_id)
        latest = max(records, key=lambda record: record.received_at, default=None)
        return HeartbeatSummary(
            installation_id=installation_id,
            heartbeat_count=len(records),
            last_received_at=latest.received_at if latest else None,
            declared_client_version=latest.declared_client_version if latest else None,
            declared_schema_version=latest.declared_schema_version if latest else None,
        )

    async def version_status_directory(self) -> tuple[HeartbeatSummary, ...]:
        """The queryable directory of every installation's version status."""
        installation_ids = await self._store.installation_ids()
        return tuple(
            [await self.heartbeat_summary(installation_id) for installation_id in installation_ids]
        )

    async def bind_device(
        self,
        principal: InstallationPrincipal,
        claim: DeviceIdentityClaim,
        *,
        now: datetime,
    ) -> DeviceBinding:
        """Bind the installation to a physical device via product attestation.

        Platform hints in the claim never become the identity: the product's
        attestation provider must return one, and an attestation that merely
        echoes the platform UUID is refused.  Recognition, calibration, and
        combination rules stay with the injected product policy.
        """
        _require_aware(now, field_name="now")
        if not isinstance(claim, DeviceIdentityClaim):
            raise DeviceTrustMalformed("claim must be a DeviceIdentityClaim")
        if claim.claim_version not in self._supported_claim_versions:
            raise DeviceTrustVersionUnsupported(
                f"claim version {claim.claim_version!r} is not supported by this "
                "deployment; unknown versions are refused, never guessed"
            )
        installation = await self._store.get_installation(principal.installation_id)
        identity = self._attestation.attest(claim, now=now)
        if identity is None:
            raise DeviceTrustAccessDenied(
                "platform-reported hints do not establish a physical identity; "
                "product attestation is required"
            )
        if not isinstance(identity, PhysicalDeviceIdentity):
            raise DeviceTrustMalformed(
                "attestation must answer a PhysicalDeviceIdentity or None"
            )
        if identity.stable_identity == claim.platform_uuid:
            raise DeviceTrustAccessDenied(
                "an attestation that echoes the platform UUID is not a physical identity"
            )
        if not self._combination_policy.allows(installation, identity):
            raise DeviceTrustAccessDenied(
                "the product combination policy refuses this binding"
            )
        binding = DeviceBinding(
            binding_id=uuid4(),
            installation_id=installation.installation_id,
            stable_identity=identity.stable_identity,
            proof_reference=identity.proof_reference,
            bound_at=now,
        )
        await self._store.insert_binding(binding)
        return binding


class HardwareLeaseService:
    """The acquire/renew/release state machine over `HardwareLease`."""

    def __init__(self, store: DeviceTrustStore, *, lease_ttl: timedelta) -> None:
        if not isinstance(lease_ttl, timedelta) or lease_ttl <= timedelta(0):
            raise DeviceTrustMalformed("lease_ttl must be a positive duration")
        self._store = store
        self._lease_ttl = lease_ttl

    async def acquire(
        self, principal: InstallationPrincipal, *, asset_id: str, now: datetime
    ) -> HardwareLease:
        """Acquire the one effective lease on an asset, or be refused."""
        _require_aware(now, field_name="now")
        lease = HardwareLease(
            lease_id=uuid4(),
            asset_id=asset_id,
            installation_id=principal.installation_id,
            state=LeaseState.ACTIVE,
            acquired_at=now,
            renewed_at=now,
            expires_at=now + self._lease_ttl,
        )
        await self._store.insert_lease(lease, now=now)
        return lease

    async def renew(
        self, principal: InstallationPrincipal, lease_id: UUID, *, now: datetime
    ) -> HardwareLease:
        """Extend an effective lease; expired or released leases cannot renew."""
        _require_aware(now, field_name="now")
        lease = await self._store.get_lease(lease_id)
        if lease.installation_id != principal.installation_id:
            raise DeviceTrustAccessDenied("a lease can only be renewed by its holder")
        if lease.state is LeaseState.RELEASED:
            raise DeviceTrustStateError("released leases are terminal")
        if lease.expires_at <= now:
            raise DeviceTrustStateError(
                "an expired lease cannot be renewed; acquire a new one"
            )
        renewed = replace(lease, renewed_at=now, expires_at=now + self._lease_ttl)
        await self._store.save_lease(renewed)
        return renewed

    async def release(
        self, principal: InstallationPrincipal, lease_id: UUID, *, now: datetime
    ) -> HardwareLease:
        """Release a lease; the asset becomes leasable immediately."""
        _require_aware(now, field_name="now")
        lease = await self._store.get_lease(lease_id)
        if lease.installation_id != principal.installation_id:
            raise DeviceTrustAccessDenied("a lease can only be released by its holder")
        if lease.state is LeaseState.RELEASED:
            raise DeviceTrustStateError("released leases are terminal")
        released = replace(lease, state=LeaseState.RELEASED, released_at=now)
        await self._store.save_lease(released)
        return released
