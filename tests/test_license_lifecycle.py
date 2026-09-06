from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from techflex_cloud_foundation import (
    InMemoryLicenseLifecycleStore,
    LicenseActivationRejected,
    LicenseDocument,
    LicenseKeyset,
    LicenseLifecycleAction,
    LicenseLifecycleEvent,
    LicenseLifecycleMalformed,
    LicenseLifecycleRecord,
    LicenseLifecycleService,
    LicenseLifecycleState,
    LicenseLifecycleVersionUnsupported,
    LicenseReplayRejected,
    LicenseSignatureInvalid,
    LicenseSigningKeyUnknown,
    LicenseTransitionRejected,
    SignedLicenseDocument,
)
from techflex_cloud_foundation.license_lifecycle import (
    LICENSE_DOCUMENT_FORMAT_VERSION,
    LICENSE_LIFECYCLE_FORMAT_VERSION,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


NOW = datetime(2026, 9, 6, tzinfo=UTC)
TERM = timedelta(days=365)
GRACE = timedelta(days=14)
SKU = "sku-standard"
SERIAL = "serial-0001"


class _Policy:
    def activation_window(
        self, *, sku: str, activated_at: datetime
    ) -> tuple[datetime, datetime]:
        self._require_sku(sku)
        return activated_at, activated_at + TERM

    def renewal_window(
        self, *, sku: str, current_valid_until: datetime, now: datetime
    ) -> tuple[datetime, datetime]:
        self._require_sku(sku)
        return now, max(current_valid_until, now) + TERM

    def features(self, *, sku: str) -> frozenset[str]:
        self._require_sku(sku)
        return frozenset({"reports.view", "sync.upload"})

    def offline_grace(self, *, sku: str) -> timedelta:
        self._require_sku(sku)
        return GRACE

    @staticmethod
    def _require_sku(sku: str) -> None:
        if sku != SKU:
            raise LicenseLifecycleMalformed(f"unknown sku: {sku!r}")


def _keyset(
    signing_key: Ed25519PrivateKey, **overrides: object
) -> LicenseKeyset:
    values: dict[str, object] = {
        "revision": 3,
        "active_key_id": "license/3",
        "public_keys": {"license/3": signing_key.public_key().public_bytes_raw()},
        "revoked_key_ids": ("license/1", "license/2"),
    }
    values.update(overrides)
    return LicenseKeyset(**values)  # type: ignore[arg-type]


def _service() -> tuple[LicenseLifecycleService, InMemoryLicenseLifecycleStore]:
    signing_key = Ed25519PrivateKey.generate()
    store = InMemoryLicenseLifecycleStore()
    service = LicenseLifecycleService(
        store, _Policy(), signing_key=signing_key, keyset=_keyset(signing_key)
    )
    return service, store


async def _issued(
    service: LicenseLifecycleService, serial: str = SERIAL
) -> LicenseLifecycleRecord:
    record, _ = await service.issue(
        sku=SKU, activation_serial=serial, reason="stocked", now=NOW
    )
    return record


async def _activated(
    service: LicenseLifecycleService, serial: str = SERIAL
) -> LicenseLifecycleRecord:
    await _issued(service, serial)
    account_id = uuid4()
    record, _ = await service.activate(
        activation_serial=serial,
        tenant_id=uuid4(),
        account_id=account_id,
        hardware_id="hw-1",
        reason="first use",
        now=NOW,
    )
    return record


async def test_issue_stocks_a_license_without_bindings() -> None:
    service, _ = _service()

    record, signed = await service.issue(
        sku=SKU, activation_serial=SERIAL, reason="stocked", now=NOW
    )

    assert record.state is LicenseLifecycleState.ISSUED
    assert record.tenant_id is None and record.account_id is None
    assert record.valid_from is None and record.valid_until is None
    assert signed.document.state is LicenseLifecycleState.ISSUED
    assert signed.keyset_revision == 3
    history = await service.history(record.license_id)
    assert [event.action for event in history] == [LicenseLifecycleAction.ISSUE]
    assert history[0].occurred_at == NOW
    assert history[0].reason == "stocked"


async def test_full_happy_path_issue_activate_suspend_resume_renew_revoke() -> None:
    service, _ = _service()
    record = await _activated(service)
    assert record.state is LicenseLifecycleState.ACTIVE
    assert record.valid_from == NOW and record.valid_until == NOW + TERM

    record, _ = await service.suspend(record.license_id, reason="lapsed", now=NOW)
    assert record.state is LicenseLifecycleState.SUSPENDED

    record, _ = await service.resume(record.license_id, reason="paid", now=NOW)
    assert record.state is LicenseLifecycleState.ACTIVE

    later = NOW + timedelta(days=30)
    record, signed = await service.renew(record.license_id, reason="term+12m", now=later)
    assert record.state is LicenseLifecycleState.ACTIVE
    assert record.valid_until == NOW + TERM + TERM
    assert signed.document.version == record.version

    record, signed = await service.revoke(record.license_id, reason="chargeback", now=later)
    assert record.state is LicenseLifecycleState.REVOKED
    assert signed.document.state is LicenseLifecycleState.REVOKED

    history = await service.history(record.license_id)
    assert [event.action for event in history] == [
        LicenseLifecycleAction.ISSUE,
        LicenseLifecycleAction.ACTIVATE,
        LicenseLifecycleAction.SUSPEND,
        LicenseLifecycleAction.RESUME,
        LicenseLifecycleAction.RENEW,
        LicenseLifecycleAction.REVOKE,
    ]
    assert [event.sequence for event in history] == [1, 2, 3, 4, 5, 6]
    assert all(len({event.digest() for event in history}) == 6 for _ in (0,))


@pytest.mark.parametrize(
    ("action", "message"),
    [
        ("suspend", "issued license"),
        ("resume", "issued license"),
        ("renew", "issued license"),
        ("revoke", "issued license"),
    ],
)
async def test_issued_license_refuses_everything_but_activation(
    action: str, message: str
) -> None:
    service, _ = _service()
    record = await _issued(service)
    method = getattr(service, action)

    with pytest.raises(LicenseTransitionRejected, match=message):
        await method(record.license_id, reason="nope", now=NOW)


async def test_suspended_license_cannot_suspend_or_renew() -> None:
    service, _ = _service()
    record = await _activated(service)
    record, _ = await service.suspend(record.license_id, reason="lapsed", now=NOW)

    with pytest.raises(LicenseTransitionRejected, match="already SUSPENDED"):
        await service.suspend(record.license_id, reason="again", now=NOW)
    with pytest.raises(LicenseTransitionRejected):
        await service.renew(record.license_id, reason="extend", now=NOW)


async def test_revoked_is_terminal_for_every_action() -> None:
    service, _ = _service()
    record = await _activated(service)
    record, _ = await service.revoke(record.license_id, reason="fraud", now=NOW)

    for action in ("suspend", "resume", "renew", "revoke"):
        with pytest.raises(LicenseTransitionRejected, match="terminal"):
            await getattr(service, action)(record.license_id, reason="x", now=NOW)


async def test_revoked_from_suspended_is_terminal() -> None:
    service, _ = _service()
    record = await _activated(service)
    record, _ = await service.suspend(record.license_id, reason="lapsed", now=NOW)
    record, _ = await service.revoke(record.license_id, reason="gone", now=NOW)

    with pytest.raises(LicenseTransitionRejected, match="terminal"):
        await service.resume(record.license_id, reason="undo", now=NOW)


async def test_activate_rejects_replay_same_account() -> None:
    service, _ = _service()
    record = await _activated(service)

    with pytest.raises(LicenseReplayRejected, match="single-use"):
        await service.activate(
            activation_serial=SERIAL,
            tenant_id=uuid4(),
            account_id=record.account_id,  # type: ignore[arg-type]
            hardware_id="hw-1",
            reason="double spend",
            now=NOW,
        )


async def test_activate_rejects_cross_account_replay() -> None:
    service, _ = _service()
    await _activated(service)

    with pytest.raises(LicenseReplayRejected, match="different account"):
        await service.activate(
            activation_serial=SERIAL,
            tenant_id=uuid4(),
            account_id=uuid4(),
            hardware_id="hw-9",
            reason="replay",
            now=NOW,
        )


async def test_activate_rejects_unknown_serial() -> None:
    service, _ = _service()

    with pytest.raises(LicenseActivationRejected, match="unknown"):
        await service.activate(
            activation_serial="serial-never-issued",
            tenant_id=uuid4(),
            account_id=uuid4(),
            hardware_id="hw-1",
            reason="guess",
            now=NOW,
        )


async def test_issue_rejects_duplicate_serial_and_unknown_sku() -> None:
    service, _ = _service()
    await _issued(service)

    with pytest.raises(Exception, match="already bound"):
        await service.issue(
            sku=SKU, activation_serial=SERIAL, reason="dup", now=NOW
        )
    with pytest.raises(LicenseLifecycleMalformed, match="unknown sku"):
        await service.issue(
            sku="sku-other", activation_serial="serial-2", reason="x", now=NOW
        )


async def test_activation_binds_window_from_policy() -> None:
    service, _ = _service()
    record, signed = await service.activate(
        activation_serial=(await _issued(service)).activation_serial,
        tenant_id=uuid4(),
        account_id=uuid4(),
        hardware_id="hw-1",
        reason="first use",
        now=NOW,
    )

    assert record.valid_from == NOW
    assert record.valid_until == NOW + TERM
    assert signed.document.features == frozenset({"reports.view", "sync.upload"})


async def test_renew_rejects_already_expired_window() -> None:
    class _ExpiringPolicy(_Policy):
        def renewal_window(
            self, *, sku: str, current_valid_until: datetime, now: datetime
        ) -> tuple[datetime, datetime]:
            return now - TERM, now - timedelta(days=1)

    signing_key = Ed25519PrivateKey.generate()
    store = InMemoryLicenseLifecycleStore()
    service = LicenseLifecycleService(
        store, _ExpiringPolicy(), signing_key=signing_key, keyset=_keyset(signing_key)
    )
    record = await _activated(service)

    with pytest.raises(LicenseLifecycleMalformed, match="already-expired"):
        await service.renew(record.license_id, reason="extend", now=NOW)


async def test_offline_access_grace_boundaries() -> None:
    service, _ = _service()
    record = await _activated(service)
    expiry = NOW + TERM

    inside_term = await service.offline_access(record.license_id, now=expiry - timedelta(seconds=1))
    assert inside_term.allowed

    inside_grace = await service.offline_access(
        record.license_id, now=expiry + GRACE - timedelta(seconds=1)
    )
    assert inside_grace.allowed

    at_deadline = await service.offline_access(record.license_id, now=expiry + GRACE)
    assert not at_deadline.allowed

    beyond = await service.offline_access(
        record.license_id, now=expiry + GRACE + timedelta(days=1)
    )
    assert not beyond.allowed


async def test_offline_access_requires_active_state() -> None:
    service, _ = _service()
    record = await _activated(service)
    record, _ = await service.suspend(record.license_id, reason="lapsed", now=NOW)

    decision = await service.offline_access(record.license_id, now=NOW)

    assert not decision.allowed
    assert "SUSPENDED" in decision.reason


async def test_signed_document_verifies_under_keyset() -> None:
    service, _ = _service()
    record, signed = await service.issue(
        sku=SKU, activation_serial=SERIAL, reason="stocked", now=NOW
    )
    signing_key = Ed25519PrivateKey.generate()
    wrong_keyset = LicenseKeyset(
        revision=3,
        active_key_id="license/9",
        public_keys={"license/9": signing_key.public_key().public_bytes_raw()},
    )

    keyset = _keyset_from_service(service)
    assert keyset.verify(signed) is signed.document
    with pytest.raises(LicenseSigningKeyUnknown):
        wrong_keyset.verify(signed)
    rotated = LicenseKeyset(
        revision=4,
        active_key_id="license/4",
        public_keys={
            **keyset.public_keys,
            "license/4": signing_key.public_key().public_bytes_raw(),
        },
        revoked_key_ids=("license/3",),
    )
    with pytest.raises(LicenseSigningKeyUnknown, match="revoked"):
        rotated.verify(signed)


async def test_signed_document_rejects_tampering() -> None:
    service, _ = _service()
    _, signed = await service.issue(
        sku=SKU, activation_serial=SERIAL, reason="stocked", now=NOW
    )
    keyset = _keyset_from_service(service)
    tampered = SignedLicenseDocument(
        document=LicenseDocument(
            license_id=signed.document.license_id,
            state=LicenseLifecycleState.ACTIVE,
            version=signed.document.version,
            sku=SKU,
            features=frozenset({"everything"}),
            issued_at=NOW,
        ),
        key_id=signed.key_id,
        signature=signed.signature,
        keyset_revision=signed.keyset_revision,
    )

    with pytest.raises(LicenseSignatureInvalid):
        keyset.verify(tampered)


def _keyset_from_service(service: LicenseLifecycleService) -> LicenseKeyset:
    return service._keyset


def test_event_and_document_refuse_unknown_format_versions() -> None:
    with pytest.raises(LicenseLifecycleVersionUnsupported):
        LicenseLifecycleEvent(
            license_id=uuid4(),
            sequence=1,
            action=LicenseLifecycleAction.ISSUE,
            from_state=None,
            to_state=LicenseLifecycleState.ISSUED,
            reason="x",
            occurred_at=NOW,
            format_version=LICENSE_LIFECYCLE_FORMAT_VERSION + 1,
        )
    with pytest.raises(LicenseLifecycleVersionUnsupported):
        LicenseDocument(
            license_id=uuid4(),
            state=LicenseLifecycleState.ISSUED,
            version=1,
            sku=SKU,
            features=frozenset(),
            issued_at=NOW,
            format_version=LICENSE_DOCUMENT_FORMAT_VERSION + 1,
        )


def test_record_and_event_structural_validation() -> None:
    with pytest.raises(LicenseLifecycleMalformed, match="timezone-aware"):
        LicenseLifecycleEvent(
            license_id=uuid4(),
            sequence=1,
            action=LicenseLifecycleAction.ISSUE,
            from_state=None,
            to_state=LicenseLifecycleState.ISSUED,
            reason="x",
            occurred_at=datetime(2026, 9, 6),
        )
    with pytest.raises(LicenseLifecycleMalformed, match="no tenant"):
        LicenseLifecycleRecord(
            license_id=uuid4(),
            state=LicenseLifecycleState.ISSUED,
            version=1,
            sku=SKU,
            activation_serial=SERIAL,
            issued_at=NOW,
            tenant_id=uuid4(),
        )
    with pytest.raises(LicenseLifecycleMalformed, match="valid_until"):
        LicenseLifecycleRecord(
            license_id=uuid4(),
            state=LicenseLifecycleState.ACTIVE,
            version=1,
            sku=SKU,
            activation_serial=SERIAL,
            issued_at=NOW,
            valid_from=NOW,
            valid_until=NOW,
        )


def test_keyset_structural_validation() -> None:
    signing_key = Ed25519PrivateKey.generate()
    raw = signing_key.public_key().public_bytes_raw()

    with pytest.raises(LicenseLifecycleMalformed, match="active key id"):
        LicenseKeyset(revision=1, active_key_id="missing", public_keys={"k": raw})
    with pytest.raises(LicenseLifecycleMalformed, match="cannot be revoked"):
        LicenseKeyset(
            revision=1, active_key_id="k", public_keys={"k": raw}, revoked_key_ids=("k",)
        )
    with pytest.raises(LicenseLifecycleMalformed, match="at least one"):
        LicenseKeyset(revision=1, active_key_id="k", public_keys={})


async def test_naive_now_is_refused() -> None:
    service, _ = _service()

    with pytest.raises(LicenseLifecycleMalformed, match="timezone-aware"):
        await service.issue(
            sku=SKU,
            activation_serial=SERIAL,
            reason="x",
            now=datetime(2026, 9, 6),
        )
