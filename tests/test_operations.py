from __future__ import annotations

from dataclasses import FrozenInstanceError, asdict
from datetime import UTC, datetime, timedelta
import json
from uuid import UUID, uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from techflex_cloud_foundation import (
    ConfigReleaseDocument,
    InMemoryOperationsStore,
    OperationsAction,
    OperationsAuditRecord,
    OperationsCommand,
    OperationsConflict,
    OperationsConsole,
    OperationsDowngradeRejected,
    OperationsGrantRefused,
    OperationsKeyset,
    OperationsMalformed,
    OperationsObjectKind,
    OperationsObjectState,
    OperationsOutcome,
    OperationsPermissionDenied,
    OperationsSignatureInvalid,
    OperationsSigningKeyUnknown,
    OperationsStateError,
    OperationsTarget,
    PlatformPrincipal,
    ProductCatalog,
    ProductRecord,
    ProductRegistry,
    SensitiveAccessGrant,
    SignedConfigRelease,
    TenantPrincipal,
    UpgradeOrderKind,
    VersionRelation,
    command_purpose,
    validate_upgrade_order,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


NOW = datetime(2026, 9, 6, tzinfo=UTC)
GRANT_TTL = timedelta(minutes=15)
OPERATOR = PlatformPrincipal(
    subject_id="platform-ops-1", role_names=frozenset({"platform-operations"})
)
COLLEAGUE = PlatformPrincipal(
    subject_id="platform-ops-2", role_names=frozenset({"platform-operations"})
)
TENANT_OPERATOR = TenantPrincipal(
    tenant_id="tenant-1", operator_id="operator-1", role_names=frozenset({"admin"})
)
LICENSE = OperationsTarget(kind=OperationsObjectKind.LICENSE, object_id="license-1")
ANOTHER_LICENSE = OperationsTarget(
    kind=OperationsObjectKind.LICENSE, object_id="license-2"
)
ORGANIZATION = OperationsTarget(
    kind=OperationsObjectKind.ORGANIZATION, object_id="org-1"
)
DEVICE = OperationsTarget(kind=OperationsObjectKind.DEVICE, object_id="device-1")
PRODUCT = OperationsTarget(
    kind=OperationsObjectKind.PRODUCT_REGISTRATION, object_id="product-alpha"
)
SENSITIVE_PURPOSES = frozenset({"license.close", "license.disable"})


class NumericPolicy:
    """Test policy: numeric version strings compare by integer value."""

    def compare(self, left: str, right: str) -> VersionRelation | None:
        if not left.isdigit() or not right.isdigit():
            return None
        if int(left) < int(right):
            return VersionRelation.OLDER
        if int(left) > int(right):
            return VersionRelation.NEWER
        return VersionRelation.EQUAL

    def unsupported_disposition(self, *, dimension: str, version: str) -> str:
        raise AssertionError("unsupported_disposition is not used here")


def _keyset(signing_key: Ed25519PrivateKey) -> OperationsKeyset:
    return OperationsKeyset(
        revision=2,
        active_key_id="operations/2",
        public_keys={
            "operations/2": signing_key.public_key().public_bytes_raw()
        },
        revoked_key_ids=("operations/1",),
    )


def _console(
    **overrides: object,
) -> tuple[OperationsConsole, InMemoryOperationsStore]:
    signing_key = Ed25519PrivateKey.generate()
    store = InMemoryOperationsStore()
    values: dict[str, object] = {
        "store": store,
        "signing_key": signing_key,
        "keyset": _keyset(signing_key),
        "sensitive_purposes": SENSITIVE_PURPOSES,
        "max_grant_lifetime": GRANT_TTL,
    }
    values.update(overrides)
    return (
        OperationsConsole(**values),  # type: ignore[arg-type]
        store,
    )


def _command(
    action: OperationsAction,
    target: OperationsTarget,
    *,
    issued_by: PlatformPrincipal = OPERATOR,
    parameters: dict[str, str] | None = None,
    issued_at: datetime = NOW,
) -> OperationsCommand:
    return OperationsCommand(
        command_id=uuid4(),
        action=action,
        issued_by=issued_by,
        target=target,
        parameters=parameters or {},
        issued_at=issued_at,
    )


async def _stocked(
    console: OperationsConsole, target: OperationsTarget = LICENSE
) -> None:
    action = (
        OperationsAction.CREATE
        if target.kind
        in (OperationsObjectKind.ORGANIZATION, OperationsObjectKind.LICENSE)
        else OperationsAction.REGISTER
    )
    await console.execute(_command(action, target), now=NOW)


async def _grant_for(
    console: OperationsConsole,
    action: OperationsAction = OperationsAction.CLOSE,
    target: OperationsTarget = LICENSE,
    *,
    holder: PlatformPrincipal = OPERATOR,
    duration: timedelta = GRANT_TTL,
    now: datetime = NOW,
) -> SensitiveAccessGrant:
    return await console.issue_grant(
        holder,
        action=action,
        target=target,
        reason="incident ticket-4711",
        duration=duration,
        now=now,
    )


# ---------------------------------------------------------------------------
# Commands, immutability, and the audit trail
# ---------------------------------------------------------------------------


async def test_commands_and_audit_records_are_immutable() -> None:
    command = _command(OperationsAction.CREATE, LICENSE)
    with pytest.raises(FrozenInstanceError):
        command.action = OperationsAction.CLOSE  # type: ignore[misc]

    console, _ = _console()
    _, audit = await console.execute(command, now=NOW)
    with pytest.raises(FrozenInstanceError):
        audit.outcome = OperationsOutcome.REFUSED  # type: ignore[misc]


async def test_executed_command_appends_its_audit_record() -> None:
    console, store = _console()
    command = _command(
        OperationsAction.CREATE,
        LICENSE,
        parameters={"sku": "sku-standard", "reason": "stocked for sale"},
    )

    record, audit = await console.execute(command, now=NOW)

    assert record.kind is OperationsObjectKind.LICENSE
    assert record.state is OperationsObjectState.ACTIVE
    assert record.version == 1
    assert audit.actor_subject == OPERATOR.subject_id
    assert audit.action is OperationsAction.CREATE
    assert audit.target == LICENSE
    assert audit.outcome is OperationsOutcome.APPLIED
    assert audit.occurred_at == NOW
    assert audit.grant_id is None
    assert audit.command_digest == command.digest()
    assert await store.audit_records(LICENSE) == (audit,)


async def test_command_parameters_never_enter_the_audit_trail() -> None:
    console, store = _console()
    secret = "activation-secret-0123456789"
    command = _command(
        OperationsAction.CREATE,
        LICENSE,
        parameters={"activation_code": secret, "reason": "stocked"},
    )

    await console.execute(command, now=NOW)
    await _grant_for(console)
    refused = _command(OperationsAction.CLOSE, LICENSE)
    with pytest.raises(OperationsGrantRefused):
        await console.execute(refused, now=NOW)

    for target in (LICENSE, ANOTHER_LICENSE, ORGANIZATION):
        for record in await store.audit_records(target):
            serialized = json.dumps(asdict(record), default=str)
            assert secret not in serialized
            assert "activation_code" not in serialized


async def test_command_cannot_execute_before_it_was_issued() -> None:
    console, _ = _console()
    command = _command(
        OperationsAction.CREATE, LICENSE, issued_at=NOW + timedelta(minutes=1)
    )
    with pytest.raises(OperationsMalformed, match="before it was issued"):
        await console.execute(command, now=NOW)


async def test_a_command_never_applies_twice() -> None:
    console, _ = _console()
    command = _command(OperationsAction.CREATE, LICENSE)
    await console.execute(command, now=NOW)
    # The replay is refused by the object store first ("already exists");
    # the audit trail's one-APPLIED-record-per-command rule is the backstop
    # for concurrent writers, tested against the store directly below.
    with pytest.raises(OperationsConflict, match="already exists"):
        await console.execute(command, now=NOW + timedelta(minutes=1))


async def test_audit_trail_holds_one_applied_record_per_command() -> None:
    store = InMemoryOperationsStore()
    applied = _applied_audit_record()
    await store.append_audit(applied)
    with pytest.raises(OperationsConflict, match="already executed"):
        await store.append_audit(_applied_audit_record(command_id=applied.command_id))


def _applied_audit_record(
    *, command_id: UUID | None = None
) -> OperationsAuditRecord:
    return OperationsAuditRecord(
        record_id=uuid4(),
        command_id=command_id or uuid4(),
        actor_subject=OPERATOR.subject_id,
        action=OperationsAction.DISABLE,
        target=LICENSE,
        outcome=OperationsOutcome.APPLIED,
        command_digest="0" * 64,
        occurred_at=NOW,
    )


async def test_action_kind_pairs_are_a_whitelist() -> None:
    with pytest.raises(OperationsMalformed, match="whitelist"):
        _command(OperationsAction.REGISTER, ORGANIZATION)
    with pytest.raises(OperationsMalformed, match="whitelist"):
        _command(OperationsAction.CREATE, DEVICE)


async def test_lifecycle_actions_apply_to_every_kind() -> None:
    # Sensitivity is injected policy, so the plain state machine runs on a
    # console whose sensitive set is empty.
    console, _ = _console(sensitive_purposes=frozenset())
    await _stocked(console, ORGANIZATION)
    await _stocked(console, LICENSE)
    await _stocked(console, DEVICE)
    await _stocked(console, PRODUCT)

    for target in (ORGANIZATION, LICENSE, DEVICE, PRODUCT):
        record, _ = await console.execute(
            _command(OperationsAction.DISABLE, target), now=NOW
        )
        assert record.state is OperationsObjectState.SUSPENDED
        record, _ = await console.execute(
            _command(OperationsAction.ENABLE, target), now=NOW
        )
        assert record.state is OperationsObjectState.ACTIVE


async def test_object_lifecycle_is_a_whitelist_and_close_is_terminal() -> None:
    console, _ = _console(sensitive_purposes=frozenset())
    await _stocked(console)

    _, audit = await console.execute(
        _command(OperationsAction.DISABLE, LICENSE), now=NOW
    )
    assert audit.outcome is OperationsOutcome.APPLIED
    with pytest.raises(OperationsStateError, match="already SUSPENDED"):
        await console.execute(_command(OperationsAction.DISABLE, LICENSE), now=NOW)

    await console.execute(_command(OperationsAction.ENABLE, LICENSE), now=NOW)
    record, _ = await console.execute(
        _command(OperationsAction.CLOSE, LICENSE), now=NOW
    )
    assert record.state is OperationsObjectState.CLOSED

    with pytest.raises(OperationsStateError, match="terminal"):
        await console.execute(_command(OperationsAction.ENABLE, LICENSE), now=NOW)
    with pytest.raises(OperationsStateError, match="terminal"):
        await console.execute(_command(OperationsAction.DISABLE, LICENSE), now=NOW)
    with pytest.raises(OperationsStateError, match="already CLOSED"):
        await console.execute(_command(OperationsAction.CLOSE, LICENSE), now=NOW)


async def test_duplicate_create_conflicts() -> None:
    console, _ = _console()
    await _stocked(console)
    with pytest.raises(OperationsConflict, match="already exists"):
        await console.execute(
            _command(OperationsAction.CREATE, LICENSE), now=NOW
        )


async def test_command_on_unknown_object_is_refused() -> None:
    console, _ = _console()
    with pytest.raises(OperationsMalformed, match="unknown"):
        await console.execute(_command(OperationsAction.ENABLE, LICENSE), now=NOW)


# ---------------------------------------------------------------------------
# Principal separation: the platform console never admits tenant identities
# ---------------------------------------------------------------------------


async def test_tenant_principal_cannot_issue_commands() -> None:
    with pytest.raises(OperationsPermissionDenied, match="tenant principals"):
        _command(OperationsAction.CREATE, LICENSE, issued_by=TENANT_OPERATOR)


async def test_tenant_principal_cannot_request_grants() -> None:
    console, _ = _console()
    with pytest.raises(OperationsPermissionDenied, match="tenant principals"):
        await console.issue_grant(
            TENANT_OPERATOR,  # type: ignore[arg-type]
            action=OperationsAction.CLOSE,
            target=LICENSE,
            reason="should not be issued",
            duration=GRANT_TTL,
            now=NOW,
        )


async def test_tenant_principal_cannot_publish_config() -> None:
    console, _ = _console()
    with pytest.raises(OperationsPermissionDenied, match="tenant principals"):
        await console.publish_config(
            config_id="gateway",
            version=1,
            payload={"mode": "strict"},
            principal=TENANT_OPERATOR,  # type: ignore[arg-type]
            now=NOW,
        )


async def test_command_requires_a_principal_at_all() -> None:
    with pytest.raises(OperationsMalformed, match="PlatformPrincipal"):
        _command(
            OperationsAction.CREATE,
            LICENSE,
            issued_by="platform-ops-1",  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Sensitive operations and short-lived, single-use grants
# ---------------------------------------------------------------------------


async def test_sensitive_close_without_grant_is_refused_and_audited() -> None:
    console, store = _console()
    await _stocked(console)
    command = _command(OperationsAction.CLOSE, LICENSE)

    with pytest.raises(OperationsGrantRefused, match="requires"):
        await console.execute(command, now=NOW)

    records = await store.audit_records(LICENSE)
    refusals = [
        record for record in records if record.outcome is OperationsOutcome.REFUSED
    ]
    assert len(records) == 2  # the CREATE that stocked it, plus the refusal
    (refusal,) = refusals
    assert refusal.command_id == command.command_id
    assert refusal.command_digest == command.digest()
    assert refusal.grant_id is None


async def test_expired_grant_is_refused() -> None:
    console, store = _console()
    await _stocked(console)
    grant = await _grant_for(console, duration=timedelta(minutes=5))

    later = NOW + timedelta(minutes=6)
    with pytest.raises(OperationsGrantRefused, match="expired"):
        await console.execute(
            _command(OperationsAction.CLOSE, LICENSE), now=later, grant_id=grant.grant_id
        )
    refusals = [
        record
        for record in await store.audit_records(LICENSE)
        if record.outcome is OperationsOutcome.REFUSED
    ]
    assert refusals, "an expired-grant refusal must leave an audit record"


async def test_grant_purpose_mismatch_is_refused() -> None:
    console, _ = _console()
    await _stocked(console)
    grant = await _grant_for(console, action=OperationsAction.CLOSE)

    with pytest.raises(OperationsGrantRefused, match="exactly one purpose"):
        await console.execute(
            _command(OperationsAction.DISABLE, LICENSE),
            now=NOW,
            grant_id=grant.grant_id,
        )


async def test_grant_holder_mismatch_is_refused() -> None:
    console, _ = _console()
    await _stocked(console)
    grant = await _grant_for(console, holder=COLLEAGUE)

    with pytest.raises(OperationsGrantRefused, match="another operator"):
        await console.execute(
            _command(OperationsAction.CLOSE, LICENSE), now=NOW, grant_id=grant.grant_id
        )


async def test_grant_target_mismatch_is_refused() -> None:
    console, _ = _console()
    await _stocked(console, LICENSE)
    await _stocked(console, ANOTHER_LICENSE)
    grant = await _grant_for(console, target=ANOTHER_LICENSE)

    with pytest.raises(OperationsGrantRefused, match="does not cover this target"):
        await console.execute(
            _command(OperationsAction.CLOSE, LICENSE), now=NOW, grant_id=grant.grant_id
        )


async def test_grant_is_single_use() -> None:
    console, _ = _console()
    await _stocked(console, LICENSE)
    await _stocked(console, ANOTHER_LICENSE)

    grant = await _grant_for(console, target=LICENSE)
    record, audit = await console.execute(
        _command(OperationsAction.CLOSE, LICENSE), now=NOW, grant_id=grant.grant_id
    )
    assert record.state is OperationsObjectState.CLOSED
    assert audit.grant_id == grant.grant_id
    assert audit.outcome is OperationsOutcome.APPLIED

    with pytest.raises(OperationsGrantRefused, match="single-use"):
        await console.execute(
            _command(OperationsAction.DISABLE, ANOTHER_LICENSE),
            now=NOW,
            grant_id=grant.grant_id,
        )


async def test_unknown_grant_is_refused() -> None:
    console, _ = _console()
    await _stocked(console)
    with pytest.raises(OperationsGrantRefused, match="unknown"):
        await console.execute(
            _command(OperationsAction.CLOSE, LICENSE),
            now=NOW,
            grant_id=uuid4(),
        )


async def test_grant_lifetime_has_a_ceiling() -> None:
    console, _ = _console()
    with pytest.raises(OperationsMalformed, match="at most"):
        await _grant_for(console, duration=GRANT_TTL + timedelta(minutes=1))
    with pytest.raises(OperationsMalformed, match="at most"):
        await _grant_for(console, duration=timedelta(0))


async def test_grants_are_minted_only_for_sensitive_purposes() -> None:
    console, _ = _console()
    with pytest.raises(OperationsGrantRefused, match="not a sensitive operation"):
        await console.issue_grant(
            OPERATOR,
            action=OperationsAction.ENABLE,
            target=LICENSE,
            reason="should not be issued",
            duration=GRANT_TTL,
            now=NOW,
        )


async def test_ordinary_command_refuses_a_presented_grant() -> None:
    console, _ = _console()
    await _stocked(console)
    grant = await _grant_for(console)
    # ENABLE is not in the sensitive set, so the grant is out of place; the
    # refusal happens before the state machine is even consulted.
    with pytest.raises(OperationsMalformed, match="ordinary command"):
        await console.execute(
            _command(OperationsAction.ENABLE, LICENSE),
            now=NOW,
            grant_id=grant.grant_id,
        )


async def test_grant_record_is_structurally_validated() -> None:
    with pytest.raises(OperationsMalformed, match="after issued_at"):
        SensitiveAccessGrant(
            grant_id=uuid4(),
            purpose="license.close",
            holder_subject=OPERATOR.subject_id,
            target=LICENSE,
            issued_at=NOW,
            expires_at=NOW,
        )


# ---------------------------------------------------------------------------
# Signed configuration releases and the no-rollback rule
# ---------------------------------------------------------------------------


async def test_publish_signs_and_latest_returns_the_newest_release() -> None:
    console, _ = _console()

    first = await console.publish_config(
        config_id="gateway",
        version=1,
        payload={"mode": "strict", "retries": "3"},
        principal=OPERATOR,
        now=NOW,
    )
    third = await console.publish_config(
        config_id="gateway",
        version=3,
        payload={"mode": "strict", "retries": "5"},
        principal=OPERATOR,
        now=NOW + timedelta(minutes=1),
    )

    assert first.keyset_revision == 2
    assert console.verify_config(third).version == 3
    latest = await console.latest_config("gateway")
    assert latest is not None and latest.document.version == 3
    assert latest.document.published_by == OPERATOR.subject_id
    assert latest.document.released_at == NOW + timedelta(minutes=1)


async def test_release_sequence_never_rolls_back() -> None:
    console, _ = _console()
    await console.publish_config(
        config_id="gateway",
        version=2,
        payload={"mode": "strict"},
        principal=OPERATOR,
        now=NOW,
    )

    with pytest.raises(OperationsDowngradeRejected, match="never roll back"):
        await console.publish_config(
            config_id="gateway",
            version=1,
            payload={"mode": "strict"},
            principal=OPERATOR,
            now=NOW,
        )
    with pytest.raises(OperationsDowngradeRejected, match="never roll back"):
        await console.publish_config(
            config_id="gateway",
            version=2,
            payload={"mode": "strict"},
            principal=OPERATOR,
            now=NOW,
        )

    other = await console.publish_config(
        config_id="ingest",
        version=1,
        payload={"window": "60"},
        principal=OPERATOR,
        now=NOW,
    )
    assert other.document.version == 1


async def test_tampered_release_signature_is_refused() -> None:
    console, _ = _console()
    signed = await console.publish_config(
        config_id="gateway",
        version=1,
        payload={"mode": "strict"},
        principal=OPERATOR,
        now=NOW,
    )
    tampered = SignedConfigRelease(
        document=ConfigReleaseDocument(
            config_id="gateway",
            version=1,
            payload={"mode": "permissive"},
            published_by=OPERATOR.subject_id,
            released_at=NOW,
        ),
        key_id=signed.key_id,
        signature=signed.signature,
        keyset_revision=signed.keyset_revision,
    )
    with pytest.raises(OperationsSignatureInvalid):
        console.verify_config(tampered)


async def test_release_key_must_be_known_and_unrevoked() -> None:
    console, _ = _console()
    signed = await console.publish_config(
        config_id="gateway",
        version=1,
        payload={"mode": "strict"},
        principal=OPERATOR,
        now=NOW,
    )
    for key_id in ("operations/1", "operations/9"):
        bad = SignedConfigRelease(
            document=signed.document,
            key_id=key_id,
            signature=signed.signature,
            keyset_revision=signed.keyset_revision,
        )
        with pytest.raises(OperationsSigningKeyUnknown):
            console.verify_config(bad)


async def test_release_payload_must_be_text() -> None:
    with pytest.raises(OperationsMalformed, match="must be text"):
        ConfigReleaseDocument(
            config_id="gateway",
            version=1,
            payload={"retries": 3},  # type: ignore[dict-item]
            published_by=OPERATOR.subject_id,
            released_at=NOW,
        )


# ---------------------------------------------------------------------------
# Upgrade-order decisions from the product registry
# ---------------------------------------------------------------------------


def _registry(**overrides: object) -> ProductRegistry:
    values: dict[str, object] = {
        "product_id": "alpha",
        "supported_schema_versions": ("3", "4", "5"),
        "migration_order": ("1", "2", "3", "4", "5"),
        "minimum_versions": {"schema": "3"},
    }
    values.update(overrides)
    record = ProductRecord(**values)  # type: ignore[arg-type]
    return ProductRegistry(
        catalog=ProductCatalog(products=(record,)), policy=NumericPolicy()
    )


def test_ordered_upgrade_follows_the_migration_order() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="2",
        declared_targets=("3", "4"),
    )
    assert decision.kind is UpgradeOrderKind.ORDERED
    assert decision.upgrade_path == ("3", "4")


def test_ordered_path_includes_undeclared_intermediate_steps() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="2",
        declared_targets=("5",),
    )
    assert decision.kind is UpgradeOrderKind.ORDERED
    assert decision.upgrade_path == ("3", "4", "5")


def test_out_of_order_targets_are_refused() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="2",
        declared_targets=("5", "4"),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_OUT_OF_ORDER
    assert decision.upgrade_path == ()


def test_downgrade_target_is_refused() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="4",
        declared_targets=("3",),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_OUT_OF_ORDER


def test_declaring_the_current_version_is_not_an_upgrade() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="4",
        declared_targets=("4", "5"),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_OUT_OF_ORDER


def test_incompatible_target_is_refused() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="3",
        declared_targets=("9",),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_INCOMPATIBLE
    assert decision.upgrade_path == ()


def test_unregistered_product_is_refused() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="omega",
        current_version="3",
        declared_targets=("4",),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_INCOMPATIBLE


def test_target_below_minimum_version_is_refused() -> None:
    decision = validate_upgrade_order(
        _registry(minimum_versions={"schema": "4"}),
        product_id="alpha",
        current_version="2",
        declared_targets=("3",),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_INCOMPATIBLE
    assert "minimum" in decision.reason


def test_current_version_off_the_migration_order_is_refused() -> None:
    decision = validate_upgrade_order(
        _registry(),
        product_id="alpha",
        current_version="0",
        declared_targets=("4",),
    )
    assert decision.kind is UpgradeOrderKind.REJECTED_OUT_OF_ORDER


def test_product_without_migration_order_falls_back_to_the_policy() -> None:
    registry = _registry(migration_order=())
    ordered = validate_upgrade_order(
        registry,
        product_id="alpha",
        current_version="3",
        declared_targets=("5",),
    )
    assert ordered.kind is UpgradeOrderKind.ORDERED
    assert ordered.upgrade_path == ("5",)

    backwards = validate_upgrade_order(
        registry,
        product_id="alpha",
        current_version="4",
        declared_targets=("3",),
    )
    assert backwards.kind is UpgradeOrderKind.REJECTED_OUT_OF_ORDER


def test_empty_upgrade_declaration_is_malformed() -> None:
    with pytest.raises(OperationsMalformed, match="at least one target"):
        validate_upgrade_order(
            _registry(),
            product_id="alpha",
            current_version="2",
            declared_targets=(),
        )


def test_command_purpose_vocabulary() -> None:
    assert command_purpose(OperationsAction.CLOSE, OperationsObjectKind.LICENSE) == (
        "license.close"
    )
    assert command_purpose(
        OperationsAction.REGISTER, OperationsObjectKind.PRODUCT_REGISTRATION
    ) == "product-registration.register"
    with pytest.raises(OperationsMalformed, match="whitelist"):
        command_purpose(OperationsAction.CREATE, OperationsObjectKind.DEVICE)
