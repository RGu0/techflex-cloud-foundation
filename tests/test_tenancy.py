from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from techflex_cloud_foundation import (
    CompositeTenantReference,
    DatabaseIntrospectionSnapshot,
    DatabaseRoleSnapshot,
    HmacTokenCodec,
    InMemoryTenantConnectionPool,
    RequestValidator,
    RlsContract,
    RlsContractViolation,
    RlsPolicySnapshot,
    RlsTableSnapshot,
    TenancyMalformed,
    TenantContext,
    TenantContextLeaked,
    TenantContextMissing,
    TenantDataPlane,
    TenantIsolationViolation,
    TrustedRequestContext,
    parse_introspection_snapshot,
)

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


SECRET = b"t" * 32


def _codec() -> HmacTokenCodec:
    return HmacTokenCodec(
        secret=SECRET, key_id="tenant/1", token_type="access", audience="tenant-data"
    )


def _trusted(
    tenant: str = "tenant-a", subject: str = "operator-1"
) -> TrustedRequestContext:
    codec = _codec()
    now = datetime.now(UTC)
    token = codec.issue(
        {"tenant_id": tenant, "sub": subject}, expires_at=now + timedelta(days=1)
    )
    validator = RequestValidator(codec, max_payload_bytes=1024)
    return validator.validate(f"Bearer {token}", now=now)


def test_tenant_context_comes_from_the_trusted_request_context() -> None:
    context = TenantContext.from_request(_trusted())

    assert context.tenant_id == "tenant-a"
    assert context.subject_id == "operator-1"


def test_tenant_context_requires_non_empty_identifiers() -> None:
    with pytest.raises(TenancyMalformed):
        TenantContext(tenant_id="", subject_id="operator-1")


async def test_scope_binds_the_tenant_and_clears_it_on_exit() -> None:
    pool = InMemoryTenantConnectionPool()
    plane = TenantDataPlane(pool)
    context = TenantContext.from_request(_trusted())

    async with plane.scope(context) as session:
        assert session.tenant_id == "tenant-a"
        assert await session.connection.current_tenant() == "tenant-a"

    assert await pool.last_connection.current_tenant() is None


async def test_session_refuses_use_after_the_scope_closes() -> None:
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    context = TenantContext.from_request(_trusted())

    async with plane.scope(context) as session:
        pass

    with pytest.raises(TenantContextMissing):
        _ = session.connection


async def test_a_failure_inside_the_scope_still_clears_the_tenant() -> None:
    pool = InMemoryTenantConnectionPool()
    plane = TenantDataPlane(pool)
    context = TenantContext.from_request(_trusted())

    with pytest.raises(RuntimeError):
        async with plane.scope(context):
            raise RuntimeError("work failed")

    assert await pool.last_connection.current_tenant() is None


async def test_connection_reuse_never_inherits_the_previous_tenant() -> None:
    pool = InMemoryTenantConnectionPool()
    plane = TenantDataPlane(pool)

    async with plane.scope(TenantContext.from_request(_trusted("tenant-a"))) as first:
        first_connection = first.connection
        assert await first_connection.current_tenant() == "tenant-a"

    async with plane.scope(TenantContext.from_request(_trusted("tenant-b"))) as second:
        second_connection = second.connection
        assert await second_connection.current_tenant() == "tenant-b"

    # The isolation only means anything because it is one connection twice.
    assert pool.acquired_count == 2
    assert first_connection is second_connection


async def test_a_connection_returned_with_residual_context_is_an_error() -> None:
    # A driver whose reset silently no-ops, so the residue survives the scope.
    pool = InMemoryTenantConnectionPool(clear_succeeds=False)
    plane = TenantDataPlane(pool)
    context = TenantContext.from_request(_trusted())

    with pytest.raises(TenantContextLeaked):
        async with plane.scope(context):
            pass


async def test_a_payload_supplied_tenant_cannot_open_a_scope() -> None:
    plane = TenantDataPlane(InMemoryTenantConnectionPool())

    with pytest.raises(TenancyMalformed):
        async with plane.scope("tenant-b"):  # type: ignore[arg-type]
            pass


def test_a_composite_reference_stays_inside_its_own_tenant() -> None:
    context = TenantContext.from_request(_trusted("tenant-a"))
    reference = CompositeTenantReference(tenant_id="tenant-a", entity_id="artifact-1")

    reference.ensure_within(context)


def test_a_composite_reference_cannot_point_across_tenants() -> None:
    context = TenantContext.from_request(_trusted("tenant-a"))
    foreign = CompositeTenantReference(tenant_id="tenant-b", entity_id="artifact-1")

    with pytest.raises(TenantIsolationViolation):
        foreign.ensure_within(context)


@pytest.mark.parametrize(
    "owner,borrower",
    [
        ("tenant-a", "tenant-b"),
        ("tenant-b", "tenant-a"),
        ("tenant-a", "tenant-a-2"),
        ("t", "t "),
    ],
)
def test_no_distinct_tenant_pair_ever_accepts_the_other(
    owner: str, borrower: str
) -> None:
    context = TenantContext(tenant_id=borrower, subject_id="operator-1")
    reference = CompositeTenantReference(tenant_id=owner, entity_id="row-1")

    with pytest.raises(TenantIsolationViolation):
        reference.ensure_within(context)


async def test_a_session_refuses_a_reference_from_another_tenant() -> None:
    plane = TenantDataPlane(InMemoryTenantConnectionPool())
    context = TenantContext.from_request(_trusted("tenant-a"))

    async with plane.scope(context) as session:
        session.ensure_owns(
            CompositeTenantReference(tenant_id="tenant-a", entity_id="row-1")
        )
        with pytest.raises(TenantIsolationViolation):
            session.ensure_owns(
                CompositeTenantReference(tenant_id="tenant-b", entity_id="row-1")
            )


TENANT_SETTING = "app.tenant_id"


def _policy(**overrides: object) -> RlsPolicySnapshot:
    values: dict[str, object] = {
        "name": "tenant_isolation",
        "command": "ALL",
        "using_expression": "tenant_id = current_setting('app.tenant_id')",
        "check_expression": "tenant_id = current_setting('app.tenant_id')",
    }
    values.update(overrides)
    return RlsPolicySnapshot(**values)  # type: ignore[arg-type]


def _table(**overrides: object) -> RlsTableSnapshot:
    values: dict[str, object] = {
        "schema": "artifact_registry",
        "table": "artifact",
        "rls_enabled": True,
        "rls_forced": True,
        "owner": "platform_migrator",
        "policies": (_policy(),),
    }
    values.update(overrides)
    return RlsTableSnapshot(**values)  # type: ignore[arg-type]


def _role(**overrides: object) -> DatabaseRoleSnapshot:
    values: dict[str, object] = {
        "name": "platform_app",
        "is_superuser": False,
        "bypasses_rls": False,
        "owned_tables": (),
    }
    values.update(overrides)
    return DatabaseRoleSnapshot(**values)  # type: ignore[arg-type]


def _snapshot(**overrides: object) -> DatabaseIntrospectionSnapshot:
    values: dict[str, object] = {
        "application_role": _role(),
        "tables": (_table(),),
    }
    values.update(overrides)
    return DatabaseIntrospectionSnapshot(**values)  # type: ignore[arg-type]


def _contract(**overrides: object) -> RlsContract:
    values: dict[str, object] = {
        "tenant_setting": TENANT_SETTING,
        "required_tables": ("artifact_registry.artifact",),
    }
    values.update(overrides)
    return RlsContract(**values)  # type: ignore[arg-type]


def test_a_compliant_deployment_satisfies_the_contract() -> None:
    report = _contract().validate(_snapshot())

    assert report.satisfied
    assert report.findings == ()
    report.require_satisfied()


def test_a_required_table_absent_from_the_snapshot_is_a_finding() -> None:
    report = _contract(
        required_tables=("artifact_registry.artifact", "operations.outbox")
    ).validate(_snapshot())

    assert [finding.code for finding in report.findings] == ["table_missing"]
    with pytest.raises(RlsContractViolation):
        report.require_satisfied()


def test_row_level_security_switched_off_is_a_finding() -> None:
    report = _contract().validate(_snapshot(tables=(_table(rls_enabled=False),)))

    assert "rls_disabled" in [finding.code for finding in report.findings]


def test_row_level_security_that_is_not_forced_is_a_finding() -> None:
    report = _contract().validate(_snapshot(tables=(_table(rls_forced=False),)))

    assert "rls_not_forced" in [finding.code for finding in report.findings]


def test_a_table_without_any_policy_is_a_finding() -> None:
    report = _contract().validate(_snapshot(tables=(_table(policies=()),)))

    assert "no_policy" in [finding.code for finding in report.findings]


def test_a_policy_that_ignores_the_tenant_setting_is_a_finding() -> None:
    loose = _policy(
        using_expression="true", check_expression="true"
    )
    report = _contract().validate(_snapshot(tables=(_table(policies=(loose,)),)))

    assert "policy_ignores_tenant_setting" in [f.code for f in report.findings]


def test_a_policy_missing_its_write_check_is_a_finding() -> None:
    write_open = _policy(check_expression=None)
    report = _contract().validate(_snapshot(tables=(_table(policies=(write_open,)),)))

    assert "policy_ignores_tenant_setting" in [f.code for f in report.findings]


def test_a_superuser_application_role_is_a_finding() -> None:
    report = _contract().validate(_snapshot(application_role=_role(is_superuser=True)))

    assert "role_is_superuser" in [finding.code for finding in report.findings]


def test_an_application_role_that_bypasses_rls_is_a_finding() -> None:
    report = _contract().validate(_snapshot(application_role=_role(bypasses_rls=True)))

    assert "role_bypasses_rls" in [finding.code for finding in report.findings]


def test_an_application_role_owning_a_required_table_is_a_finding() -> None:
    owner_role = _role(owned_tables=("artifact_registry.artifact",))
    report = _contract().validate(
        _snapshot(
            application_role=owner_role,
            tables=(_table(owner="platform_app"),),
        )
    )

    assert "role_owns_table" in [finding.code for finding in report.findings]


def test_a_table_outside_the_contract_is_not_judged() -> None:
    product_table = _table(
        schema="product_feet",
        table="session",
        rls_enabled=False,
        rls_forced=False,
        policies=(),
    )
    report = _contract().validate(_snapshot(tables=(_table(), product_table)))

    assert report.satisfied


def test_a_snapshot_document_cannot_smuggle_a_credential() -> None:
    document = {
        "application_role": {
            "name": "platform_app",
            "is_superuser": False,
            "bypasses_rls": False,
            "owned_tables": [],
            "password": "hunter2",
        },
        "tables": [],
    }

    with pytest.raises(TenancyMalformed):
        parse_introspection_snapshot(document)


def test_a_snapshot_document_cannot_carry_a_connection_string() -> None:
    document = {
        "application_role": {
            "name": "platform_app",
            "is_superuser": False,
            "bypasses_rls": False,
            "owned_tables": [],
        },
        "tables": [],
        "dsn": "postgresql://user:pw@host/db",
    }

    with pytest.raises(TenancyMalformed):
        parse_introspection_snapshot(document)


def test_a_well_formed_snapshot_document_parses() -> None:
    document = {
        "application_role": {
            "name": "platform_app",
            "is_superuser": False,
            "bypasses_rls": False,
            "owned_tables": [],
        },
        "tables": [
            {
                "schema": "artifact_registry",
                "table": "artifact",
                "rls_enabled": True,
                "rls_forced": True,
                "owner": "platform_migrator",
                "policies": [
                    {
                        "name": "tenant_isolation",
                        "command": "ALL",
                        "using_expression": (
                            "tenant_id = current_setting('app.tenant_id')"
                        ),
                        "check_expression": (
                            "tenant_id = current_setting('app.tenant_id')"
                        ),
                    }
                ],
            }
        ],
    }

    snapshot = parse_introspection_snapshot(document)

    assert _contract().validate(snapshot).satisfied


class _RefusingConnection:
    """A driver that refuses the ``SET`` binding the tenant."""

    def __init__(self) -> None:
        self._tenant: str | None = None

    async def set_tenant(self, tenant_id: str) -> None:
        raise RuntimeError("driver refused SET")

    async def clear_tenant(self) -> None:
        self._tenant = None

    async def current_tenant(self) -> str | None:
        return self._tenant


class _RecordingPool:
    def __init__(self, connection: object) -> None:
        self._connection = connection
        self.released: list[object] = []

    async def acquire(self) -> object:
        return self._connection

    async def release(self, connection: object) -> None:
        self.released.append(connection)


async def test_a_failure_binding_the_tenant_still_returns_the_connection() -> None:
    connection = _RefusingConnection()
    pool = _RecordingPool(connection)
    plane = TenantDataPlane(pool)  # type: ignore[arg-type]

    with pytest.raises(RuntimeError):
        async with plane.scope(TenantContext.from_request(_trusted())):
            pass

    assert pool.released == [connection]


def test_a_policy_command_this_contract_does_not_know_is_refused() -> None:
    # PostgreSQL policies take ALL/SELECT/INSERT/UPDATE/DELETE.  Anything else
    # would be checked against neither clause set and pass unexamined.
    with pytest.raises(TenancyMalformed):
        RlsPolicySnapshot(
            name="merge_rows",
            command="MERGE",
            using_expression="tenant_id = current_setting('app.tenant_id')",
        )
