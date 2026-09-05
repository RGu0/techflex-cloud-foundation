"""PostgreSQL tenant data plane (CP-08).

The server-side isolation boundary for tenant-scoped data: a `TenantContext`
derived only from an already-authenticated request, a transaction scope that
binds that tenant for the life of the work and clears it before the
connection goes back to the pool, composite references that cannot point
across tenants, and a row-level-security contract with a validator that
decides a deployment from an introspection snapshot.

Invariants carried over from RAY-341 and the deployment architecture:

- tenant comes only from the trusted authentication context; nothing in a
  request payload can select it.
- A data-plane operation without a bound tenant is refused, never run
  unscoped.
- A connection returned to the pool carrying tenant context is an error, not
  a warning: the next borrower would inherit it.
- RLS is not the only boundary — composite references and query scoping
  constrain the tenant as well, so a child row cannot reference a parent in
  another tenant.
- The validator reads a snapshot of catalog facts, never a live connection,
  and no credential ever enters a snapshot, a report, or this package.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any, Protocol

from .gateway import TrustedRequestContext
from .manifest import ManifestMalformed
from .manifest import _require_text as _manifest_require_text


class TenancyError(Exception):
    """Base class for tenant data-plane failures."""


class TenancyMalformed(TenancyError):
    """A context, reference, snapshot, or contract is structurally invalid."""


class TenantContextMissing(TenancyError):
    """A data-plane operation was attempted with no tenant bound."""


class TenantContextLeaked(TenancyError):
    """A connection still carried tenant context when the scope ended."""


class TenantIsolationViolation(TenancyError):
    """A reference or row belongs to a tenant other than the bound one."""


class RlsContractViolation(TenancyError):
    """A deployment's introspection snapshot fails the RLS contract."""


def _require_text(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise TenancyMalformed(str(exc)) from exc


@dataclass(frozen=True)
class TenantContext:
    """The tenant a unit of work runs under, derived from trusted auth.

    Build one with :meth:`from_request`.  The tenant is never taken from a
    request payload, a query parameter, or any other client-supplied value.
    """

    tenant_id: str
    subject_id: str

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.subject_id, field_name="subject id")

    @classmethod
    def from_request(cls, request: TrustedRequestContext) -> TenantContext:
        """Derive the data-plane tenant from an authenticated request."""
        if not isinstance(request, TrustedRequestContext):
            raise TenancyMalformed(
                "tenant context must be derived from a TrustedRequestContext; "
                "the tenant is never taken from a request payload"
            )
        return cls(tenant_id=request.tenant_id, subject_id=request.subject_id)


@dataclass(frozen=True)
class CompositeTenantReference:
    """A foreign key that carries its tenant, so it cannot cross tenants.

    A bare ``entity_id`` reference is only as good as the query that resolved
    it; carrying the tenant alongside makes a cross-tenant parent a type-level
    fact the child can check, independently of RLS.
    """

    tenant_id: str
    entity_id: str

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.entity_id, field_name="entity id")

    def ensure_within(self, context: TenantContext) -> None:
        """Refuse a reference whose tenant is not the bound one."""
        if not isinstance(context, TenantContext):
            raise TenancyMalformed("a tenant check requires a TenantContext")
        if self.tenant_id != context.tenant_id:
            raise TenantIsolationViolation(
                f"reference {self.entity_id!r} belongs to another tenant; "
                "a composite reference never crosses a tenant boundary"
            )


class TenantConnection(Protocol):
    """One pooled connection whose tenant context can be set and cleared."""

    async def set_tenant(self, tenant_id: str) -> None: ...

    async def clear_tenant(self) -> None: ...

    async def current_tenant(self) -> str | None: ...


class TenantConnectionPool(Protocol):
    """Connection source; production binds a real pool, tests use memory."""

    async def acquire(self) -> TenantConnection: ...

    async def release(self, connection: TenantConnection) -> None: ...


class TenantScopedSession:
    """A unit of work with exactly one tenant bound for its whole life.

    ``connection`` is reachable only while the scope is open.  Reaching for it
    afterwards raises rather than handing back a connection whose tenant
    context has already been cleared and which may already belong to another
    borrower.
    """

    def __init__(self, context: TenantContext, connection: TenantConnection) -> None:
        self._context = context
        self._connection: TenantConnection | None = connection

    @property
    def tenant_id(self) -> str:
        return self._context.tenant_id

    @property
    def subject_id(self) -> str:
        return self._context.subject_id

    @property
    def connection(self) -> TenantConnection:
        if self._connection is None:
            raise TenantContextMissing(
                "this session is closed; a data-plane operation must run "
                "inside an open tenant scope"
            )
        return self._connection

    def ensure_owns(self, reference: CompositeTenantReference) -> None:
        """Refuse a reference from another tenant before it reaches SQL."""
        if self._connection is None:
            raise TenantContextMissing(
                "this session is closed; a tenant check must run inside an "
                "open tenant scope"
            )
        reference.ensure_within(self._context)

    def _close(self) -> None:
        self._connection = None


class TenantDataPlane:
    """Binds a tenant for the length of a scope and proves it was cleared.

    The clear is checked, not assumed.  A driver whose reset silently does
    nothing leaves the next borrower reading another tenant's rows under a
    stale ``SET``, and the pool would hand that connection out again; so a
    connection that still reports a tenant is raised on and never released.
    """

    def __init__(self, pool: TenantConnectionPool) -> None:
        self._pool = pool

    @asynccontextmanager
    async def scope(
        self, context: TenantContext
    ) -> AsyncIterator[TenantScopedSession]:
        """Run work under one tenant; clear and verify before release."""
        if not isinstance(context, TenantContext):
            raise TenancyMalformed(
                "a tenant scope requires a TenantContext derived from trusted "
                "authentication"
            )
        connection = await self._pool.acquire()
        # The bind is inside the try: a driver that refuses the ``SET`` would
        # otherwise strand an acquired connection, uncleared and unreturned,
        # on exactly the path where the tenant is least certain.
        session: TenantScopedSession | None = None
        try:
            await connection.set_tenant(context.tenant_id)
            session = TenantScopedSession(context, connection)
            yield session
        finally:
            if session is not None:
                session._close()
            await connection.clear_tenant()
            residue = await connection.current_tenant()
            if residue is not None:
                raise TenantContextLeaked(
                    f"connection still carries tenant {residue!r} after the "
                    "scope ended; it is not returned to the pool"
                )
            await self._pool.release(connection)


class InMemoryTenantConnection:
    """Volatile reference connection that records its bound tenant."""

    def __init__(self, *, clear_succeeds: bool = True) -> None:
        self._tenant: str | None = None
        self._clear_succeeds = clear_succeeds

    async def set_tenant(self, tenant_id: str) -> None:
        _require_text(tenant_id, field_name="tenant id")
        self._tenant = tenant_id

    async def clear_tenant(self) -> None:
        if self._clear_succeeds:
            self._tenant = None

    async def current_tenant(self) -> str | None:
        return self._tenant


class InMemoryTenantConnectionPool:
    """Reference pool that hands out one connection, so reuse is observable."""

    def __init__(self, *, clear_succeeds: bool = True) -> None:
        self._connection = InMemoryTenantConnection(clear_succeeds=clear_succeeds)
        self._acquired_count = 0

    @property
    def last_connection(self) -> InMemoryTenantConnection:
        return self._connection

    @property
    def acquired_count(self) -> int:
        return self._acquired_count

    async def acquire(self) -> TenantConnection:
        self._acquired_count += 1
        return self._connection

    async def release(self, connection: TenantConnection) -> None:
        return None


# A policy's USING clause decides which existing rows are visible; its WITH
# CHECK clause decides which rows may be written.  PostgreSQL only accepts
# each clause for the commands it applies to, so a contract that demanded
# both everywhere would fail a correct deployment.
_COMMANDS_WITH_USING = frozenset({"ALL", "SELECT", "UPDATE", "DELETE"})
_COMMANDS_WITH_CHECK = frozenset({"ALL", "INSERT", "UPDATE"})
_POLICY_COMMANDS = _COMMANDS_WITH_USING | _COMMANDS_WITH_CHECK


@dataclass(frozen=True)
class RlsPolicySnapshot:
    """One catalog policy row, as read from ``pg_policies``."""

    name: str
    command: str
    using_expression: str | None = None
    check_expression: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.name, field_name="policy name")
        _require_text(self.command, field_name="policy command")
        object.__setattr__(self, "command", self.command.upper())
        # A command this contract does not know would match neither clause set
        # and so pass without a single check.  Refuse it instead: an unexamined
        # policy reading as compliant is the one outcome a validator must not
        # produce.
        if self.command not in _POLICY_COMMANDS:
            raise TenancyMalformed(
                f"policy command {self.command!r} is not one this contract "
                f"knows ({', '.join(sorted(_POLICY_COMMANDS))}); an unknown "
                "command is refused, never assumed compliant"
            )

    def unconstrained_clauses(self, tenant_setting: str) -> tuple[str, ...]:
        """Name the clauses that fail to mention the tenant setting."""
        missing: list[str] = []
        if self.command in _COMMANDS_WITH_USING and not _mentions(
            self.using_expression, tenant_setting
        ):
            missing.append("USING")
        if self.command in _COMMANDS_WITH_CHECK and not _mentions(
            self.check_expression, tenant_setting
        ):
            missing.append("WITH CHECK")
        return tuple(missing)


def _mentions(expression: str | None, tenant_setting: str) -> bool:
    """Whether a catalog expression constrains rows by the tenant setting.

    This is a textual check over catalog text, not a proof: it establishes
    that the deployment's policy is written against the tenant setting this
    contract binds, which is what a snapshot can honestly show.  Proving that
    the predicate is *sufficient* needs cross-tenant tests against a live
    database, which belong to the deployment's own acceptance, not here.
    """

    return expression is not None and tenant_setting in expression


@dataclass(frozen=True)
class RlsTableSnapshot:
    """One table's row-level-security facts, as read from the catalog."""

    schema: str
    table: str
    rls_enabled: bool
    rls_forced: bool
    owner: str
    policies: tuple[RlsPolicySnapshot, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.schema, field_name="schema name")
        _require_text(self.table, field_name="table name")
        _require_text(self.owner, field_name="table owner")
        for flag, name in ((self.rls_enabled, "rls_enabled"), (self.rls_forced, "rls_forced")):
            if not isinstance(flag, bool):
                raise TenancyMalformed(f"{name} must be a boolean")

    @property
    def qualified_name(self) -> str:
        return f"{self.schema}.{self.table}"


@dataclass(frozen=True)
class DatabaseRoleSnapshot:
    """The role the application connects as, and what it may bypass."""

    name: str
    is_superuser: bool
    bypasses_rls: bool
    owned_tables: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.name, field_name="role name")
        for flag, field in (
            (self.is_superuser, "is_superuser"),
            (self.bypasses_rls, "bypasses_rls"),
        ):
            if not isinstance(flag, bool):
                raise TenancyMalformed(f"{field} must be a boolean")


@dataclass(frozen=True)
class DatabaseIntrospectionSnapshot:
    """Catalog facts a deployment presents for validation.

    A snapshot carries names and flags only.  No host, port, DSN, password,
    or key reference belongs here, and :func:`parse_introspection_snapshot`
    refuses a document that carries one, so a validation receipt built from a
    snapshot cannot leak a credential.
    """

    application_role: DatabaseRoleSnapshot
    tables: tuple[RlsTableSnapshot, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.application_role, DatabaseRoleSnapshot):
            raise TenancyMalformed("application_role must be a DatabaseRoleSnapshot")
        names = [table.qualified_name for table in self.tables]
        if len(set(names)) != len(names):
            raise TenancyMalformed("a table appears twice in the snapshot")

    def table_named(self, qualified_name: str) -> RlsTableSnapshot | None:
        for table in self.tables:
            if table.qualified_name == qualified_name:
                return table
        return None


@dataclass(frozen=True)
class RlsFinding:
    """One way a deployment departs from the contract."""

    code: str
    subject: str
    detail: str


@dataclass(frozen=True)
class RlsValidationReport:
    """The contract's verdict; empty findings means the deployment complies."""

    findings: tuple[RlsFinding, ...] = ()

    @property
    def satisfied(self) -> bool:
        return not self.findings

    def require_satisfied(self) -> None:
        """Raise unless the deployment satisfies every clause."""
        if self.findings:
            summary = "; ".join(
                f"{finding.code} on {finding.subject}" for finding in self.findings
            )
            raise RlsContractViolation(
                f"deployment does not satisfy the RLS contract: {summary}"
            )


@dataclass(frozen=True)
class RlsContract:
    """What a compliant tenant data plane must show in the catalog.

    Evaluated against a :class:`DatabaseIntrospectionSnapshot` rather than a
    live connection, so the contract is checkable wherever the snapshot can be
    carried -- in tests, in CI with no database, and in a deployment's own
    readiness gate through an adapter that reads ``pg_catalog``.
    """

    tenant_setting: str
    required_tables: tuple[str, ...]

    def __post_init__(self) -> None:
        _require_text(self.tenant_setting, field_name="tenant setting")
        if not self.required_tables:
            raise TenancyMalformed("a contract must require at least one table")
        for name in self.required_tables:
            _require_text(name, field_name="required table")
            if name.count(".") != 1 or name.startswith(".") or name.endswith("."):
                raise TenancyMalformed(
                    f"required table {name!r} must be schema-qualified as "
                    "'schema.table'"
                )
        if len(set(self.required_tables)) != len(self.required_tables):
            raise TenancyMalformed("a table is required twice")

    def validate(
        self, snapshot: DatabaseIntrospectionSnapshot
    ) -> RlsValidationReport:
        """Decide one deployment; a table outside the contract is not judged."""
        if not isinstance(snapshot, DatabaseIntrospectionSnapshot):
            raise TenancyMalformed(
                "validation requires a DatabaseIntrospectionSnapshot"
            )
        findings: list[RlsFinding] = []
        findings.extend(self._role_findings(snapshot))
        for qualified_name in self.required_tables:
            findings.extend(self._table_findings(snapshot, qualified_name))
        return RlsValidationReport(tuple(findings))

    def _role_findings(
        self, snapshot: DatabaseIntrospectionSnapshot
    ) -> list[RlsFinding]:
        role = snapshot.application_role
        findings: list[RlsFinding] = []
        if role.is_superuser:
            findings.append(
                RlsFinding(
                    code="role_is_superuser",
                    subject=role.name,
                    detail="a superuser is never subject to row-level security",
                )
            )
        if role.bypasses_rls:
            findings.append(
                RlsFinding(
                    code="role_bypasses_rls",
                    subject=role.name,
                    detail="BYPASSRLS makes every policy advisory",
                )
            )
        owned = [
            name
            for name in self.required_tables
            if name in role.owned_tables
            or (
                (table := snapshot.table_named(name)) is not None
                and table.owner == role.name
            )
        ]
        for name in owned:
            findings.append(
                RlsFinding(
                    code="role_owns_table",
                    subject=name,
                    detail=(
                        f"the application role {role.name!r} owns this table; an "
                        "owner escapes its own policies unless RLS is forced, and "
                        "can drop them outright"
                    ),
                )
            )
        return findings

    def _table_findings(
        self, snapshot: DatabaseIntrospectionSnapshot, qualified_name: str
    ) -> list[RlsFinding]:
        table = snapshot.table_named(qualified_name)
        if table is None:
            return [
                RlsFinding(
                    code="table_missing",
                    subject=qualified_name,
                    detail=(
                        "the contract requires this table; the snapshot does not "
                        "show it, so nothing is known about its isolation"
                    ),
                )
            ]
        findings: list[RlsFinding] = []
        if not table.rls_enabled:
            findings.append(
                RlsFinding(
                    code="rls_disabled",
                    subject=qualified_name,
                    detail="row-level security is off; every row is visible",
                )
            )
        if not table.rls_forced:
            findings.append(
                RlsFinding(
                    code="rls_not_forced",
                    subject=qualified_name,
                    detail=(
                        "without FORCE, the table owner reads and writes past "
                        "every policy"
                    ),
                )
            )
        if not table.policies:
            findings.append(
                RlsFinding(
                    code="no_policy",
                    subject=qualified_name,
                    detail=(
                        "no policy constrains this table to a tenant; enabling "
                        "RLS without one denies everything or, once a permissive "
                        "policy appears, allows everything"
                    ),
                )
            )
        for policy in table.policies:
            # Permissive policies are OR-ed, so one clause that ignores the
            # tenant widens access no matter how strict its neighbours are.
            # Every policy on a required table has to constrain the tenant.
            clauses = policy.unconstrained_clauses(self.tenant_setting)
            if clauses:
                findings.append(
                    RlsFinding(
                        code="policy_ignores_tenant_setting",
                        subject=f"{qualified_name}.{policy.name}",
                        detail=(
                            f"{' and '.join(clauses)} does not constrain rows by "
                            f"{self.tenant_setting!r}; permissive policies are "
                            "OR-ed, so this one widens access"
                        ),
                    )
                )
        return findings


def _require_known_fields(
    document: Mapping[str, Any], allowed: frozenset[str], *, what: str
) -> None:
    if not isinstance(document, Mapping):
        raise TenancyMalformed(f"{what} must be a mapping")
    unknown = sorted(set(document) - allowed)
    if unknown:
        raise TenancyMalformed(
            f"{what} carries unknown field(s) {unknown}; a snapshot holds catalog "
            "names and flags only, never a credential or connection string"
        )


_POLICY_FIELDS = frozenset({"name", "command", "using_expression", "check_expression"})
_TABLE_FIELDS = frozenset(
    {"schema", "table", "rls_enabled", "rls_forced", "owner", "policies"}
)
_ROLE_FIELDS = frozenset({"name", "is_superuser", "bypasses_rls", "owned_tables"})
_SNAPSHOT_FIELDS = frozenset({"application_role", "tables"})


def parse_introspection_snapshot(
    document: Mapping[str, Any],
) -> DatabaseIntrospectionSnapshot:
    """Parse a snapshot document, refusing any field this contract does not know.

    Refusing unknown fields is what keeps a credential out: an adapter that
    hands over its whole connection record, or a hand-written document with a
    ``dsn`` or ``password`` beside the catalog facts, is rejected instead of
    quietly carried into a validation receipt.
    """

    _require_known_fields(document, _SNAPSHOT_FIELDS, what="snapshot")
    try:
        raw_role = document["application_role"]
    except KeyError:
        raise TenancyMalformed("snapshot is missing application_role") from None
    _require_known_fields(raw_role, _ROLE_FIELDS, what="application_role")
    role = DatabaseRoleSnapshot(
        name=raw_role.get("name", ""),
        is_superuser=raw_role.get("is_superuser", False),
        bypasses_rls=raw_role.get("bypasses_rls", False),
        owned_tables=tuple(raw_role.get("owned_tables", ())),
    )
    tables: list[RlsTableSnapshot] = []
    for raw_table in document.get("tables", ()):
        _require_known_fields(raw_table, _TABLE_FIELDS, what="table")
        policies: list[RlsPolicySnapshot] = []
        for raw_policy in raw_table.get("policies", ()):
            _require_known_fields(raw_policy, _POLICY_FIELDS, what="policy")
            policies.append(
                RlsPolicySnapshot(
                    name=raw_policy.get("name", ""),
                    command=raw_policy.get("command", ""),
                    using_expression=raw_policy.get("using_expression"),
                    check_expression=raw_policy.get("check_expression"),
                )
            )
        tables.append(
            RlsTableSnapshot(
                schema=raw_table.get("schema", ""),
                table=raw_table.get("table", ""),
                rls_enabled=raw_table.get("rls_enabled", False),
                rls_forced=raw_table.get("rls_forced", False),
                owner=raw_table.get("owner", ""),
                policies=tuple(policies),
            )
        )
    return DatabaseIntrospectionSnapshot(
        application_role=role, tables=tuple(tables)
    )
