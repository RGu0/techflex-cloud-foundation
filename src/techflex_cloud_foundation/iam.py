"""Organization IAM: tenants, operators, roles, and sessions (CP-03).

The foundation supplies the *mechanism* for institutional identity: the
organization/tenant/site/operator entities, a role-to-permission model
evaluated against a trusted principal, account enable/disable, versioned
password hashing, an SSO adapter boundary, and refresh-session rotation.
It never supplies the business meaning: role *names*, seat and device-group
rules, and the onboarding/invitation/approval flow stay with the product,
and concrete identity providers stay with the deployment.

Two invariants shape everything here:

- **Platform IAM and tenant IAM are separate.**  ``PlatformPrincipal`` and
  ``TenantPrincipal`` are distinct types signed under distinct audiences, so
  a platform credential cannot be presented as a tenant credential and a
  tenant credential cannot reach a platform permission.  A platform
  principal carries no ``tenant_id`` at all -- it cannot impersonate one.
- **Tenant comes only from a trusted authentication subject.**  Tenant
  identity is read from verified claims or from CP-02's
  ``TrustedRequestContext``; nothing here accepts a caller-supplied tenant.

Audience, key-id, and expiry checking is reused from ``tokens``; per-source
rate limiting reuses ``gateway``'s store protocol rather than growing a
second one.  Failures close: unknown accounts, wrong passwords, suspended
accounts, and closed accounts are refused identically so that login cannot
be used to enumerate organizations or operators, and a replayed refresh
token revokes its whole session family.

Real credentials, key bytes, password plaintext, and cloud account details
are never stored by these types -- only salted digests and opaque handles.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import StrEnum
import hashlib
import hmac
import secrets
from typing import Any, Protocol
from uuid import uuid4

from .gateway import RateLimitPolicy, RateLimitStore, TrustedRequestContext
from .manifest import ManifestMalformed
from .manifest import _require_text as _manifest_require_text
from .tokens import (
    HmacTokenCodec,
    TokenAudienceMismatch,
    TokenError,
    TokenHeaderMismatch,
)

_PBKDF2_ALGORITHM = "pbkdf2_sha256"
_PBKDF2_DEFAULT_ITERATIONS = 600_000
_PBKDF2_SALT_BYTES = 16
_REFRESH_SECRET_BYTES = 32

# One message for every refusal reachable from a credential.  A distinct
# message per cause -- "no such operator", "wrong password", "account
# suspended" -- is an enumeration oracle: it answers questions about the
# organization to someone who has not authenticated.  The cause is still
# available to the caller through the raised type's ``__cause__`` where one
# exists, but never through what the boundary says.
_UNIFORM_REFUSAL = "authentication refused"


class IamError(Exception):
    """Base class for identity, authorization, and session failures."""


class IamMalformed(IamError):
    """An entity, role, credential record, or token is structurally invalid."""


class IamAuthenticationRefused(IamError):
    """A credential was refused.  The message never says why."""


class IamPermissionDenied(IamError):
    """An authenticated principal lacks the required permission."""


class IamRealmMismatch(IamAuthenticationRefused):
    """A credential was recognised as belonging to the other realm.

    A refusal first, and only incidentally a more specific one.  When the two
    realms use different signing keys -- the recommended setup -- a token
    from the wrong plane fails its signature check before its audience is
    ever read, so it is indistinguishable from a forgery and arrives as a
    plain ``IamAuthenticationRefused``.  This subclass appears only where the
    boundary can actually tell the difference: codecs that share a key but
    differ in audience, and refresh sessions, which are looked up by id and
    so carry their realm with them.

    Callers therefore catch ``IamAuthenticationRefused`` to fail closed and
    treat this type as a diagnostic, never as the thing that enforces the
    separation.  The enforcement is that neither codec accepts the other's
    tokens at all.
    """


class IamSessionRefused(IamError):
    """A refresh session is unknown, expired, revoked, or does not match."""


class IamSessionReplayed(IamSessionRefused):
    """An already-rotated refresh token was presented again.

    Refresh rotation makes each token single-use, so a second presentation
    means the token leaked: either the legitimate holder's copy or an
    attacker's.  Which one cannot be determined here, so the whole session
    family is revoked rather than guessed about.
    """


class AccountState(StrEnum):
    """Neutral account lifecycle; ``CLOSED`` is terminal."""

    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class IamRealm(StrEnum):
    """Which IAM plane a role, principal, or session belongs to."""

    PLATFORM = "platform"
    TENANT = "tenant"


# The account lifecycle as a table rather than as guard clauses, matching the
# license lifecycle in ``entitlement``.  Every pair not named here is refused,
# so a transition is legal because it is written down -- not because nobody
# thought to forbid it.  Reactivation from SUSPENDED is deliberate (a lapsed
# subscription restored should not require re-creating the operator); CLOSED
# is terminal because a reopened account would silently inherit the former
# holder's memberships and sessions.
_ALLOWED_ACCOUNT_TRANSITIONS: Mapping[AccountState, frozenset[AccountState]] = {
    AccountState.ACTIVE: frozenset({AccountState.SUSPENDED, AccountState.CLOSED}),
    AccountState.SUSPENDED: frozenset({AccountState.ACTIVE, AccountState.CLOSED}),
    AccountState.CLOSED: frozenset(),
}


def _require_text(value: str, *, field_name: str) -> str:
    try:
        return _manifest_require_text(value, field_name=field_name)
    except ManifestMalformed as exc:
        raise IamMalformed(str(exc)) from exc


def _require_aware(value: datetime, *, field_name: str) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise IamMalformed(f"{field_name} must be timezone-aware")


def _require_state(value: AccountState, *, field_name: str) -> None:
    if not isinstance(value, AccountState):
        raise IamMalformed(f"{field_name} must be an AccountState")


def _require_names(values: frozenset[str], *, field_name: str) -> frozenset[str]:
    if not isinstance(values, frozenset):
        raise IamMalformed(f"{field_name} must be a frozenset")
    for value in values:
        _require_text(value, field_name=f"{field_name} entry")
    return values


def source_fingerprint(source: str, *, salt: bytes) -> str:
    """Derive a privacy-safe rate-limit key from a client-visible source.

    Login rate limiting has to key on something the caller cannot choose,
    which in practice means an address or a device identifier -- data this
    project does not keep.  Hashing it under a deployment-held salt gives a
    stable key that is useless outside the deployment and cannot be reversed
    into the address it came from, so the limiter works without the rest of
    the platform holding a log of who connected from where.
    """

    _require_text(source, field_name="rate limit source")
    if not isinstance(salt, bytes) or len(salt) < 16:
        raise IamMalformed("source fingerprint salt must be at least 16 bytes")
    return hashlib.sha256(salt + source.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Organization:
    """A customer institution.  Business fields stay with the product."""

    organization_id: str
    state: AccountState = AccountState.ACTIVE

    def __post_init__(self) -> None:
        _require_text(self.organization_id, field_name="organization id")
        _require_state(self.state, field_name="organization state")


@dataclass(frozen=True)
class Tenant:
    """One isolation boundary owned by an organization."""

    tenant_id: str
    organization_id: str
    state: AccountState = AccountState.ACTIVE

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.organization_id, field_name="organization id")
        _require_state(self.state, field_name="tenant state")


@dataclass(frozen=True)
class Site:
    """A place or deployment unit inside a tenant."""

    site_id: str
    tenant_id: str
    state: AccountState = AccountState.ACTIVE

    def __post_init__(self) -> None:
        _require_text(self.site_id, field_name="site id")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_state(self.state, field_name="site state")


@dataclass(frozen=True)
class TenantOperator:
    """A person who signs in on behalf of a tenant.

    An operator is not a ``ClientInstallation``, a terminal, a measurement
    device, a license subject, or a workload identity.  Those are separate
    identity kinds owned by CP-04 and CP-05, and conflating any of them with
    an operator would let a device credential inherit a person's permissions.
    """

    operator_id: str
    tenant_id: str
    state: AccountState = AccountState.ACTIVE
    site_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _require_text(self.operator_id, field_name="operator id")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_state(self.state, field_name="operator state")
        _require_names(self.site_ids, field_name="operator site ids")


@dataclass(frozen=True)
class ProductMembership:
    """An operator's roles within one product, scoped to one tenant."""

    operator_id: str
    tenant_id: str
    product_id: str
    role_names: frozenset[str]

    def __post_init__(self) -> None:
        _require_text(self.operator_id, field_name="operator id")
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.product_id, field_name="product id")
        _require_names(self.role_names, field_name="membership role names")


def transition_account(state: AccountState, requested: AccountState) -> AccountState:
    """Move an account along the table above, or raise.

    Disabling an account governs **new** authorization only.  It does not
    decide retention, export, or deletion of anything the account already
    produced: those need an explicit ``lifecycle.DeletionDecision``, and
    suspending an operator must not be a backdoor into erasing their data.
    """

    _require_state(state, field_name="current state")
    _require_state(requested, field_name="requested state")
    allowed = _ALLOWED_ACCOUNT_TRANSITIONS[state]
    if requested not in allowed:
        raise IamMalformed(_account_rejection_reason(state, requested))
    return requested


def _account_rejection_reason(current: AccountState, requested: AccountState) -> str:
    if current is requested:
        return f"account is already {current.value}; check the state instead of re-applying it"
    if current is AccountState.CLOSED:
        return (
            "a closed account is terminal and cannot be reopened; create a new account "
            "rather than inheriting the former holder's memberships and sessions"
        )
    return f"{current.value} -> {requested.value} is not a legal account transition"


@dataclass(frozen=True)
class Role:
    """A named permission set within one realm.

    The foundation owns the *shape* -- a name bound to permissions, scoped to
    a realm -- and nothing about which names exist.  "Clinician", "site
    admin", and every other business role is injected by the product, so
    adding one is a product change and not a change here.
    """

    name: str
    realm: IamRealm
    permissions: frozenset[str]

    def __post_init__(self) -> None:
        _require_text(self.name, field_name="role name")
        if not isinstance(self.realm, IamRealm):
            raise IamMalformed("role realm must be an IamRealm")
        _require_names(self.permissions, field_name="role permissions")


@dataclass(frozen=True)
class AuthorizationDecision:
    """The answer for one permission check, with the reason it came out that way."""

    permission: str
    realm: IamRealm
    allowed: bool
    reason: str

    def __post_init__(self) -> None:
        _require_text(self.permission, field_name="permission")
        _require_text(self.reason, field_name="decision reason")
        if not isinstance(self.realm, IamRealm):
            raise IamMalformed("decision realm must be an IamRealm")


@dataclass(frozen=True)
class PlatformPrincipal:
    """An operator of the platform itself.

    It deliberately has no ``tenant_id``.  A platform administrator manages
    organizations and accounts; giving the type somewhere to put a tenant is
    what would let one act *as* a tenant, so the field does not exist rather
    than being set to ``None`` and checked later.
    """

    subject_id: str
    role_names: frozenset[str]

    def __post_init__(self) -> None:
        _require_text(self.subject_id, field_name="platform subject id")
        _require_names(self.role_names, field_name="platform role names")


@dataclass(frozen=True)
class TenantPrincipal:
    """An operator acting inside one tenant, derived from verified claims only."""

    tenant_id: str
    operator_id: str
    role_names: frozenset[str]
    site_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _require_text(self.tenant_id, field_name="tenant id")
        _require_text(self.operator_id, field_name="operator id")
        _require_names(self.role_names, field_name="tenant role names")
        _require_names(self.site_ids, field_name="tenant site ids")


@dataclass(frozen=True)
class RoleCatalog:
    """The registered roles of both realms, evaluated against a principal."""

    roles: tuple[Role, ...]

    def __post_init__(self) -> None:
        keys = [(role.realm, role.name) for role in self.roles]
        if len(set(keys)) != len(keys):
            raise IamMalformed("role names must be unique within a realm")

    def permissions_for(self, names: frozenset[str], *, realm: IamRealm) -> frozenset[str]:
        """Union the permissions of known roles in ``realm``.

        A name registered only in the *other* realm contributes nothing.  It
        is not an error -- the same word may legitimately name a platform
        role and a tenant role -- but it must not carry permissions across
        the boundary, which is exactly what matching on name alone would do.
        """

        _require_names(names, field_name="role names")
        granted: set[str] = set()
        for role in self.roles:
            if role.realm is realm and role.name in names:
                granted |= role.permissions
        return frozenset(granted)

    def decide(
        self, principal: PlatformPrincipal | TenantPrincipal, permission: str
    ) -> AuthorizationDecision:
        """Answer one permission check for either kind of principal."""

        _require_text(permission, field_name="permission")
        realm = _realm_of(principal)
        granted = self.permissions_for(principal.role_names, realm=realm)
        allowed = permission in granted
        return AuthorizationDecision(
            permission=permission,
            realm=realm,
            allowed=allowed,
            reason=(
                f"granted by a {realm.value} role"
                if allowed
                else f"no {realm.value} role grants this permission"
            ),
        )

    def require(
        self, principal: PlatformPrincipal | TenantPrincipal, permission: str
    ) -> AuthorizationDecision:
        """Return the decision, or raise ``IamPermissionDenied``."""

        decision = self.decide(principal, permission)
        if not decision.allowed:
            raise IamPermissionDenied(decision.reason)
        return decision


def _realm_of(principal: PlatformPrincipal | TenantPrincipal) -> IamRealm:
    if isinstance(principal, PlatformPrincipal):
        return IamRealm.PLATFORM
    if isinstance(principal, TenantPrincipal):
        return IamRealm.TENANT
    raise IamMalformed("principal must be a PlatformPrincipal or a TenantPrincipal")


class PasswordHasher(Protocol):
    """Versioned password hashing; the algorithm is part of the stored value."""

    @property
    def algorithm(self) -> str: ...

    def hash(self, password: str) -> str: ...

    def verify(self, password: str, encoded: str) -> bool: ...

    def needs_rehash(self, encoded: str) -> bool: ...


class Pbkdf2PasswordHasher:
    """PBKDF2-HMAC-SHA256 reference hasher.

    Encoded as ``pbkdf2_sha256$<iterations>$<salt_hex>$<derived_hex>`` so the
    cost is stored alongside the digest: raising ``iterations`` later leaves
    existing values verifiable and reports them through ``needs_rehash``
    rather than locking their owners out.  A deployment that wants Argon2 or
    a KMS-backed hasher supplies its own ``PasswordHasher`` -- nothing here
    assumes this one.
    """

    def __init__(self, *, iterations: int = _PBKDF2_DEFAULT_ITERATIONS) -> None:
        if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
            raise IamMalformed("iterations must be a positive integer")
        self._iterations = iterations

    @property
    def algorithm(self) -> str:
        return _PBKDF2_ALGORITHM

    def hash(self, password: str) -> str:
        _require_text(password, field_name="password")
        salt = secrets.token_bytes(_PBKDF2_SALT_BYTES)
        derived = self._derive(password, salt, self._iterations)
        return f"{_PBKDF2_ALGORITHM}${self._iterations}${salt.hex()}${derived.hex()}"

    def verify(self, password: str, encoded: str) -> bool:
        _require_text(password, field_name="password")
        iterations, salt, expected = self._parse(encoded)
        derived = self._derive(password, salt, iterations)
        return hmac.compare_digest(derived, expected)

    def needs_rehash(self, encoded: str) -> bool:
        iterations, _, _ = self._parse(encoded)
        return iterations < self._iterations

    def _derive(self, password: str, salt: bytes, iterations: int) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)

    @staticmethod
    def _parse(encoded: str) -> tuple[int, bytes, bytes]:
        """Split a stored value, or raise.

        A stored hash this hasher cannot read is corruption, not a wrong
        password, so it raises instead of returning ``False``.  Returning
        ``False`` would turn a storage fault into a silent lockout that looks
        exactly like every mistyped password in the logs.
        """

        _require_text(encoded, field_name="encoded password")
        parts = encoded.split("$")
        if len(parts) != 4 or parts[0] != _PBKDF2_ALGORITHM:
            raise IamMalformed("encoded password is not a pbkdf2_sha256 value")
        try:
            iterations = int(parts[1])
            salt = bytes.fromhex(parts[2])
            expected = bytes.fromhex(parts[3])
        except ValueError as exc:
            raise IamMalformed("encoded password has malformed parameters") from exc
        if iterations < 1 or not salt or not expected:
            raise IamMalformed("encoded password has malformed parameters")
        return iterations, salt, expected


@dataclass(frozen=True)
class FederatedIdentity:
    """What an SSO provider asserts: which provider, and which subject there.

    Nothing else crosses the boundary.  Display names, mail addresses, and
    group lists are provider-shaped personal data that the foundation has no
    use for; a deployment that needs them maps them outside this contract.
    """

    provider_id: str
    external_subject: str

    def __post_init__(self) -> None:
        _require_text(self.provider_id, field_name="provider id")
        _require_text(self.external_subject, field_name="external subject")


class IdentityProvider(Protocol):
    """The SSO boundary.

    Concrete providers -- OIDC, SAML, LDAP, or a vendor MFA service -- are
    deployment concerns, so the foundation states only what it needs back
    from one.  Binding an implementation in here would make every consumer
    depend on one vendor's libraries and endpoints.
    """

    @property
    def provider_id(self) -> str: ...

    def authenticate(self, assertion: str, *, now: datetime) -> FederatedIdentity: ...


@dataclass(frozen=True)
class CredentialRecord:
    """What the credential store holds for one sign-in identity.

    ``encoded_password`` is a hash, never a password, and is ``None`` for an
    SSO-only account.  The record carries no key bytes, no recovery secret,
    and no cloud account details.
    """

    subject_id: str
    realm: IamRealm
    state: AccountState = AccountState.ACTIVE
    tenant_id: str | None = None
    encoded_password: str | None = None
    federated_subject: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.subject_id, field_name="subject id")
        if not isinstance(self.realm, IamRealm):
            raise IamMalformed("credential realm must be an IamRealm")
        _require_state(self.state, field_name="credential state")
        if self.realm is IamRealm.TENANT:
            if self.tenant_id is None:
                raise IamMalformed("a tenant credential must name its tenant")
            _require_text(self.tenant_id, field_name="tenant id")
        elif self.tenant_id is not None:
            # A platform credential with a tenant would be the one place a
            # platform administrator could acquire a tenant identity.
            raise IamMalformed("a platform credential must not name a tenant")
        if self.encoded_password is not None:
            _require_text(self.encoded_password, field_name="encoded password")
        if self.federated_subject is not None:
            _require_text(self.federated_subject, field_name="federated subject")


class CredentialStore(Protocol):
    """Lookup boundary for sign-in identities; production binds a database."""

    def find(self, realm: IamRealm, identifier: str) -> CredentialRecord | None: ...


class RoleAssignmentStore(Protocol):
    """Which roles a verified subject holds; production binds a database."""

    def roles_for(self, record: CredentialRecord) -> frozenset[str]: ...


class InMemoryCredentialStore:
    """Volatile credential lookup, suitable for tests and integration."""

    def __init__(self) -> None:
        self._records: dict[tuple[IamRealm, str], CredentialRecord] = {}

    def add(self, identifier: str, record: CredentialRecord) -> None:
        _require_text(identifier, field_name="identifier")
        self._records[(record.realm, identifier)] = record

    def find(self, realm: IamRealm, identifier: str) -> CredentialRecord | None:
        return self._records.get((realm, identifier))


class InMemoryRoleAssignmentStore:
    """Volatile role assignment, keyed by realm and subject."""

    def __init__(self) -> None:
        self._roles: dict[tuple[IamRealm, str], frozenset[str]] = {}

    def assign(self, realm: IamRealm, subject_id: str, roles: frozenset[str]) -> None:
        _require_text(subject_id, field_name="subject id")
        self._roles[(realm, subject_id)] = _require_names(roles, field_name="roles")

    def roles_for(self, record: CredentialRecord) -> frozenset[str]:
        return self._roles.get((record.realm, record.subject_id), frozenset())


@dataclass(frozen=True)
class RefreshSession:
    """One refresh credential, stored as a digest and single-use by rotation."""

    session_id: str
    family_id: str
    realm: IamRealm
    subject_id: str
    token_digest: str
    issued_at: datetime
    expires_at: datetime
    tenant_id: str | None = None
    rotated_to: str | None = None
    revoked: bool = False

    def __post_init__(self) -> None:
        _require_text(self.session_id, field_name="session id")
        _require_text(self.family_id, field_name="family id")
        if not isinstance(self.realm, IamRealm):
            raise IamMalformed("session realm must be an IamRealm")
        _require_text(self.subject_id, field_name="subject id")
        if len(self.token_digest) != 64:
            raise IamMalformed("session token digest must be a complete SHA-256 hex")
        _require_aware(self.issued_at, field_name="issued_at")
        _require_aware(self.expires_at, field_name="expires_at")
        if self.expires_at <= self.issued_at:
            raise IamMalformed("session expires_at must be after issued_at")
        if self.realm is IamRealm.TENANT:
            if self.tenant_id is None:
                raise IamMalformed("a tenant session must name its tenant")
            _require_text(self.tenant_id, field_name="tenant id")
        elif self.tenant_id is not None:
            raise IamMalformed("a platform session must not name a tenant")


class RefreshSessionStore(Protocol):
    """Persistence boundary for refresh sessions; production binds shared state."""

    def get(self, session_id: str) -> RefreshSession | None: ...

    def put(self, session: RefreshSession) -> None: ...

    def revoke_family(self, family_id: str) -> int: ...


class InMemoryRefreshSessionStore:
    """Volatile refresh-session reference, suitable for tests and integration."""

    def __init__(self) -> None:
        self._sessions: dict[str, RefreshSession] = {}

    def get(self, session_id: str) -> RefreshSession | None:
        return self._sessions.get(session_id)

    def put(self, session: RefreshSession) -> None:
        self._sessions[session.session_id] = session

    def revoke_family(self, family_id: str) -> int:
        revoked = 0
        for session_id, session in list(self._sessions.items()):
            if session.family_id == family_id and not session.revoked:
                self._sessions[session_id] = replace(session, revoked=True)
                revoked += 1
        return revoked


class RefreshSessionService:
    """Issue, rotate, and revoke refresh sessions with replay detection."""

    def __init__(self, store: RefreshSessionStore, *, lifetime_seconds: int) -> None:
        if (
            not isinstance(lifetime_seconds, int)
            or isinstance(lifetime_seconds, bool)
            or lifetime_seconds <= 0
        ):
            raise IamMalformed("lifetime_seconds must be a positive integer")
        self._store = store
        self._lifetime_seconds = lifetime_seconds

    def issue(
        self,
        *,
        realm: IamRealm,
        subject_id: str,
        now: datetime,
        tenant_id: str | None = None,
        family_id: str | None = None,
    ) -> tuple[RefreshSession, str]:
        """Mint a session and return it with its one raw token.

        The raw token is returned exactly once and never stored; the store
        keeps only its SHA-256 digest, so a dump of the session table does
        not yield a usable credential.
        """

        _require_aware(now, field_name="now")
        session_id = uuid4().hex
        raw_token = f"{session_id}.{secrets.token_urlsafe(_REFRESH_SECRET_BYTES)}"
        session = RefreshSession(
            session_id=session_id,
            family_id=family_id or session_id,
            realm=realm,
            subject_id=subject_id,
            token_digest=hashlib.sha256(raw_token.encode("ascii")).hexdigest(),
            issued_at=now,
            expires_at=now + timedelta(seconds=self._lifetime_seconds),
            tenant_id=tenant_id,
        )
        self._store.put(session)
        return session, raw_token

    def rotate(
        self, raw_token: str, *, realm: IamRealm, now: datetime
    ) -> tuple[RefreshSession, str]:
        """Exchange a refresh token for its successor, or fail closed.

        Every refusal below is deliberate.  A token that has already been
        rotated is the dangerous one: it means two parties hold the same
        credential, so the entire family is revoked rather than letting
        whichever caller arrives second continue the session.
        """

        _require_aware(now, field_name="now")
        session = self._lookup(raw_token, realm=realm)
        if session.rotated_to is not None:
            self._store.revoke_family(session.family_id)
            raise IamSessionReplayed(
                "refresh token was already rotated; the session family has been revoked"
            )
        if session.revoked:
            raise IamSessionRefused("refresh session has been revoked")
        if session.expires_at <= now:
            raise IamSessionRefused("refresh session has expired")
        successor, successor_token = self.issue(
            realm=session.realm,
            subject_id=session.subject_id,
            now=now,
            tenant_id=session.tenant_id,
            family_id=session.family_id,
        )
        self._store.put(replace(session, rotated_to=successor.session_id))
        return successor, successor_token

    def revoke(self, session_id: str) -> None:
        """Revoke one session, leaving the rest of its family alone."""

        _require_text(session_id, field_name="session id")
        session = self._store.get(session_id)
        if session is None:
            raise IamSessionRefused("unknown refresh session")
        self._store.put(replace(session, revoked=True))

    def revoke_family(self, family_id: str) -> int:
        """Revoke every session descended from one sign-in."""

        _require_text(family_id, field_name="family id")
        return self._store.revoke_family(family_id)

    def _lookup(self, raw_token: str, *, realm: IamRealm) -> RefreshSession:
        _require_text(raw_token, field_name="refresh token")
        session_id, _, _ = raw_token.partition(".")
        if not session_id:
            raise IamSessionRefused("refresh token is malformed")
        session = self._store.get(session_id)
        if session is None:
            raise IamSessionRefused("unknown refresh session")
        supplied = hashlib.sha256(raw_token.encode("ascii")).hexdigest()
        if not hmac.compare_digest(supplied, session.token_digest):
            raise IamSessionRefused("refresh token does not match this session")
        if session.realm is not realm:
            raise IamRealmMismatch(
                f"refresh session belongs to the {session.realm.value} realm"
            )
        return session


class RealmTokenAuthority:
    """Issues and verifies access tokens for both realms, kept apart.

    Two ``HmacTokenCodec`` instances, one per realm.  Construction proves the
    invariant directly rather than inspecting configuration: it mints a probe
    token with the platform codec and requires the tenant codec to *reject*
    it.  That is the property worth having -- a token issued for one plane
    must not verify in the other -- and it holds whether the codecs are kept
    apart by audience, by signing key, or by both.  Checking it here means a
    mis-wired deployment fails at startup, not the first time a platform
    token reaches a tenant endpoint.
    """

    def __init__(self, *, platform_codec: HmacTokenCodec, tenant_codec: HmacTokenCodec) -> None:
        for label, codec in (("platform_codec", platform_codec), ("tenant_codec", tenant_codec)):
            if not isinstance(codec, HmacTokenCodec):
                raise IamMalformed(f"{label} must be an HmacTokenCodec")
        probe = platform_codec.issue({"sub": "audience-probe"})
        try:
            tenant_codec.verify(probe)
        except TokenError:
            pass
        else:
            raise IamMalformed(
                "platform and tenant codecs must not share an audience and signing key; "
                "a token issued for one realm must never verify in the other"
            )
        self._platform = platform_codec
        self._tenant = tenant_codec

    def issue_platform(
        self, principal: PlatformPrincipal, *, expires_at: datetime | None = None
    ) -> str:
        if not isinstance(principal, PlatformPrincipal):
            raise IamMalformed("issue_platform requires a PlatformPrincipal")
        return self._platform.issue(
            {"sub": principal.subject_id, "roles": sorted(principal.role_names)},
            expires_at=expires_at,
        )

    def issue_tenant(
        self, principal: TenantPrincipal, *, expires_at: datetime | None = None
    ) -> str:
        if not isinstance(principal, TenantPrincipal):
            raise IamMalformed("issue_tenant requires a TenantPrincipal")
        return self._tenant.issue(
            {
                "sub": principal.operator_id,
                "tenant_id": principal.tenant_id,
                "roles": sorted(principal.role_names),
                "sites": sorted(principal.site_ids),
            },
            expires_at=expires_at,
        )

    def verify_platform(self, token: str, *, now: datetime | None = None) -> PlatformPrincipal:
        claims = self._verify(self._platform, token, realm=IamRealm.PLATFORM, now=now)
        if claims.get("tenant_id") is not None:
            raise IamRealmMismatch("a platform token must not carry a tenant claim")
        return PlatformPrincipal(
            subject_id=_claim_text(claims, "sub"),
            role_names=_claim_names(claims, "roles"),
        )

    def verify_tenant(self, token: str, *, now: datetime | None = None) -> TenantPrincipal:
        claims = self._verify(self._tenant, token, realm=IamRealm.TENANT, now=now)
        return TenantPrincipal(
            tenant_id=_claim_text(claims, "tenant_id"),
            operator_id=_claim_text(claims, "sub"),
            role_names=_claim_names(claims, "roles"),
            site_ids=_claim_names(claims, "sites"),
        )

    @staticmethod
    def _verify(
        codec: HmacTokenCodec, token: str, *, realm: IamRealm, now: datetime | None
    ) -> dict[str, Any]:
        """Verify under one realm's codec, separating "wrong plane" from "bad token".

        Only an audience or header mismatch means the caller crossed realms.
        An expired, tampered, or malformed token is an ordinary refusal, and
        reporting it as a realm mismatch would send an operator hunting for a
        configuration fault that is not there.
        """

        try:
            return codec.verify(token, now=now)
        except (TokenAudienceMismatch, TokenHeaderMismatch) as exc:
            raise IamRealmMismatch(
                f"token was not issued for the {realm.value} realm"
            ) from exc
        except TokenError as exc:
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL) from exc


def tenant_principal_from_context(
    context: TrustedRequestContext,
    *,
    role_names: frozenset[str],
    site_ids: frozenset[str] = frozenset(),
) -> TenantPrincipal:
    """Lift CP-02's validated request context into a tenant principal.

    CP-02 already established the only trustworthy tenant fact -- that the
    tenant came from verified token claims and not from the payload -- so
    this reuses that context rather than re-deriving tenant identity from a
    second parse of the same token.  Roles are supplied by the caller from
    its assignment store; they are authorization state, not a claim this
    boundary invents.
    """

    if not isinstance(context, TrustedRequestContext):
        raise IamMalformed("a tenant principal requires a TrustedRequestContext")
    return TenantPrincipal(
        tenant_id=context.tenant_id,
        operator_id=context.subject_id,
        role_names=role_names,
        site_ids=site_ids,
    )


def _claim_text(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise IamMalformed(f"token carries no usable {name!r} claim")
    return value


def _claim_names(claims: Mapping[str, Any], name: str) -> frozenset[str]:
    value = claims.get(name, [])
    if not isinstance(value, list) or not all(
        isinstance(entry, str) and entry for entry in value
    ):
        raise IamMalformed(f"token {name!r} claim must be a list of non-empty strings")
    return frozenset(value)


class Authenticator:
    """Password sign-in that refuses uniformly and rate-limits by source.

    Every failure path -- unknown identifier, wrong password, suspended
    account, closed account, SSO-only account -- raises the same exception
    with the same message, and the unknown-identifier path still runs a
    password verification against a throwaway hash so that "no such account"
    does not return measurably faster than "wrong password".  Together those
    keep sign-in from answering whether an organization or operator exists.
    """

    def __init__(
        self,
        credentials: CredentialStore,
        assignments: RoleAssignmentStore,
        hasher: PasswordHasher,
        *,
        rate_limit: RateLimitPolicy | None = None,
        rate_store: RateLimitStore | None = None,
    ) -> None:
        if rate_limit is not None and rate_store is None:
            raise IamMalformed("a rate limit policy requires a rate store")
        self._credentials = credentials
        self._assignments = assignments
        self._hasher = hasher
        self._rate_limit = rate_limit
        self._rate_store = rate_store
        self._decoy = hasher.hash(secrets.token_urlsafe(_REFRESH_SECRET_BYTES))

    def authenticate(
        self,
        *,
        realm: IamRealm,
        identifier: str,
        password: str,
        now: datetime,
        source_key: str | None = None,
    ) -> PlatformPrincipal | TenantPrincipal:
        """Verify a password and return the realm's principal, or refuse."""

        _require_aware(now, field_name="now")
        _require_text(identifier, field_name="identifier")
        _require_text(password, field_name="password")
        if not isinstance(realm, IamRealm):
            raise IamMalformed("realm must be an IamRealm")
        self._check_rate(source_key, now=now)
        record = self._credentials.find(realm, identifier)
        if record is None or record.encoded_password is None:
            # Spend the same work as a real verification before refusing.
            self._hasher.verify(password, self._decoy)
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
        if record.realm is not realm:
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
        if not self._hasher.verify(password, record.encoded_password):
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
        if record.state is not AccountState.ACTIVE:
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
        return self._principal(record)

    def authenticate_federated(
        self,
        provider: IdentityProvider,
        assertion: str,
        *,
        realm: IamRealm,
        now: datetime,
        source_key: str | None = None,
    ) -> PlatformPrincipal | TenantPrincipal:
        """Verify an SSO assertion through a provider adapter, or refuse."""

        _require_aware(now, field_name="now")
        if not isinstance(realm, IamRealm):
            raise IamMalformed("realm must be an IamRealm")
        self._check_rate(source_key, now=now)
        identity = provider.authenticate(assertion, now=now)
        if identity.provider_id != provider.provider_id:
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
        record = self._credentials.find(realm, identity.external_subject)
        if (
            record is None
            or record.realm is not realm
            or record.federated_subject != identity.external_subject
            or record.state is not AccountState.ACTIVE
        ):
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
        return self._principal(record)

    def _principal(self, record: CredentialRecord) -> PlatformPrincipal | TenantPrincipal:
        roles = self._assignments.roles_for(record)
        if record.realm is IamRealm.PLATFORM:
            return PlatformPrincipal(subject_id=record.subject_id, role_names=roles)
        if record.tenant_id is None:
            # ``CredentialRecord`` already refuses this, so reaching it means a
            # store handed back something it did not construct.  Refusing beats
            # asserting: assertions vanish under ``python -O``, and this is the
            # check that keeps a tenant principal from existing without a tenant.
            raise IamMalformed("a tenant credential record must name its tenant")
        return TenantPrincipal(
            tenant_id=record.tenant_id,
            operator_id=record.subject_id,
            role_names=roles,
        )

    def _check_rate(self, source_key: str | None, *, now: datetime) -> None:
        if self._rate_limit is None or self._rate_store is None:
            return
        if source_key is None:
            raise IamMalformed("a rate-limited authenticator requires a source key")
        retry_after = self._rate_store.hit(source_key, self._rate_limit, now=now)
        if retry_after is not None:
            raise IamAuthenticationRefused(_UNIFORM_REFUSAL)
