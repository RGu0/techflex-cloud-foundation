from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from techflex_cloud_foundation import (
    AccountState,
    Authenticator,
    CredentialRecord,
    FederatedIdentity,
    HmacTokenCodec,
    IamAuthenticationRefused,
    IamMalformed,
    IamPermissionDenied,
    IamRealm,
    IamRealmMismatch,
    IamSessionRefused,
    IamSessionReplayed,
    InMemoryCredentialStore,
    InMemoryRateLimitStore,
    InMemoryRefreshSessionStore,
    InMemoryRoleAssignmentStore,
    Organization,
    Pbkdf2PasswordHasher,
    PlatformPrincipal,
    ProductMembership,
    RateLimitPolicy,
    RealmTokenAuthority,
    RefreshSessionService,
    RequestValidator,
    Role,
    RoleCatalog,
    Site,
    Tenant,
    TenantOperator,
    TenantPrincipal,
    source_fingerprint,
    tenant_principal_from_context,
    transition_account,
)

NOW = datetime(2026, 9, 4, 12, 0, tzinfo=UTC)
SALT = b"deployment-held-salt-16+"

PLATFORM_SECRET = b"platform-signing-secret-32-bytes!"
TENANT_SECRET = b"tenant-signing-secret-32-bytes!!!"


def _platform_codec() -> HmacTokenCodec:
    return HmacTokenCodec(
        secret=PLATFORM_SECRET, key_id="k1", token_type="access", audience="platform"
    )


def _tenant_codec() -> HmacTokenCodec:
    return HmacTokenCodec(
        secret=TENANT_SECRET, key_id="k1", token_type="access", audience="tenant"
    )


def _authority() -> RealmTokenAuthority:
    return RealmTokenAuthority(platform_codec=_platform_codec(), tenant_codec=_tenant_codec())


def _fast_hasher() -> Pbkdf2PasswordHasher:
    # The production default is 600k iterations; tests assert behaviour, not cost.
    return Pbkdf2PasswordHasher(iterations=10)


# --------------------------------------------------------------------------
# Entities and the account lifecycle
# --------------------------------------------------------------------------


def test_entities_require_non_empty_identifiers() -> None:
    with pytest.raises(IamMalformed):
        Organization(organization_id="")
    with pytest.raises(IamMalformed):
        Tenant(tenant_id="t1", organization_id="")
    with pytest.raises(IamMalformed):
        Site(site_id="", tenant_id="t1")
    with pytest.raises(IamMalformed):
        TenantOperator(operator_id="op1", tenant_id="")
    with pytest.raises(IamMalformed):
        ProductMembership(
            operator_id="op1", tenant_id="t1", product_id="", role_names=frozenset({"r"})
        )


def test_operator_site_ids_must_be_non_empty_text() -> None:
    with pytest.raises(IamMalformed):
        TenantOperator(operator_id="op1", tenant_id="t1", site_ids=frozenset({""}))


def test_account_state_must_be_an_account_state() -> None:
    with pytest.raises(IamMalformed):
        Organization(organization_id="org1", state="active")  # type: ignore[arg-type]


def test_account_suspension_is_reversible_but_closing_is_terminal() -> None:
    assert transition_account(AccountState.ACTIVE, AccountState.SUSPENDED) is (
        AccountState.SUSPENDED
    )
    assert transition_account(AccountState.SUSPENDED, AccountState.ACTIVE) is AccountState.ACTIVE
    assert transition_account(AccountState.ACTIVE, AccountState.CLOSED) is AccountState.CLOSED

    with pytest.raises(IamMalformed, match="terminal"):
        transition_account(AccountState.CLOSED, AccountState.ACTIVE)


def test_reapplying_the_same_account_state_is_refused() -> None:
    with pytest.raises(IamMalformed, match="already active"):
        transition_account(AccountState.ACTIVE, AccountState.ACTIVE)


# --------------------------------------------------------------------------
# Roles and authorization
# --------------------------------------------------------------------------


def test_role_permissions_do_not_cross_realms() -> None:
    # The same word names a role in both planes -- a realistic accident.
    catalog = RoleCatalog(
        roles=(
            Role(name="admin", realm=IamRealm.PLATFORM, permissions=frozenset({"org.create"})),
            Role(name="admin", realm=IamRealm.TENANT, permissions=frozenset({"session.read"})),
        )
    )

    assert catalog.permissions_for(frozenset({"admin"}), realm=IamRealm.PLATFORM) == frozenset(
        {"org.create"}
    )
    assert catalog.permissions_for(frozenset({"admin"}), realm=IamRealm.TENANT) == frozenset(
        {"session.read"}
    )


def test_tenant_principal_never_receives_a_platform_permission() -> None:
    catalog = RoleCatalog(
        roles=(
            Role(name="admin", realm=IamRealm.PLATFORM, permissions=frozenset({"org.create"})),
            Role(name="admin", realm=IamRealm.TENANT, permissions=frozenset({"session.read"})),
        )
    )
    operator = TenantPrincipal(
        tenant_id="t1", operator_id="op1", role_names=frozenset({"admin"})
    )

    decision = catalog.decide(operator, "org.create")

    assert decision.allowed is False
    assert decision.realm is IamRealm.TENANT
    with pytest.raises(IamPermissionDenied):
        catalog.require(operator, "org.create")


def test_platform_principal_is_granted_its_own_realms_permission() -> None:
    catalog = RoleCatalog(
        roles=(
            Role(name="admin", realm=IamRealm.PLATFORM, permissions=frozenset({"org.create"})),
        )
    )
    admin = PlatformPrincipal(subject_id="pa1", role_names=frozenset({"admin"}))

    assert catalog.require(admin, "org.create").allowed is True


def test_platform_principal_has_no_tenant_field_at_all() -> None:
    admin = PlatformPrincipal(subject_id="pa1", role_names=frozenset())

    assert not hasattr(admin, "tenant_id")


def test_role_names_must_be_unique_within_a_realm() -> None:
    with pytest.raises(IamMalformed, match="unique within a realm"):
        RoleCatalog(
            roles=(
                Role(name="admin", realm=IamRealm.TENANT, permissions=frozenset({"a"})),
                Role(name="admin", realm=IamRealm.TENANT, permissions=frozenset({"b"})),
            )
        )


def test_authorization_refuses_anything_that_is_not_a_principal() -> None:
    catalog = RoleCatalog(roles=())

    with pytest.raises(IamMalformed, match="PlatformPrincipal or a TenantPrincipal"):
        catalog.decide("op1", "session.read")  # type: ignore[arg-type]


def test_unregistered_role_name_grants_nothing() -> None:
    catalog = RoleCatalog(
        roles=(Role(name="known", realm=IamRealm.TENANT, permissions=frozenset({"a"})),)
    )
    operator = TenantPrincipal(
        tenant_id="t1", operator_id="op1", role_names=frozenset({"invented"})
    )

    assert catalog.decide(operator, "a").allowed is False


# --------------------------------------------------------------------------
# Password hashing
# --------------------------------------------------------------------------


def test_password_round_trips_and_rejects_the_wrong_password() -> None:
    hasher = _fast_hasher()
    encoded = hasher.hash("correct horse")

    assert hasher.verify("correct horse", encoded) is True
    assert hasher.verify("wrong horse", encoded) is False


def test_encoded_password_never_contains_the_plaintext() -> None:
    encoded = _fast_hasher().hash("correct horse")

    assert "correct horse" not in encoded
    assert encoded.startswith("pbkdf2_sha256$")


def test_equal_passwords_hash_differently_because_the_salt_differs() -> None:
    hasher = _fast_hasher()

    assert hasher.hash("same") != hasher.hash("same")


def test_needs_rehash_reports_a_value_below_the_current_cost() -> None:
    weak = Pbkdf2PasswordHasher(iterations=10).hash("pw")

    assert Pbkdf2PasswordHasher(iterations=20).needs_rehash(weak) is True
    assert Pbkdf2PasswordHasher(iterations=10).needs_rehash(weak) is False


def test_corrupt_stored_hash_raises_rather_than_reporting_a_wrong_password() -> None:
    hasher = _fast_hasher()

    for corrupt in ("", "not-a-hash", "pbkdf2_sha256$x$aa$bb", "argon2$1$aa$bb"):
        with pytest.raises(IamMalformed):
            hasher.verify("pw", corrupt)


def test_hasher_iterations_must_be_a_positive_integer() -> None:
    with pytest.raises(IamMalformed):
        Pbkdf2PasswordHasher(iterations=0)
    with pytest.raises(IamMalformed):
        Pbkdf2PasswordHasher(iterations=True)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Realm separation
# --------------------------------------------------------------------------


def test_platform_and_tenant_tokens_round_trip_in_their_own_realm() -> None:
    authority = _authority()
    admin = PlatformPrincipal(subject_id="pa1", role_names=frozenset({"admin"}))
    operator = TenantPrincipal(
        tenant_id="t1",
        operator_id="op1",
        role_names=frozenset({"clinician"}),
        site_ids=frozenset({"s1"}),
    )

    assert authority.verify_platform(authority.issue_platform(admin)) == admin
    assert authority.verify_tenant(authority.issue_tenant(operator)) == operator


def test_a_platform_token_is_refused_as_a_tenant_credential() -> None:
    authority = _authority()
    token = authority.issue_platform(
        PlatformPrincipal(subject_id="pa1", role_names=frozenset({"admin"}))
    )

    # Separate signing keys mean the tenant codec rejects this on signature,
    # before it ever reads the audience -- so the refusal is the general one.
    # That the token does not verify is the invariant; how it is classified
    # is not.
    with pytest.raises(IamAuthenticationRefused):
        authority.verify_tenant(token)


def test_a_tenant_token_is_refused_as_a_platform_credential() -> None:
    authority = _authority()
    token = authority.issue_tenant(
        TenantPrincipal(tenant_id="t1", operator_id="op1", role_names=frozenset())
    )

    with pytest.raises(IamAuthenticationRefused):
        authority.verify_platform(token)


def test_realms_split_only_by_audience_still_refuse_and_can_say_why() -> None:
    # A deployment that reuses one signing key and separates the planes by
    # audience alone is weaker, but still separated -- and here the boundary
    # can name the reason, because the signature check passes first.
    authority = RealmTokenAuthority(
        platform_codec=HmacTokenCodec(
            secret=PLATFORM_SECRET, key_id="k1", token_type="access", audience="platform"
        ),
        tenant_codec=HmacTokenCodec(
            secret=PLATFORM_SECRET, key_id="k1", token_type="access", audience="tenant"
        ),
    )
    token = authority.issue_platform(
        PlatformPrincipal(subject_id="pa1", role_names=frozenset({"admin"}))
    )

    with pytest.raises(IamRealmMismatch, match="not issued for the tenant realm"):
        authority.verify_tenant(token)


def test_a_realm_mismatch_is_itself_an_authentication_refusal() -> None:
    # Callers fail closed by catching the general type; the specific one is a
    # diagnostic layered on top, never the thing enforcing the separation.
    assert issubclass(IamRealmMismatch, IamAuthenticationRefused)


def test_codecs_that_do_not_separate_the_realms_are_refused_at_construction() -> None:
    shared = _platform_codec()

    with pytest.raises(IamMalformed, match="must never verify in the other"):
        RealmTokenAuthority(platform_codec=shared, tenant_codec=_platform_codec())


def test_expired_token_is_an_ordinary_refusal_not_a_realm_mismatch() -> None:
    authority = _authority()
    token = authority.issue_tenant(
        TenantPrincipal(tenant_id="t1", operator_id="op1", role_names=frozenset()),
        expires_at=datetime.now(UTC) + timedelta(seconds=5),
    )

    with pytest.raises(IamAuthenticationRefused) as caught:
        authority.verify_tenant(token, now=datetime.now(UTC) + timedelta(hours=1))
    assert not isinstance(caught.value, IamRealmMismatch)


def test_tampered_token_is_refused() -> None:
    authority = _authority()
    token = authority.issue_tenant(
        TenantPrincipal(tenant_id="t1", operator_id="op1", role_names=frozenset())
    )
    head, _, tail = token.rpartition(".")

    with pytest.raises(IamAuthenticationRefused):
        authority.verify_tenant(f"{head}.{'a' * len(tail)}")


def test_issue_helpers_refuse_the_other_realms_principal() -> None:
    authority = _authority()

    with pytest.raises(IamMalformed):
        authority.issue_platform(
            TenantPrincipal(tenant_id="t1", operator_id="op1", role_names=frozenset())  # type: ignore[arg-type]
        )
    with pytest.raises(IamMalformed):
        authority.issue_tenant(
            PlatformPrincipal(subject_id="pa1", role_names=frozenset())  # type: ignore[arg-type]
        )


def test_authority_requires_hmac_token_codecs() -> None:
    with pytest.raises(IamMalformed, match="platform_codec"):
        RealmTokenAuthority(platform_codec="nope", tenant_codec=_tenant_codec())  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# Reuse of the CP-02 trusted request context
# --------------------------------------------------------------------------


def test_tenant_principal_is_lifted_from_the_cp02_trusted_context() -> None:
    codec = _tenant_codec()
    validator = RequestValidator(codec, max_payload_bytes=1024)
    token = codec.issue({"sub": "op1", "tenant_id": "t1"})
    context = validator.validate(f"Bearer {token}", now=NOW)

    principal = tenant_principal_from_context(context, role_names=frozenset({"clinician"}))

    assert principal.tenant_id == "t1"
    assert principal.operator_id == "op1"


def test_payload_supplied_tenant_never_reaches_a_principal() -> None:
    codec = _tenant_codec()
    validator = RequestValidator(codec, max_payload_bytes=1024)
    token = codec.issue({"sub": "op1", "tenant_id": "t1"})

    # CP-02 refuses before a principal can be built at all.
    with pytest.raises(Exception, match="payload never selects the tenant"):
        validator.validate(f"Bearer {token}", payload_tenant="t2", now=NOW)


def test_a_principal_cannot_be_built_from_an_unverified_object() -> None:
    with pytest.raises(IamMalformed, match="TrustedRequestContext"):
        tenant_principal_from_context(
            {"tenant_id": "t1", "subject_id": "op1"},  # type: ignore[arg-type]
            role_names=frozenset(),
        )


# --------------------------------------------------------------------------
# Refresh sessions
# --------------------------------------------------------------------------


def _session_service() -> tuple[RefreshSessionService, InMemoryRefreshSessionStore]:
    store = InMemoryRefreshSessionStore()
    return RefreshSessionService(store, lifetime_seconds=3600), store


def test_issued_session_stores_only_a_digest_of_its_token() -> None:
    service, store = _session_service()

    session, raw = service.issue(
        realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW
    )

    assert raw not in repr(store.get(session.session_id))
    assert session.token_digest != raw
    assert len(session.token_digest) == 64


def test_rotation_issues_a_new_token_and_keeps_the_family() -> None:
    service, _ = _session_service()
    first, first_raw = service.issue(
        realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW
    )

    second, second_raw = service.rotate(first_raw, realm=IamRealm.TENANT, now=NOW)

    assert second_raw != first_raw
    assert second.family_id == first.family_id
    assert second.session_id != first.session_id


def test_replaying_a_rotated_token_revokes_the_whole_family() -> None:
    service, store = _session_service()
    first, first_raw = service.issue(
        realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW
    )
    second, second_raw = service.rotate(first_raw, realm=IamRealm.TENANT, now=NOW)

    with pytest.raises(IamSessionReplayed):
        service.rotate(first_raw, realm=IamRealm.TENANT, now=NOW)

    # The successor the legitimate holder is using dies too: which of the two
    # holders is the attacker cannot be known here.
    assert store.get(second.session_id) is not None
    assert store.get(second.session_id).revoked is True  # type: ignore[union-attr]
    assert store.get(first.session_id).revoked is True  # type: ignore[union-attr]
    with pytest.raises(IamSessionRefused):
        service.rotate(second_raw, realm=IamRealm.TENANT, now=NOW)


def test_expired_session_cannot_be_rotated() -> None:
    service, _ = _session_service()
    _, raw = service.issue(realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW)

    with pytest.raises(IamSessionRefused, match="expired"):
        service.rotate(raw, realm=IamRealm.TENANT, now=NOW + timedelta(hours=2))


def test_revoked_session_cannot_be_rotated() -> None:
    service, _ = _session_service()
    session, raw = service.issue(
        realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW
    )
    service.revoke(session.session_id)

    with pytest.raises(IamSessionRefused, match="revoked"):
        service.rotate(raw, realm=IamRealm.TENANT, now=NOW)


def test_a_tenant_session_cannot_be_rotated_as_a_platform_one() -> None:
    service, _ = _session_service()
    _, raw = service.issue(realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW)

    with pytest.raises(IamRealmMismatch):
        service.rotate(raw, realm=IamRealm.PLATFORM, now=NOW)


def test_unknown_and_tampered_refresh_tokens_are_refused() -> None:
    service, _ = _session_service()
    session, raw = service.issue(
        realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW
    )

    with pytest.raises(IamSessionRefused, match="unknown"):
        service.rotate("deadbeef.secret", realm=IamRealm.TENANT, now=NOW)
    with pytest.raises(IamSessionRefused, match="does not match"):
        service.rotate(f"{session.session_id}.forged", realm=IamRealm.TENANT, now=NOW)
    assert raw  # the genuine token was never used


def test_platform_sessions_carry_no_tenant_and_tenant_sessions_require_one() -> None:
    service, _ = _session_service()

    platform_session, _ = service.issue(realm=IamRealm.PLATFORM, subject_id="pa1", now=NOW)
    assert platform_session.tenant_id is None

    with pytest.raises(IamMalformed, match="platform session must not name a tenant"):
        service.issue(realm=IamRealm.PLATFORM, subject_id="pa1", tenant_id="t1", now=NOW)
    with pytest.raises(IamMalformed, match="tenant session must name its tenant"):
        service.issue(realm=IamRealm.TENANT, subject_id="op1", now=NOW)


def test_session_lifetime_must_be_positive() -> None:
    with pytest.raises(IamMalformed):
        RefreshSessionService(InMemoryRefreshSessionStore(), lifetime_seconds=0)


def test_revoking_one_session_leaves_its_siblings_alone() -> None:
    service, store = _session_service()
    kept, _ = service.issue(realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW)
    other, _ = service.issue(realm=IamRealm.TENANT, subject_id="op1", tenant_id="t1", now=NOW)

    service.revoke(other.session_id)

    assert store.get(kept.session_id).revoked is False  # type: ignore[union-attr]


# --------------------------------------------------------------------------
# Sign-in: uniform refusal and rate limiting
# --------------------------------------------------------------------------


class _CountingHasher:
    """A hasher that records how often a verification actually ran."""

    def __init__(self) -> None:
        self._inner = _fast_hasher()
        self.verifications = 0

    @property
    def algorithm(self) -> str:
        return self._inner.algorithm

    def hash(self, password: str) -> str:
        return self._inner.hash(password)

    def verify(self, password: str, encoded: str) -> bool:
        self.verifications += 1
        return self._inner.verify(password, encoded)

    def needs_rehash(self, encoded: str) -> bool:
        return self._inner.needs_rehash(encoded)


def _authenticator(
    *,
    state: AccountState = AccountState.ACTIVE,
    rate_limit: RateLimitPolicy | None = None,
) -> tuple[Authenticator, _CountingHasher]:
    hasher = _CountingHasher()
    credentials = InMemoryCredentialStore()
    credentials.add(
        "op1@example.test",
        CredentialRecord(
            subject_id="op1",
            realm=IamRealm.TENANT,
            state=state,
            tenant_id="t1",
            encoded_password=hasher.hash("correct horse"),
        ),
    )
    assignments = InMemoryRoleAssignmentStore()
    assignments.assign(IamRealm.TENANT, "op1", frozenset({"clinician"}))
    authenticator = Authenticator(
        credentials,
        assignments,
        hasher,
        rate_limit=rate_limit,
        rate_store=InMemoryRateLimitStore() if rate_limit else None,
    )
    return authenticator, hasher


def test_successful_sign_in_returns_a_tenant_principal_from_stored_facts() -> None:
    authenticator, _ = _authenticator()

    principal = authenticator.authenticate(
        realm=IamRealm.TENANT,
        identifier="op1@example.test",
        password="correct horse",
        now=NOW,
    )

    assert principal == TenantPrincipal(
        tenant_id="t1", operator_id="op1", role_names=frozenset({"clinician"})
    )


@pytest.mark.parametrize(
    ("identifier", "password", "state"),
    [
        ("op1@example.test", "wrong horse", AccountState.ACTIVE),
        ("nobody@example.test", "correct horse", AccountState.ACTIVE),
        ("op1@example.test", "correct horse", AccountState.SUSPENDED),
        ("op1@example.test", "correct horse", AccountState.CLOSED),
    ],
    ids=["wrong-password", "unknown-account", "suspended", "closed"],
)
def test_every_sign_in_failure_is_indistinguishable(
    identifier: str, password: str, state: AccountState
) -> None:
    authenticator, _ = _authenticator(state=state)

    with pytest.raises(IamAuthenticationRefused) as caught:
        authenticator.authenticate(
            realm=IamRealm.TENANT, identifier=identifier, password=password, now=NOW
        )

    # One message for every cause: sign-in must not answer whether an
    # organization or an operator exists, or what state it is in.
    assert str(caught.value) == "authentication refused"


def test_unknown_account_still_pays_for_a_password_verification() -> None:
    authenticator, hasher = _authenticator()

    with pytest.raises(IamAuthenticationRefused):
        authenticator.authenticate(
            realm=IamRealm.TENANT,
            identifier="nobody@example.test",
            password="correct horse",
            now=NOW,
        )

    # Without this, "no such account" would return measurably sooner than
    # "wrong password" and the uniform message would not hide anything.
    assert hasher.verifications == 1


def test_sso_only_account_refuses_password_sign_in_uniformly() -> None:
    credentials = InMemoryCredentialStore()
    credentials.add(
        "sso@example.test",
        CredentialRecord(subject_id="op2", realm=IamRealm.TENANT, tenant_id="t1"),
    )
    authenticator = Authenticator(
        credentials, InMemoryRoleAssignmentStore(), _fast_hasher()
    )

    with pytest.raises(IamAuthenticationRefused, match="authentication refused"):
        authenticator.authenticate(
            realm=IamRealm.TENANT, identifier="sso@example.test", password="anything", now=NOW
        )


def test_exhausted_rate_limit_refuses_with_the_same_message() -> None:
    authenticator, _ = _authenticator(
        rate_limit=RateLimitPolicy(max_requests=1, window_seconds=60)
    )
    key = source_fingerprint("198.51.100.7", salt=SALT)

    authenticator.authenticate(
        realm=IamRealm.TENANT,
        identifier="op1@example.test",
        password="correct horse",
        now=NOW,
        source_key=key,
    )

    with pytest.raises(IamAuthenticationRefused, match="authentication refused"):
        authenticator.authenticate(
            realm=IamRealm.TENANT,
            identifier="op1@example.test",
            password="correct horse",
            now=NOW,
            source_key=key,
        )


def test_rate_limited_authenticator_demands_a_source_key() -> None:
    authenticator, _ = _authenticator(
        rate_limit=RateLimitPolicy(max_requests=5, window_seconds=60)
    )

    with pytest.raises(IamMalformed, match="source key"):
        authenticator.authenticate(
            realm=IamRealm.TENANT,
            identifier="op1@example.test",
            password="correct horse",
            now=NOW,
        )


def test_a_rate_policy_without_a_store_is_refused() -> None:
    with pytest.raises(IamMalformed, match="requires a rate store"):
        Authenticator(
            InMemoryCredentialStore(),
            InMemoryRoleAssignmentStore(),
            _fast_hasher(),
            rate_limit=RateLimitPolicy(max_requests=1, window_seconds=60),
        )


def test_platform_sign_in_returns_a_platform_principal() -> None:
    hasher = _fast_hasher()
    credentials = InMemoryCredentialStore()
    credentials.add(
        "admin@example.test",
        CredentialRecord(
            subject_id="pa1",
            realm=IamRealm.PLATFORM,
            encoded_password=hasher.hash("correct horse"),
        ),
    )
    assignments = InMemoryRoleAssignmentStore()
    assignments.assign(IamRealm.PLATFORM, "pa1", frozenset({"admin"}))

    principal = Authenticator(credentials, assignments, hasher).authenticate(
        realm=IamRealm.PLATFORM,
        identifier="admin@example.test",
        password="correct horse",
        now=NOW,
    )

    assert principal == PlatformPrincipal(subject_id="pa1", role_names=frozenset({"admin"}))


def test_a_tenant_identifier_does_not_resolve_in_the_platform_realm() -> None:
    authenticator, _ = _authenticator()

    with pytest.raises(IamAuthenticationRefused):
        authenticator.authenticate(
            realm=IamRealm.PLATFORM,
            identifier="op1@example.test",
            password="correct horse",
            now=NOW,
        )


# --------------------------------------------------------------------------
# Credential records and SSO
# --------------------------------------------------------------------------


def test_a_platform_credential_may_not_name_a_tenant() -> None:
    with pytest.raises(IamMalformed, match="platform credential must not name a tenant"):
        CredentialRecord(subject_id="pa1", realm=IamRealm.PLATFORM, tenant_id="t1")


def test_a_tenant_credential_must_name_its_tenant() -> None:
    with pytest.raises(IamMalformed, match="tenant credential must name its tenant"):
        CredentialRecord(subject_id="op1", realm=IamRealm.TENANT)


class _StubProvider:
    """A stand-in for the SSO adapter a deployment supplies."""

    provider_id = "stub-oidc"

    def __init__(self, subject: str) -> None:
        self._subject = subject

    def authenticate(self, assertion: str, *, now: datetime) -> FederatedIdentity:
        if assertion != "valid":
            raise IamAuthenticationRefused("authentication refused")
        return FederatedIdentity(
            provider_id=self.provider_id, external_subject=self._subject
        )


def test_federated_sign_in_maps_an_external_subject_to_a_principal() -> None:
    credentials = InMemoryCredentialStore()
    credentials.add(
        "ext-42",
        CredentialRecord(
            subject_id="op3",
            realm=IamRealm.TENANT,
            tenant_id="t1",
            federated_subject="ext-42",
        ),
    )
    assignments = InMemoryRoleAssignmentStore()
    assignments.assign(IamRealm.TENANT, "op3", frozenset({"clinician"}))
    authenticator = Authenticator(credentials, assignments, _fast_hasher())

    principal = authenticator.authenticate_federated(
        _StubProvider("ext-42"), "valid", realm=IamRealm.TENANT, now=NOW
    )

    assert principal == TenantPrincipal(
        tenant_id="t1", operator_id="op3", role_names=frozenset({"clinician"})
    )


def test_federated_sign_in_refuses_an_unmapped_external_subject() -> None:
    authenticator = Authenticator(
        InMemoryCredentialStore(), InMemoryRoleAssignmentStore(), _fast_hasher()
    )

    with pytest.raises(IamAuthenticationRefused, match="authentication refused"):
        authenticator.authenticate_federated(
            _StubProvider("ext-unknown"), "valid", realm=IamRealm.TENANT, now=NOW
        )


def test_federated_identity_requires_provider_and_subject() -> None:
    with pytest.raises(IamMalformed):
        FederatedIdentity(provider_id="", external_subject="ext-1")
    with pytest.raises(IamMalformed):
        FederatedIdentity(provider_id="p", external_subject="")


# --------------------------------------------------------------------------
# Rate-limit source fingerprints
# --------------------------------------------------------------------------


def test_fingerprint_is_stable_and_hides_its_source() -> None:
    first = source_fingerprint("198.51.100.7", salt=SALT)

    assert first == source_fingerprint("198.51.100.7", salt=SALT)
    assert "198.51.100.7" not in first
    assert len(first) == 64


def test_fingerprints_differ_across_deployments_and_sources() -> None:
    assert source_fingerprint("198.51.100.7", salt=SALT) != source_fingerprint(
        "198.51.100.8", salt=SALT
    )
    assert source_fingerprint("198.51.100.7", salt=SALT) != source_fingerprint(
        "198.51.100.7", salt=b"a-different-salt-16+++++"
    )


def test_a_short_salt_is_refused() -> None:
    with pytest.raises(IamMalformed, match="at least 16 bytes"):
        source_fingerprint("198.51.100.7", salt=b"short")
