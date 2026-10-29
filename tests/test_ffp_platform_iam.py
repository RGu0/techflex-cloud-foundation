from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.access_control import (
    PlatformLoginRequest,
    PlatformRole,
    SensitiveAccessGrantRequest,
)
from techflex_cloud_foundation.server.access_auth import (
    PlatformAccessTokenIssuer,
    RefreshTokenFactory,
)
from techflex_cloud_foundation.server.access_control.platform_iam import (
    PlatformIdentityService,
    PlatformPermissionDenied,
    SensitiveAccessService,
)
from techflex_cloud_foundation.server.access_control.repository import (
    AccessGroupSeed,
    InMemoryAccessRepository,
    TenantSeed,
)

START = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)


@dataclass
class MutableClock:
    value: datetime = START

    def __call__(self) -> datetime:
        return self.value


def _services():
    repository = InMemoryAccessRepository()
    clock = MutableClock()
    identities = PlatformIdentityService(
        repository,
        login_lookup_hmac_key=b"platform-login-lookup-key-at-least-32-bytes",
        token_issuer=PlatformAccessTokenIssuer(
            secret=b"platform-token-secret-must-be-at-least-32-bytes",
            key_id="platform/1",
        ),
        refresh_tokens=RefreshTokenFactory(
            digest_key=b"platform-refresh-key-must-be-at-least-32-bytes"
        ),
        now=clock,
    )
    sensitive = SensitiveAccessService(repository, now=clock)
    return repository, clock, identities, sensitive


async def _seed_tenant(repository: InMemoryAccessRepository):
    tenant_id = uuid4()
    await repository.provision_tenant(
        TenantSeed(tenant_id=tenant_id, name="Seed Clinic"),
        AccessGroupSeed(
            account_id=uuid4(),
            login_name_hmac=b"a" * 32,
            account_display_name="seed-clinic",
            license_id=uuid4(),
            hardware_id=uuid4(),
            hardware_identity="usb-serial-0123456789abcdef0123",
            hardware_model="DO-P4864",
            activation_code_id=uuid4(),
            activation_code_hash=b"b" * 32,
            activation_expires_at=START + timedelta(days=1),
            license_valid_from=START,
            license_valid_until=START + timedelta(days=365),
            enabled_features=("screening.start",),
        ),
        created_at=START,
    )
    return tenant_id


def test_bootstrap_owner_then_create_multiple_platform_identities() -> None:
    async def exercise() -> None:
        _, _, identities, _ = _services()
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        owner_context = await identities.verify_access_token(owner.access_token)
        support = await identities.create_identity(
            owner_context,
            login_name="platform-support",
            display_name="Support One",
            password="support-password-long-enough",
            roles=(PlatformRole.SUPPORT,),
        )
        engineer = await identities.create_identity(
            owner_context,
            login_name="platform-engineer",
            display_name="Engineer One",
            password="engineer-password-long-enough",
            roles=(PlatformRole.ENGINEER,),
        )

        assert set(owner.roles) == {PlatformRole.OWNER}
        assert set(support.roles) == {PlatformRole.SUPPORT}
        assert set(engineer.roles) == {PlatformRole.ENGINEER}
        with pytest.raises(RuntimeError, match="already been completed"):
            await identities.bootstrap_owner(
                login_name="second-owner",
                display_name="Second Owner",
                password="another-password-long-enough",
            )

    asyncio.run(exercise())


def test_platform_login_uses_independent_identity_and_roles() -> None:
    async def exercise() -> None:
        _, _, identities, _ = _services()
        await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )

        response = await identities.login(
            PlatformLoginRequest(
                login_name="platform-owner",
                password="correct-horse-battery-staple",
            )
        )
        context = await identities.verify_access_token(response.access_token)
        assert context.platform_identity_id == response.platform_identity_id
        assert context.roles == frozenset({PlatformRole.OWNER})

    asyncio.run(exercise())


def test_sensitive_identity_requires_support_or_owner_and_15_minute_grant() -> None:
    async def exercise() -> None:
        repository, clock, identities, sensitive = _services()
        tenant_id = await _seed_tenant(repository)
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        owner_context = await identities.verify_access_token(owner.access_token)
        support_login = await identities.create_identity(
            owner_context,
            login_name="platform-support",
            display_name="Support One",
            password="support-password-long-enough",
            roles=(PlatformRole.SUPPORT,),
        )
        engineer_login = await identities.create_identity(
            owner_context,
            login_name="platform-engineer",
            display_name="Engineer One",
            password="engineer-password-long-enough",
            roles=(PlatformRole.ENGINEER,),
        )
        support = await identities.verify_access_token(support_login.access_token)
        engineer = await identities.verify_access_token(engineer_login.access_token)
        request = SensitiveAccessGrantRequest(
            tenant_id=tenant_id,
            purpose_code="SUPPORT_DIAGNOSIS",
            ticket_reference="SUP-100",
            requested_duration_minutes=15,
        )

        with pytest.raises(PlatformPermissionDenied):
            await sensitive.issue_grant(engineer, request)
        grant = await sensitive.issue_grant(support, request)
        identity = await sensitive.read_identity(
            support,
            grant_id=grant.grant_id,
            tenant_id=tenant_id,
            subject_id=uuid4(),
            identity_loader=lambda: ("Patient One", "masked@example.test"),
        )
        assert identity.display_name == "Patient One"
        assert identity.grant_id == grant.grant_id

        with pytest.raises(PlatformPermissionDenied):
            await sensitive.read_identity(
                support, grant_id=grant.grant_id, tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=lambda: ("Patient Two", "other@example.test"),
            )

        clock.value += timedelta(minutes=15)
        with pytest.raises(PlatformPermissionDenied):
            await sensitive.read_identity(
                support,
                grant_id=grant.grant_id,
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=lambda: ("Patient Two", None),
            )

        actions = [event.action for event in await repository.audit_events(tenant_id=tenant_id)]
        assert actions == [
            "sensitive-access.deny",
            "sensitive-access.grant",
            "sensitive-access.use",
            "sensitive-access.deny",
            "sensitive-access.deny",
        ]
        deny_reasons = [
            dict(event.details).get("reason")
            for event in await repository.audit_events(tenant_id=tenant_id)
            if event.action == "sensitive-access.deny"
        ]
        assert deny_reasons == ["role_unauthorized", "grant_invalid", "context_inactive"]

    asyncio.run(exercise())


def test_sensitive_access_records_denial_when_grant_invalid() -> None:
    async def exercise() -> None:
        repository, clock, identities, sensitive = _services()
        tenant_id = await _seed_tenant(repository)
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        owner_context = await identities.verify_access_token(owner.access_token)
        with pytest.raises(PlatformPermissionDenied, match="grant is invalid"):
            await sensitive.read_identity(
                owner_context,
                grant_id=uuid4(),
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=lambda: ("Never Loaded", None),
            )
        events = [
            event
            for event in await repository.audit_events(tenant_id=tenant_id)
            if event.action == "sensitive-access.deny"
        ]
        assert len(events) == 1
        assert dict(events[0].details).get("reason") == "grant_invalid"

    asyncio.run(exercise())


def test_sensitive_identity_defers_async_loader_until_disclosure_is_authorized() -> None:
    async def exercise() -> None:
        repository, clock, identities, sensitive = _services()
        tenant_id = await _seed_tenant(repository)
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        owner_context = await identities.verify_access_token(owner.access_token)
        engineer_login = await identities.create_identity(
            owner_context,
            login_name="platform-engineer",
            display_name="Engineer One",
            password="engineer-password-long-enough",
            roles=(PlatformRole.ENGINEER,),
        )
        engineer_context = await identities.verify_access_token(engineer_login.access_token)
        calls = 0

        async def loader() -> tuple[str, str]:
            nonlocal calls
            calls += 1
            return ("Patient One", "masked@example.test")

        with pytest.raises(PlatformPermissionDenied, match="cannot disclose"):
            await sensitive.read_identity(
                engineer_context,
                grant_id=uuid4(),
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=loader,
            )
        with pytest.raises(PlatformPermissionDenied, match="grant is invalid"):
            await sensitive.read_identity(
                owner_context,
                grant_id=uuid4(),
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=loader,
            )
        grant = await sensitive.issue_grant(
            owner_context,
            SensitiveAccessGrantRequest(
                tenant_id=tenant_id,
                purpose_code="SUPPORT_DIAGNOSIS",
                ticket_reference="SUP-120",
                requested_duration_minutes=15,
            ),
        )
        response = await sensitive.read_identity(
            owner_context,
            grant_id=grant.grant_id,
            tenant_id=tenant_id,
            subject_id=uuid4(),
            identity_loader=loader,
        )
        assert response.display_name == "Patient One"
        assert calls == 1

        expired_grant = await sensitive.issue_grant(
            owner_context,
            SensitiveAccessGrantRequest(
                tenant_id=tenant_id,
                purpose_code="SUPPORT_DIAGNOSIS",
                ticket_reference="SUP-120-expired",
                requested_duration_minutes=15,
            ),
        )
        context_with_extra_minute = replace(
            owner_context, expires_at=owner_context.expires_at + timedelta(minutes=1)
        )
        clock.value += timedelta(minutes=15)
        with pytest.raises(PlatformPermissionDenied, match="grant is invalid"):
            await sensitive.read_identity(
                context_with_extra_minute,
                grant_id=expired_grant.grant_id,
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=loader,
            )
        assert calls == 1
        with pytest.raises(PlatformPermissionDenied, match="not active"):
            await sensitive.read_identity(
                owner_context,
                grant_id=uuid4(),
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=loader,
            )
        assert calls == 1

    asyncio.run(exercise())


def test_sensitive_identity_records_denial_when_authorized_loader_fails() -> None:
    async def exercise() -> None:
        repository, _, identities, sensitive = _services()
        tenant_id = await _seed_tenant(repository)
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        owner_context = await identities.verify_access_token(owner.access_token)
        grant = await sensitive.issue_grant(
            owner_context,
            SensitiveAccessGrantRequest(
                tenant_id=tenant_id,
                purpose_code="SUPPORT_DIAGNOSIS",
                ticket_reference="SUP-121",
                requested_duration_minutes=15,
            ),
        )

        async def loader() -> tuple[str, str]:
            raise RuntimeError("identity decryption failed")

        with pytest.raises(RuntimeError, match="decryption failed"):
            await sensitive.read_identity(
                owner_context,
                grant_id=grant.grant_id,
                tenant_id=tenant_id,
                subject_id=uuid4(),
                identity_loader=loader,
            )

        events = await repository.audit_events(tenant_id=tenant_id)
        denials = [event for event in events if event.action == "sensitive-access.deny"]
        assert len(denials) == 1
        assert dict(denials[0].details).get("reason") == "identity_load_failed"
        assert "sensitive-access.use" not in [event.action for event in events]

    asyncio.run(exercise())


def test_cross_tenant_platform_listing_is_masked_operational_summary() -> None:
    async def exercise() -> None:
        repository, _, identities, sensitive = _services()
        tenant_id = await _seed_tenant(repository)
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        context = await identities.verify_access_token(owner.access_token)

        rows = await sensitive.list_tenants(context)

        assert len(rows) == 1
        assert rows[0].tenant_id == tenant_id
        assert rows[0].active_account_count == 1
        serialized = rows[0].model_dump_json().lower()
        assert "patient" not in serialized
        assert "contact" not in serialized

    asyncio.run(exercise())


def test_verify_access_token_rejects_stale_token_after_role_rotation() -> None:
    async def exercise() -> None:
        repository, clock, identities, _ = _services()
        owner = await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        context = await identities.verify_access_token(owner.access_token)
        assert context.roles == frozenset({PlatformRole.OWNER})

        # Simulate `rotate-platform-role`: bump token_version and close role
        # bindings, then re-add a narrower SUPPORT role. The CLI performs these
        # steps atomically against Postgres; this test exercises the verifier's
        # rebinding path against the in-memory repository.
        identity = repository._platform_identities[context.platform_identity_id]
        repository._platform_identities[context.platform_identity_id] = replace(
            identity, token_version=identity.token_version + 1
        )
        for binding in repository._platform_role_bindings:
            if binding.platform_identity_id == context.platform_identity_id:
                repository._platform_role_bindings.remove(binding)
        from uuid import uuid4 as _uuid4

        from techflex_cloud_foundation.server.access_control.repository import (
            PlatformRoleBindingRecord,
        )
        repository._platform_role_bindings.append(
            PlatformRoleBindingRecord(
                binding_id=_uuid4(),
                platform_identity_id=context.platform_identity_id,
                role=PlatformRole.SUPPORT,
                valid_from=clock(),
            )
        )

        with pytest.raises(PlatformPermissionDenied, match="stale"):
            await identities.verify_access_token(owner.access_token)

        fresh = await identities.login(
            PlatformLoginRequest(
                login_name="platform-owner",
                password="correct-horse-battery-staple",
            )
        )
        refreshed = await identities.verify_access_token(fresh.access_token)
        assert refreshed.roles == frozenset({PlatformRole.SUPPORT})
        assert refreshed.token_version == identity.token_version + 1

    asyncio.run(exercise())


def test_platform_login_throttles_after_five_failed_attempts() -> None:
    async def exercise() -> None:
        _, _, identities, _ = _services()
        await identities.bootstrap_owner(
            login_name="platform-owner",
            display_name="Platform Owner",
            password="correct-horse-battery-staple",
        )
        bad_request = PlatformLoginRequest(
            login_name="platform-owner",
            password="wrong-password",
        )
        for _ in range(5):
            with pytest.raises(PlatformPermissionDenied, match="rejected"):
                await identities.login(bad_request, source_fingerprint=b"fingerprint-a")
        # Distributed source rotation must not reset the account-level counter.
        with pytest.raises(PlatformPermissionDenied, match="temporarily unavailable"):
            await identities.login(bad_request, source_fingerprint=b"fingerprint-b")
        # Correct password is also rejected while the account is locked.
        with pytest.raises(PlatformPermissionDenied, match="temporarily unavailable"):
            await identities.login(
                PlatformLoginRequest(
                    login_name="platform-owner",
                    password="correct-horse-battery-staple",
                ),
                source_fingerprint=b"fingerprint-c",
            )

    asyncio.run(exercise())
