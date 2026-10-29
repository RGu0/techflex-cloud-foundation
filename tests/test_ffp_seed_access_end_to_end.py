from __future__ import annotations

import asyncio

from scripts.verify_seed_access import run_local_acceptance


def test_ten_institution_seed_access_lifecycle_and_negative_cases() -> None:
    result = asyncio.run(run_local_acceptance())

    assert result["tenant_count"] == 10
    assert all(row["own_session_visible"] for row in result["tenants"])
    assert all(row["visible_session_count"] == 1 for row in result["tenants"])
    assert result["dynamic_tenant"] == {
        "active_before_expand": 1,
        "active_after_expand": 3,
        "active_after_reduce": 2,
        "historical_contributors": 3,
    }
    assert result["negative_cases"] == {
        "activation_replay_denied": True,
        "concurrent_hardware_lease_denied": True,
        "cross_tenant_session_denied": True,
        "expired_new_test_denied": True,
        "local_test_license_cloud_denied": True,
        "refresh_replay_denied": True,
        "revoked_new_test_denied": True,
        "sensitive_identity_without_grant_denied": True,
        "suspended_new_test_denied": True,
        "unprovisioned_eleventh_tenant_denied": True,
        "wrong_audience_token_denied": True,
        "wrong_hardware_activation_denied": True,
    }
    assert result["secrets_or_raw_identity_included"] is False
