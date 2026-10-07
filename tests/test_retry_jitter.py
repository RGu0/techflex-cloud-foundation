from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from techflex_cloud_foundation import RetryPolicy

NOW = datetime(2026, 10, 7, tzinfo=UTC)


def _no_randomness() -> float:
    raise AssertionError("this deadline must not consume randomness")


@pytest.mark.parametrize("sample, seconds", [(0.0, 3.5), (0.5, 5.0), (1.0, 6.5)])
def test_optional_jitter_spreads_the_public_retry_deadline(sample: float, seconds: float) -> None:
    policy = RetryPolicy(max_jitter_fraction=0.3, random_source=lambda: sample)
    assert policy.next_attempt_at(now=NOW, attempt_count=1) == NOW + timedelta(seconds=seconds)
    assert policy.delay_for(1) == timedelta(seconds=5)


def test_default_policy_preserves_deadline_without_randomness() -> None:
    policy = RetryPolicy(timedelta(seconds=5), timedelta(seconds=30), random_source=_no_randomness)
    assert policy.next_attempt_at(now=NOW, attempt_count=3) == NOW + timedelta(seconds=20)


def test_retry_after_is_exact_even_above_cap_and_with_jitter() -> None:
    policy = RetryPolicy(max_jitter_fraction=1.0, random_source=_no_randomness)
    assert policy.next_attempt_at(
        now=NOW, attempt_count=2, retry_after=timedelta(hours=1)
    ) == NOW + timedelta(hours=1)


@pytest.mark.parametrize("sample, seconds", [(0.0, 7.0), (0.5, 10.0), (1.0, 10.0)])
def test_jitter_remains_capped_for_extreme_attempt_counts(sample: float, seconds: float) -> None:
    policy = RetryPolicy(
        cap_delay=timedelta(seconds=10), max_jitter_fraction=0.3, random_source=lambda: sample
    )
    assert policy.next_attempt_at(now=NOW, attempt_count=10_000) == NOW + timedelta(seconds=seconds)


def test_huge_timedelta_is_clamped_before_multiplication_can_overflow() -> None:
    policy = RetryPolicy(
        timedelta.max, timedelta.max, max_jitter_fraction=1.0, random_source=lambda: 1.0
    )
    # A zero sample permits a representable deadline even for the largest delay.
    zero = RetryPolicy(
        timedelta.max, timedelta.max, max_jitter_fraction=1.0, random_source=lambda: 0.0
    )
    assert zero.next_attempt_at(now=NOW, attempt_count=10_000) == NOW
    # Datetime overflow remains datetime's own boundary, not a delay computation error.
    with pytest.raises(OverflowError, match="date value out of range"):
        policy.next_attempt_at(now=NOW, attempt_count=10_000)


@pytest.mark.parametrize("fraction", [-0.1, 1.1, float("nan"), float("inf"), True, "0.3", None])
def test_invalid_jitter_configuration_is_refused(fraction: object) -> None:
    with pytest.raises(ValueError, match="max_jitter_fraction"):
        RetryPolicy(max_jitter_fraction=fraction)  # type: ignore[arg-type]


@pytest.mark.parametrize("sample", [-0.1, 1.1, float("nan"), float("inf"), True, "0.5", None])
def test_invalid_random_sample_cannot_schedule_a_retry(sample: object) -> None:
    policy = RetryPolicy(max_jitter_fraction=0.3, random_source=lambda: sample)  # type: ignore[arg-type,return-value]
    with pytest.raises(ValueError, match="random_source"):
        policy.next_attempt_at(now=NOW, attempt_count=1)


def test_random_source_must_be_callable() -> None:
    with pytest.raises(ValueError, match="random_source"):
        RetryPolicy(random_source=None)  # type: ignore[arg-type]
