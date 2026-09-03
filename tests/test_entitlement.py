"""The license lifecycle, asserted as a table rather than as examples.

``entitlement.py`` had no test module.  ``LicenseLifecycle.transition``
enforced a single rule -- REVOKED is terminal -- and every other pair was
legal because nothing forbade it.  A whitelist only stays a whitelist if the
cells nobody thought about are the ones under test, so all sixteen ordered
pairs are enumerated here and each is asserted to be exactly as legal as the
lifecycle says.
"""

from __future__ import annotations

import itertools
from uuid import uuid4

import pytest

from techflex_cloud_foundation import LicenseLifecycle, LicenseRecord, LicenseState

TENANT = uuid4()
ACCOUNT = uuid4()
HARDWARE = "workstation-7f3a"

LEGAL_TRANSITIONS = frozenset(
    {
        (LicenseState.ACTIVE, LicenseState.SUSPENDED),
        (LicenseState.ACTIVE, LicenseState.REVOKED),
        (LicenseState.SUSPENDED, LicenseState.ACTIVE),
        (LicenseState.SUSPENDED, LicenseState.REVOKED),
    }
)
ALL_PAIRS = list(itertools.product(LicenseState, LicenseState))
REFUSED_TRANSITIONS = [pair for pair in ALL_PAIRS if pair not in LEGAL_TRANSITIONS]


def _record(state: LicenseState, *, version: int = 3) -> LicenseRecord:
    """A record in ``state``, bound as it would be in reality.

    Bindings are carried by every state except UNUSED, which is what makes a
    move back to UNUSED a contradiction rather than merely unusual.
    """

    if state is LicenseState.UNUSED:
        return LicenseRecord(uuid4(), state, version)
    return LicenseRecord(uuid4(), state, version, TENANT, ACCOUNT, HARDWARE)


class TestTransitionTable:
    def test_the_table_covers_every_ordered_pair(self) -> None:
        """A guard against the test file drifting behind the enum."""

        assert len(ALL_PAIRS) == len(LicenseState) ** 2 == 16

    @pytest.mark.parametrize("current,requested", ALL_PAIRS)
    def test_each_pair_is_exactly_as_legal_as_the_lifecycle_says(
        self, current: LicenseState, requested: LicenseState
    ) -> None:
        record = _record(current)

        if (current, requested) in LEGAL_TRANSITIONS:
            moved = LicenseLifecycle.transition(record, requested)
            assert moved.state is requested
            assert moved.version == record.version + 1
        else:
            with pytest.raises(ValueError):
                LicenseLifecycle.transition(record, requested)

    @pytest.mark.parametrize("current,requested", sorted(LEGAL_TRANSITIONS))
    def test_a_legal_move_carries_the_binding_forward_unchanged(
        self, current: LicenseState, requested: LicenseState
    ) -> None:
        """Only ``activate`` may write bindings; a transition preserves them."""

        record = _record(current)

        moved = LicenseLifecycle.transition(record, requested)

        assert (moved.license_id, moved.tenant_id, moved.account_id, moved.hardware_id) == (
            record.license_id,
            TENANT,
            ACCOUNT,
            HARDWARE,
        )

    @pytest.mark.parametrize("current,requested", REFUSED_TRANSITIONS)
    def test_a_refused_move_leaves_the_record_untouched(
        self, current: LicenseState, requested: LicenseState
    ) -> None:
        """``LicenseRecord`` is frozen, so this is a property of the design."""

        record = _record(current)
        before = (record.state, record.version)

        with pytest.raises(ValueError):
            LicenseLifecycle.transition(record, requested)

        assert (record.state, record.version) == before


class TestWhatEachRefusalProtects:
    def test_an_unused_license_cannot_be_activated_by_transition(self) -> None:
        """The bug the whitelist exists for.

        ``transition(record, ACTIVE)`` used to succeed on an UNUSED license and
        return an ACTIVE record with no tenant, no account, and no hardware --
        a state whose whole meaning is that those three are bound.
        """

        record = _record(LicenseState.UNUSED)

        with pytest.raises(ValueError, match="activate"):
            LicenseLifecycle.transition(record, LicenseState.ACTIVE)

    @pytest.mark.parametrize(
        "current", [LicenseState.ACTIVE, LicenseState.SUSPENDED, LicenseState.REVOKED]
    )
    def test_nothing_returns_to_unused(self, current: LicenseState) -> None:
        """UNUSED means unbound, and the bindings would survive the move."""

        with pytest.raises(ValueError):
            LicenseLifecycle.transition(_record(current), LicenseState.UNUSED)

    @pytest.mark.parametrize("requested", list(LicenseState))
    def test_revoked_is_terminal_in_every_direction(self, requested: LicenseState) -> None:
        with pytest.raises(ValueError):
            LicenseLifecycle.transition(_record(LicenseState.REVOKED), requested)

    def test_re_revoking_is_refused_because_it_is_not_a_no_op(self) -> None:
        """Every call increments ``version``, so repetition is not free.

        A second REVOKED would bump the version with no state change and
        invalidate a concurrent holder's optimistic-concurrency check.  The
        caller checks the state instead; the error message says so.
        """

        record = _record(LicenseState.REVOKED)

        with pytest.raises(ValueError, match="already REVOKED"):
            LicenseLifecycle.transition(record, LicenseState.REVOKED)

    @pytest.mark.parametrize("state", list(LicenseState))
    def test_a_state_is_never_transitioned_to_itself(self, state: LicenseState) -> None:
        with pytest.raises(ValueError, match="already"):
            LicenseLifecycle.transition(_record(state), state)


class TestSuspensionIsRecoverable:
    def test_a_suspended_license_returns_to_active_with_its_hardware_intact(self) -> None:
        """The reason SUSPENDED exists rather than revoking and re-issuing.

        A lapsed-then-restored subscription must not make the customer
        re-activate hardware, so the binding has to survive the round trip.
        """

        activated = LicenseLifecycle.activate(
            LicenseRecord(uuid4(), LicenseState.UNUSED, 1),
            tenant_id=TENANT,
            account_id=ACCOUNT,
            hardware_id=HARDWARE,
        )

        suspended = LicenseLifecycle.transition(activated, LicenseState.SUSPENDED)
        restored = LicenseLifecycle.transition(suspended, LicenseState.ACTIVE)

        assert restored.state is LicenseState.ACTIVE
        assert restored.hardware_id == HARDWARE
        assert restored.version == activated.version + 2

    def test_the_round_trip_can_be_repeated(self) -> None:
        record = LicenseLifecycle.activate(
            LicenseRecord(uuid4(), LicenseState.UNUSED, 1),
            tenant_id=TENANT,
            account_id=ACCOUNT,
            hardware_id=HARDWARE,
        )

        for _ in range(3):
            record = LicenseLifecycle.transition(record, LicenseState.SUSPENDED)
            record = LicenseLifecycle.transition(record, LicenseState.ACTIVE)

        assert record.state is LicenseState.ACTIVE
        assert record.version == 8


class TestActivation:
    def test_activation_binds_all_three_facts_and_advances_the_version(self) -> None:
        record = LicenseRecord(uuid4(), LicenseState.UNUSED, 1)

        activated = LicenseLifecycle.activate(
            record, tenant_id=TENANT, account_id=ACCOUNT, hardware_id=HARDWARE
        )

        assert activated.state is LicenseState.ACTIVE
        assert (activated.tenant_id, activated.account_id, activated.hardware_id) == (
            TENANT,
            ACCOUNT,
            HARDWARE,
        )
        assert activated.version == 2

    @pytest.mark.parametrize(
        "state", [LicenseState.ACTIVE, LicenseState.SUSPENDED, LicenseState.REVOKED]
    )
    def test_only_an_unused_license_can_be_activated(self, state: LicenseState) -> None:
        with pytest.raises(ValueError, match="unused"):
            LicenseLifecycle.activate(
                _record(state), tenant_id=TENANT, account_id=ACCOUNT, hardware_id=HARDWARE
            )

    def test_an_empty_hardware_id_is_not_a_binding(self) -> None:
        with pytest.raises(ValueError):
            LicenseLifecycle.activate(
                LicenseRecord(uuid4(), LicenseState.UNUSED, 1),
                tenant_id=TENANT,
                account_id=ACCOUNT,
                hardware_id="",
            )
