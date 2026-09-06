from __future__ import annotations

from datetime import UTC, datetime, timedelta
import hashlib
from pathlib import Path

import pytest

from techflex_cloud_foundation import (
    BackupComponent,
    BackupManifest,
    ChainedAppendLog,
    EventAuditAnchor,
    InMemoryRestoreTarget,
    ObservabilityMalformed,
    ObservabilityVersionUnsupported,
    RecoveryReceipt,
    RecoveryTargetNotEmpty,
    RecoveryVerificationFailed,
    RestoreVerifier,
    SafeFieldCatalog,
    SecurityEvent,
    Severity,
    SliThreshold,
    ThresholdDirection,
)

NOW = datetime(2026, 9, 6, tzinfo=UTC)
DATABASE_BYTES = b"pg dump bytes"
OBJECTS_BYTES = b"tarred objects"


def _catalog() -> SafeFieldCatalog:
    return SafeFieldCatalog(("operation", "status", "retryable", "duration_ms"))


def _event(
    catalog: SafeFieldCatalog | None = None,
    *,
    fields: dict[str, object] | None = None,
    occurred_at: datetime = NOW,
) -> SecurityEvent:
    return (catalog or _catalog()).build_event(
        event_name="backup_completed",
        severity=Severity.INFO,
        component="platform.backup",
        correlation_id="corr-1",
        occurred_at=occurred_at,
        fields={"operation": "backup", "status": "ok"} if fields is None else fields,
    )


def _manifest(**overrides: object) -> BackupManifest:
    kwargs: dict[str, object] = {
        "components": (
            BackupComponent(
                name="database",
                sha256=hashlib.sha256(DATABASE_BYTES).hexdigest(),
                size_bytes=len(DATABASE_BYTES),
                key_reference="backup/age-key-1",
            ),
            BackupComponent(
                name="objects",
                sha256=hashlib.sha256(OBJECTS_BYTES).hexdigest(),
                size_bytes=len(OBJECTS_BYTES),
            ),
        ),
        "tenant_count": 2,
        "source_version": "schema-0006",
        "created_at": NOW,
    }
    kwargs.update(overrides)
    return BackupManifest(**kwargs)  # type: ignore[arg-type]


class TestSafeFieldCatalog:
    def test_undeclared_field_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="whitelist"):
            _event(fields={"operation": "backup", "queue_depth": 3})

    def test_identity_field_can_never_be_declared(self) -> None:
        for name in ("user_identity", "access_token", "object_key", "raw_payload"):
            with pytest.raises(ObservabilityMalformed, match="refused"):
                SafeFieldCatalog(("operation", name))

    def test_forbidden_field_is_refused_at_build_time(self) -> None:
        catalog = _catalog()
        with pytest.raises(ObservabilityMalformed, match="refused"):
            catalog.build_event(
                event_name="x",
                severity=Severity.INFO,
                component="c",
                correlation_id="corr-1",
                occurred_at=NOW,
                fields={"session_token": "abc"},
            )

    def test_secret_like_value_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="secret-like"):
            _event(fields={"operation": "Bearer abc123", "status": "ok"})

    def test_non_json_values_are_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="JSON"):
            _event(fields={"operation": object(), "status": "ok"})

    def test_nested_containers_are_accepted(self) -> None:
        event = _event(fields={"operation": "backup", "status": {"phase": "done"}})
        assert event.fields["status"] == {"phase": "done"}

    def test_unknown_event_version_is_refused(self) -> None:
        with pytest.raises(ObservabilityVersionUnsupported):
            SecurityEvent(
                event_name="x",
                severity=Severity.INFO,
                component="c",
                correlation_id="corr-1",
                occurred_at=NOW,
                fields={},
                event_version=99,
            )

    def test_naive_timestamp_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="timezone-aware"):
            _event(occurred_at=datetime(2026, 9, 6))

    def test_event_digest_is_reproducible(self) -> None:
        assert _event().digest() == _event().digest()


class TestSliThreshold:
    def test_contradictory_bounds_are_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="contradict"):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(minutes=5),
                direction=ThresholdDirection.WITHIN,
                lower=0.9,
                upper=0.1,
            )

    def test_direction_with_an_unused_bound_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="contradiction"):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(minutes=5),
                direction=ThresholdDirection.AT_MOST,
                lower=0.1,
                upper=0.5,
            )

    def test_direction_missing_its_bound_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="requires its bound"):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(minutes=5),
                direction=ThresholdDirection.AT_LEAST,
            )

    def test_bounded_direction_requires_both_bounds(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="both bounds"):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(minutes=5),
                direction=ThresholdDirection.OUTSIDE,
                lower=0.1,
            )

    def test_non_positive_window_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="window"):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(0),
                direction=ThresholdDirection.AT_MOST,
                upper=0.5,
            )

    def test_non_finite_bound_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="finite"):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(minutes=5),
                direction=ThresholdDirection.AT_MOST,
                upper=float("nan"),
            )

    def test_unknown_threshold_version_is_refused(self) -> None:
        with pytest.raises(ObservabilityVersionUnsupported):
            SliThreshold(
                metric_name="error_rate",
                window=timedelta(minutes=5),
                direction=ThresholdDirection.AT_MOST,
                upper=0.5,
                threshold_version=99,
            )

    def test_breach_evaluation(self) -> None:
        at_most = SliThreshold(
            metric_name="error_rate",
            window=timedelta(minutes=5),
            direction=ThresholdDirection.AT_MOST,
            upper=0.05,
        )
        assert at_most.is_breach(0.06)
        assert not at_most.is_breach(0.05)
        within = SliThreshold(
            metric_name="heartbeat_seconds",
            window=timedelta(minutes=5),
            direction=ThresholdDirection.WITHIN,
            lower=1.0,
            upper=60.0,
        )
        assert within.is_breach(0.5)
        assert not within.is_breach(30.0)
        outside = SliThreshold(
            metric_name="queue_depth",
            window=timedelta(minutes=5),
            direction=ThresholdDirection.OUTSIDE,
            lower=10.0,
            upper=20.0,
        )
        assert outside.is_breach(15.0)
        assert not outside.is_breach(25.0)


class TestEventAuditAnchor:
    def test_anchored_events_verify_end_to_end(self, tmp_path: Path) -> None:
        anchor = EventAuditAnchor(ChainedAppendLog(tmp_path))
        first = anchor.anchor(_event())
        second = anchor.anchor(
            _event(fields={"operation": "restore", "status": "ok"})
        )
        assert second.previous_sha256 == first.sha256
        records = anchor.verified_events()
        assert [record.sha256 for record in records] == [first.sha256, second.sha256]
        assert anchor.head_digest() == first.sha256
        assert records[0].payload["event_name"] == "backup_completed"

    def test_tampered_chain_fails_verification(self, tmp_path: Path) -> None:
        anchor = EventAuditAnchor(ChainedAppendLog(tmp_path))
        anchor.anchor(_event())
        anchor.anchor(_event(fields={"operation": "restore", "status": "ok"}))
        active = tmp_path / "events.jsonl"
        lines = active.read_bytes().splitlines(keepends=True)
        lines[0] = lines[0].replace(b"backup_completed", b"backup__deleted")
        active.write_bytes(b"".join(lines))
        with pytest.raises(ValueError, match="digest"):
            anchor.verified_events()


class TestBackupManifest:
    def test_empty_component_list_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="at least one component"):
            _manifest(components=())

    def test_duplicate_component_names_are_refused(self) -> None:
        component = BackupComponent(
            name="database",
            sha256=hashlib.sha256(DATABASE_BYTES).hexdigest(),
            size_bytes=len(DATABASE_BYTES),
        )
        with pytest.raises(ObservabilityMalformed, match="unique"):
            _manifest(components=(component, component))

    def test_unknown_format_version_is_refused(self) -> None:
        with pytest.raises(ObservabilityVersionUnsupported):
            _manifest(format_version=99)

    def test_short_digest_prefix_is_refused(self) -> None:
        with pytest.raises(ObservabilityMalformed, match="complete lowercase hex"):
            BackupComponent(name="database", sha256="abc123", size_bytes=1)

    def test_manifest_digest_is_reproducible(self) -> None:
        assert _manifest().digest() == _manifest().digest()


class TestRestoreVerifier:
    def test_successful_drill_issues_a_receipt(self) -> None:
        manifest = _manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                {"database": DATABASE_BYTES, "objects": OBJECTS_BYTES},
                tenant_count=2,
                version="schema-0006",
                key_references=("backup/age-key-1",),
            )

        receipt = RestoreVerifier().run_drill(
            manifest, target, restore, verified_at=NOW
        )
        assert isinstance(receipt, RecoveryReceipt)
        assert receipt.manifest_digest == manifest.digest()
        assert receipt.tenant_count == 2
        assert receipt.restored_version == "schema-0006"
        assert [c.name for c in receipt.components] == ["database", "objects"]
        assert receipt.components[0].sha256 == manifest.components[0].sha256

    def test_non_empty_target_is_refused(self) -> None:
        manifest = _manifest()
        target = InMemoryRestoreTarget()
        target.load(
            {"database": DATABASE_BYTES, "objects": OBJECTS_BYTES},
            tenant_count=2,
            version="schema-0006",
            key_references=("backup/age-key-1",),
        )
        with pytest.raises(RecoveryTargetNotEmpty):
            RestoreVerifier().run_drill(manifest, target, lambda: None, verified_at=NOW)

    def test_tampered_component_bytes_fail(self) -> None:
        manifest = _manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                {"database": b"tampered byte", "objects": OBJECTS_BYTES},
                tenant_count=2,
                version="schema-0006",
                key_references=("backup/age-key-1",),
            )

        with pytest.raises(RecoveryVerificationFailed, match="digest mismatch"):
            RestoreVerifier().run_drill(manifest, target, restore, verified_at=NOW)

    def test_declared_but_unrestored_component_fails(self) -> None:
        """A component asserted present but never re-digested is a failure."""
        manifest = _manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                {"objects": OBJECTS_BYTES},
                tenant_count=2,
                version="schema-0006",
                key_references=("backup/age-key-1",),
            )

        with pytest.raises(RecoveryVerificationFailed, match="never restored"):
            RestoreVerifier().run_drill(manifest, target, restore, verified_at=NOW)

    def test_tenant_count_mismatch_fails(self) -> None:
        manifest = _manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                {"database": DATABASE_BYTES, "objects": OBJECTS_BYTES},
                tenant_count=1,
                version="schema-0006",
                key_references=("backup/age-key-1",),
            )

        with pytest.raises(RecoveryVerificationFailed, match="tenant count"):
            RestoreVerifier().run_drill(manifest, target, restore, verified_at=NOW)

    def test_version_mismatch_fails(self) -> None:
        manifest = _manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                {"database": DATABASE_BYTES, "objects": OBJECTS_BYTES},
                tenant_count=2,
                version="schema-0005",
                key_references=("backup/age-key-1",),
            )

        with pytest.raises(RecoveryVerificationFailed, match="version"):
            RestoreVerifier().run_drill(manifest, target, restore, verified_at=NOW)

    def test_unresolvable_old_key_reference_fails(self) -> None:
        manifest = _manifest()
        target = InMemoryRestoreTarget()

        def restore() -> None:
            target.load(
                {"database": DATABASE_BYTES, "objects": OBJECTS_BYTES},
                tenant_count=2,
                version="schema-0006",
                key_references=("backup/age-key-2",),
            )

        with pytest.raises(RecoveryVerificationFailed, match="key reference"):
            RestoreVerifier().run_drill(manifest, target, restore, verified_at=NOW)
