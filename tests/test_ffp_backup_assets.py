from __future__ import annotations

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "deploy/aliyun/seed"


def test_backup_is_custom_format_manifested_encrypted_and_atomically_published() -> None:
    text = (ROOT / "backup.sh").read_text()
    for token in (
        "pg_dump", "--format=custom", "sha256sum", "object-manifest.sha256",
        "FEETFORCEPLATE_BACKUP_AGE_RECIPIENT", "age --recipient", ".staging-",
        "sync -f", "mv ", "implementation_sha", "schema_versions",
    ):
        assert token in text
    assert "AGE_RECIPIENT=" not in text
    assert "PRIVATE_KEY" not in text
    assert 'sha256sum "$bundle_final" >"$bundle_final.sha256.tmp"' in text
    assert 'mv "$bundle_final.sha256.tmp" "$bundle_final.sha256"' in text
    assert "0007_completion_receipt_fields,0008_activation_projection_grants,0009_unverified_session_holds,0010_local_basic_report_copies,0011_controlled_identity_recovery,0012_terminal_activation,0013_insole_inventory,0014_recovery_bound_migration_permits" in text


def test_retention_preserves_newest_verified_backup() -> None:
    text = (ROOT / "backup.sh").read_text()
    assert "newest_bundle" in text
    assert "candidate" in text
    assert '"$candidate" == "$newest_bundle"' in text
    assert "RETENTION_DAYS" in text


def test_restore_requires_separate_empty_targets_and_verifies_objects() -> None:
    text = (ROOT / "restore-verify.sh").read_text()
    for token in (
        "FEETFORCEPLATE_RESTORE_DSN", "FEETFORCEPLATE_BACKUP_DSN",
        "FEETFORCEPLATE_RESTORE_OBJECT_ROOT", "FEETFORCEPLATE_OBJECT_ROOT",
        "target database must be empty", "target object root must be empty",
        "pg_restore", "sha256sum --check", "object-manifest.sha256",
        "FEETFORCEPLATE_BACKUP_AGE_IDENTITY_FILE",
    ):
        assert token in text
    assert "--clean" not in text
    assert "sha256sum --check --quiet" in text


def test_daily_systemd_timer_and_service_are_present() -> None:
    service = (ROOT / "feetforceplate-backup.service").read_text()
    timer = (ROOT / "feetforceplate-backup.timer").read_text()
    assert "User=feetforceplate" in service
    assert "ExecStart=/opt/feetforceplate/app/deploy/aliyun/seed/backup.sh" in service
    assert "ReadWritePaths=/var/lib/feetforceplate/backups" in service
    assert "OnCalendar=daily" in timer
    assert "Persistent=true" in timer


def test_restore_drill_uses_isolated_targets_and_cleans_private_material() -> None:
    path = ROOT / "run-restore-drill.sh"
    text = path.read_text()

    for token in (
        "feetforceplate_restore_",
        "FEETFORCEPLATE_RESTORE_DSN",
        "FEETFORCEPLATE_RESTORE_OBJECT_ROOT",
        "runuser -u postgres",
        "restore-verify.sh",
        "production_unchanged=true",
        "cleanup=verified",
        "dropdb --if-exists",
    ):
        assert token in text
    assert 'rm -rf -- "$work_root"' in text
    assert 'rm -f -- "$identity_source"' in text
    assert "dropdb --if-exists feetforceplate_seed" not in text
    if os.name != "nt":
        assert path.stat().st_mode & 0o100
