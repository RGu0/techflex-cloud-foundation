"""The host rehearsal scripts keep the guards that make them safe to run beside production."""

from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import pytest

REHEARSAL = Path(__file__).resolve().parents[1] / "deploy" / "aliyun" / "seed" / "rehearsal"
SCRIPTS = sorted(REHEARSAL.glob("rehearse-*.sh"))


def _text(name: str) -> str:
    return (REHEARSAL / name).read_text(encoding="utf-8")


def test_the_rehearsal_scripts_are_present() -> None:
    assert [path.name for path in SCRIPTS] == [
        "rehearse-1-runtime.sh",
        "rehearse-1b-warm.sh",
        "rehearse-2-restore-migrate.sh",
        "rehearse-2b-acl.sh",
        "rehearse-3-down.sh",
        "rehearse-3-up.sh",
    ]


def _working_bash() -> bool:
    # On a Windows runner `bash` can be the WSL launcher with no distribution installed.
    try:
        probe = subprocess.run(["bash", "-c", "echo ok"], capture_output=True, check=False)
    except OSError:
        return False
    return probe.returncode == 0 and probe.stdout.strip() == b"ok"


@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_each_script_requires_root(script: Path) -> None:
    text = script.read_text(encoding="utf-8")
    assert text.startswith("#!/usr/bin/env bash\n")
    assert "EUID" in text


@pytest.mark.skipif(not _working_bash(), reason="no working bash on this host")
@pytest.mark.parametrize("script", SCRIPTS, ids=lambda path: path.name)
def test_each_script_is_valid_bash(script: Path) -> None:
    # As bytes over stdin: a text-mode pipe on Windows would turn every newline into CRLF.
    subprocess.run(["bash", "-n"], input=script.read_bytes(), check=True)


def test_the_loopback_instance_never_reaches_production_endpoints_or_oss() -> None:
    up = _text("rehearse-3-up.sh")

    assert "OSS_[A-Z_]*" in up and "BACKUP_[A-Z_]*" in up
    assert "FEETFORCEPLATE_OBJECT_BACKEND=filesystem" in up
    assert "listen 127.0.0.1:27443 ssl;" in up and "127.0.0.1:8743#127.0.0.1:28743" in up
    assert "FEETFORCEPLATE_BIND_PORT=28743" in up
    assert "leaked into rehearsal env" in up


def test_the_temporary_pg_hba_lines_are_tagged_and_restored_byte_for_byte() -> None:
    up, down = _text("rehearse-3-up.sh"), _text("rehearse-3-down.sh")

    assert "pg_hba.conf.orig" in up and "# rehearsal" in up
    assert "pg_reload_conf" in up and "pg_reload_conf" in down
    assert 'cmp "$r/pg_hba.conf.orig" "$hba"' in down
    assert "dropdb" in down


def test_the_restore_step_compares_production_before_and_after() -> None:
    restore = _text("rehearse-2-restore-migrate.sh")

    assert "PRODUCTION CHANGED" in restore
    assert 'rm -f -- "$identity_source"' in restore


def test_the_allowlist_proxy_tunnels_only_the_wheel_host() -> None:
    namespace: dict[str, object] = {}
    source = (REHEARSAL / "allowlist_proxy.py").read_text(encoding="utf-8")
    exec(compile(source.split("if __name__")[0], "allowlist_proxy.py", "exec"), namespace)

    assert namespace["ALLOWED"] == {("files.pythonhosted.org", 443)}
    proxy = str(REHEARSAL / "allowlist_proxy.py")
    subprocess.run([sys.executable, "-m", "py_compile", proxy], check=True)
