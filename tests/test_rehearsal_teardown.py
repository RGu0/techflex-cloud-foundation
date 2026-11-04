"""Execute teardown with isolated files and doubles for privileged host commands."""

import os
from pathlib import Path
import subprocess

import pytest
from test_rehearsal_assets import REHEARSAL, _working_bash

pytestmark = pytest.mark.skipif(not _working_bash(), reason="no working bash")


@pytest.fixture
def teardown(tmp_path: Path):
    scratch = tmp_path / "scratch"
    (scratch / "nginx").mkdir(parents=True)
    (scratch / "nginx/nginx.pid").write_text("987654\n")
    original = scratch / "pg_hba.conf.orig"
    original.write_text("original config\n")
    hba = tmp_path / "pg_hba.conf"
    hba.write_text("# rehearsal\n")
    # Only the privilege guard and fixed host paths change; all teardown control
    # flow runs unchanged. Functions intercept even bash's builtin kill.
    source = (REHEARSAL / "rehearse-3-down.sh").read_text()
    source = source.replace('${EUID}', '0')
    source = source.replace('/var/lib/feetforceplate/.rehearsal', str(scratch))
    source = source.replace('/var/lib/pgsql/data/pg_hba.conf', str(hba))
    assert '/var/lib/' not in source
    doubles = r'''
kill() { touch "${REHEARSAL_CONFIG%/*}/terminated"; [[ "$FAIL" != kill ]]; }
ps() {
  [[ "$FAIL" != ps ]] || return 1
  if [[ "$FAIL" == wrong_process ]]; then echo 'unrelated worker';
  else echo "nginx: master process nginx -c $REHEARSAL_CONFIG -p ignored"; fi
}
sleep() { :; }
systemctl() {
  case "$1" in
    show) [[ "$FAIL" != show ]] || return 1; echo "${UNIT_STATE:-loaded}" ;;
    stop) [[ "$FAIL" != stop ]] ;;
    reset-failed) return 0 ;;
    *) return 99 ;;
  esac
}
install() {
  [[ "$FAIL" != install ]] || return 1
  [[ "$FAIL" != cmp ]] || return 0
  cp "$7" "$8"
}
runuser() {
  [[ "$1 $2 $3" == '-u postgres --' ]] || return 99
  shift 3
  if [[ "$1" == dropdb ]]; then
    [[ "$*" == 'dropdb --if-exists feetforceplate_rehearsal' ]] || return 99
    [[ "$FAIL" != dropdb ]]
  elif [[ "$1 $2" == 'psql -Atqc' ]]; then
    case "$3" in
      'select pg_reload_conf()')
        [[ "$FAIL" != reload ]] || return 1
        if [[ "$FAIL" == reload_false ]]; then echo f; else echo t; fi ;;
      'select count(*) from pg_database where datname='*)
        [[ "$FAIL" != db_query ]] || return 1
        if [[ "$FAIL" == db_present ]]; then echo 1; else echo 0; fi ;;
      *) return 99 ;;
    esac
  else return 99; fi
}
ss() {
  [[ "$FAIL" != ss ]] || return 1
  if [[ "$FAIL" == listener ]]; then echo 'LISTEN 0 128 127.0.0.1:27443'; fi
  return 0
}
'''
    script = tmp_path / "down.sh"
    script.write_text(doubles + '\n' + source)

    def run(failure="", unit_state="loaded"):
        return subprocess.run(
            ["bash", str(script)], capture_output=True, text=True, check=False,
            env={**os.environ, "FAIL": failure, "UNIT_STATE": unit_state,
                 "REHEARSAL_CONFIG": str(scratch / "nginx/nginx.conf")},
        )

    return run, scratch, original, hba


@pytest.mark.parametrize("failure", [
    "kill", "stop", "install", "reload", "reload_false", "cmp", "dropdb",
    "ss", "listener", "db_query", "db_present", "show", "ps", "wrong_process",
])
def test_failure_preserves_recovery_files_and_can_be_retried(teardown, failure):
    run, scratch, original, hba = teardown
    failed = run(failure)
    assert failed.returncode != 0, failed.stdout + failed.stderr
    assert "rehearsal_down=done" not in failed.stdout
    assert original.read_text() == "original config\n"
    if failure in {"ps", "wrong_process"}:
        assert not (scratch / "nginx/terminated").exists()
    recovered = run()
    assert recovered.returncode == 0, recovered.stderr
    assert hba.read_text() == "original config\n"
    assert not scratch.exists()
    assert "rehearsal_down=done" in recovered.stdout


def test_success_and_repeated_teardown_with_missing_transient_unit(teardown):
    run, scratch, _, hba = teardown
    result = run()
    assert result.returncode == 0, result.stderr
    assert hba.read_text() == "original config\n"
    assert not scratch.exists()
    repeated = run(unit_state="not-found")
    assert repeated.returncode == 0, repeated.stderr
    assert "rehearsal_down=done" in repeated.stdout


def test_missing_backup_with_tagged_configuration_refuses_cleanup(teardown):
    run, scratch, original, _ = teardown
    original.unlink()
    result = run()
    assert result.returncode != 0
    assert scratch.is_dir()
    assert "rehearsal_down=done" not in result.stdout
