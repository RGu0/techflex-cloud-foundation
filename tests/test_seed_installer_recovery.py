"""Execute the installer in a relocated filesystem; external host commands are doubles."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile

import pytest

pytestmark = pytest.mark.skipif(os.name == 'nt', reason='Linux host shell; POSIX doubles')

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    'var/lib/pgsql/data/pg_hba.conf', 'var/lib/pgsql/data/postgresql.auto.conf',
    'etc/nginx/nginx.conf', 'etc/nginx/conf.d/feetforceplate-seed.conf',
    'etc/feetforceplate/tls/seed.key', 'etc/feetforceplate/tls/seed.crt',
    'etc/systemd/system/feetforceplate-seed.service',
    'etc/systemd/system/feetforceplate-backup.service',
    'etc/systemd/system/feetforceplate-backup.timer',
)
DOUBLE = r'''
import hashlib, json, os, pathlib, shutil, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['FAKE_ROOT'])
state_file = root / 'state.json'
state = json.loads(state_file.read_text())
def save(): state_file.write_text(json.dumps(state))
def fail(point):
    if os.environ.get('FAIL_AT') == point and not state.get('failed'):
        state['failed'] = True; save(); sys.exit(9)
if name in ('chown', 'id', 'age', 'journalctl', 'sleep', 'pg_isready'):
    sys.exit(0)
if name == 'sha256sum':
    print(hashlib.sha256(pathlib.Path(args[0]).read_bytes()).hexdigest(), args[0])
elif name == 'stat': print('600' if args[1] == '%a' else 'feetforceplate:feetforceplate 600')
elif name == 'python3': print('https://example.invalid/wheel ' + os.environ['WHEEL_SHA'])
elif name == 'runuser':
    line = ' '.join(args)
    if 'SHOW unix_socket' in line: print('/tmp/pg')
    elif 'SELECT count' in line: print('1')
    elif 'schema apply' in line:
        (root / 'migration-applied').write_text('forward-only'); fail('migration')
    elif 'schema status' in line: print('{"pending": []}')
    elif 'ALTER SYSTEM' in line:
        (root / 'var/lib/pgsql/data/postgresql.auto.conf').write_text('new-pg-auto')
    elif 'uv sync' in line:
        pass
elif name == 'systemctl':
    action = args[0]; units = args[1:]
    if (action == 'is-active' and units[-1] == 'feetforceplate-seed.service'
            and state.get('failed') and os.environ.get('RECOVERY_FAIL') == 'unknown'):
        print('unknown'); sys.exit(4)
    missing = (units and units[-1].startswith('feetforceplate-')
               and not (root / 'etc/systemd/system' / units[-1]).exists())
    if missing:
        if action == 'is-active': print('unknown'); sys.exit(4)
        if action == 'is-enabled': print('not-found'); sys.exit(4)
        if action in ('stop', 'disable'): sys.exit(5)
    if action in ('is-active', 'is-enabled'):
        print(state[units[-1]]['active' if action == 'is-active' else 'enabled'])
    elif action == 'show':
        print('42')
    elif action == 'daemon-reload':
        for unit, values in state.items():
            if (unit.startswith('feetforceplate-')
                    and (root / 'etc/systemd/system' / unit).exists()):
                if values['active'] == 'unknown': values['active'] = 'inactive'
                if values['enabled'] == 'not-found': values['enabled'] = 'disabled'
        save()
    else:
        for unit in units:
            if unit.startswith('--'): continue
            if action in ('start', 'restart', 'stop'):
                state[unit]['active'] = 'inactive' if action == 'stop' else 'active'
                if (action == 'restart' and unit == 'feetforceplate-seed.service'
                        and (root / 'opt/feetforceplate/app').resolve().name != 'old'):
                    (root / 'var/lib/feetforceplate/runtime/venv/version').write_text('new-runtime')
            elif action in ('enable', 'disable'):
                state[unit]['enabled'] = 'enabled' if action == 'enable' else 'disabled'
            save()
            if state.get('failed') and os.environ.get('RECOVERY_FAIL') and action == 'restart':
                sys.exit(11)
            fail(action + ':' + unit)
elif name == 'curl':
    url = args[-1]
    if ':8743/' in url and os.environ.get('FAIL_AT') == 'backend':
        state['failed'] = True; save(); sys.exit(9)
    if ':17443/' in url: fail('preflight')
    if ':7443/' in url: fail('ingress')
elif name == 'nginx': fail('nginx-test')
elif name == 'ss':
    if state['nginx']['active'] == 'active': print('LISTEN nginx pid=42,fd=1')
elif name == 'install':
    filtered = []; i = 0
    while i < len(args):
        if args[i] in ('-o', '-g'): i += 2
        else: filtered.append(args[i]); i += 1
    sys.exit(subprocess.call(['/usr/bin/install', *filtered]))
elif name == 'mv':
    args = ['-f' if a == '-Tf' else a for a in args]
    # GNU mv -T replaces the symlink rather than following its directory target.
    if pathlib.Path(args[-1]).is_symlink(): pathlib.Path(args[-1]).unlink()
    sys.exit(subprocess.call(['/bin/mv', *args]))
elif name == 'readlink': print(pathlib.Path(args[-1]).resolve())
elif name == 'openssl': print('a' * 64)
elif name == 'uv': pass
else: raise RuntimeError((name, args))
'''


def relocated(text: str, root: Path) -> str:
    # Relocate literal host paths, retaining the production shell control flow.
    for prefix in ('/var/lib/', '/opt/feetforceplate', '/etc/', '/proc/'):
        text = text.replace(prefix, str(root) + prefix)
    return text.replace('${EUID}', '0')


def run_install(tmp_path: Path, fault: str, recovery_fail: bool | str = False, *,
                unmanaged: bool = False, absent: bool = False, fresh: bool = False):
    host = tmp_path / 'host'
    host.mkdir()
    for name in FILES:
        path = host / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('old:' + name)
    old = host / 'opt/feetforceplate/releases/old'
    old.mkdir(parents=True)
    (host / 'opt/feetforceplate/app').symlink_to(old)
    runtime = host / 'var/lib/feetforceplate/runtime/venv'
    runtime.mkdir(parents=True)
    (runtime / 'version').write_text('old-runtime')
    (host / 'etc/feetforceplate/seed.env').write_text('')
    proc = host / 'proc/42'
    proc.mkdir(parents=True)
    (proc / 'cmdline').write_text('uvicorn legacy' if unmanaged else 'nginx: master process')
    if absent:
        (host / 'etc/feetforceplate/tls/seed.key').unlink()
        (host / 'opt/feetforceplate/app').unlink()
    units = ('postgresql', 'nginx', 'feetforceplate-seed.service',
             'feetforceplate-backup.service', 'feetforceplate-backup.timer')
    initial = {u: {'active': 'inactive' if 'backup' in u else 'active',
                   'enabled': 'disabled' if 'backup' in u else 'enabled'} for u in units}
    if fresh:
        for unit in units:
            if unit.startswith('feetforceplate-'):
                (host / 'etc/systemd/system' / unit).unlink()
                initial[unit] = {'active': 'unknown', 'enabled': 'not-found'}
    (host / 'state.json').write_text(json.dumps(initial))
    bindir = tmp_path / 'bin'
    bindir.mkdir()
    for command in ('age', 'curl', 'nginx', 'openssl', 'pg_isready', 'psql', 'python3',
                    'runuser', 'systemctl', 'uv', 'chown', 'id', 'sha256sum', 'stat',
                    'install', 'mv', 'readlink', 'sleep', 'journalctl', 'ss'):
        path = bindir / command
        path.write_text(f'#!{sys.executable}\n' + DOUBLE)
        path.chmod(0o755)
    source = tmp_path / 'source'
    shutil.copytree(ROOT / 'deploy', source / 'deploy')
    # Install-layout side effects stay real, apart from the ownership check.
    for path in (source / 'deploy/aliyun/seed').glob('*.sh'):
        text = relocated(path.read_text(), host)
        text = text.replace('find "$release_source" -user root -print -quit', 'printf ""')
        path.write_text(text)
    archive = tmp_path / 'release.tar.gz'
    with tarfile.open(archive, 'w:gz') as tf:
        tf.add(source / 'deploy', arcname='deploy')
    wheel = tmp_path / 'wheel'
    wheel.write_text('fake-wheel')
    env = {**os.environ, 'PATH': str(bindir) + ':' + os.environ['PATH'],
           'FAKE_ROOT': str(host), 'FAIL_AT': fault,
           'WHEEL_SHA': hashlib.sha256(wheel.read_bytes()).hexdigest()}
    if recovery_fail:
        env['RECOVERY_FAIL'] = str(recovery_fail)
    result = subprocess.run(
        ['bash', str(source / 'deploy/aliyun/seed/install-seed-release.sh'),
         str(archive), 'a' * 40, hashlib.sha256(archive.read_bytes()).hexdigest(),
         str(wheel), str(wheel), 'https://example.invalid:7443', 'age1abc', str(wheel)],
        env=env, text=True, capture_output=True, check=False, timeout=30,
    )
    return result, host, initial


@pytest.mark.parametrize('fault', ['migration', 'restart:postgresql', 'backend', 'nginx-test',
                                   'preflight', 'ingress', 'start:feetforceplate-backup.service'])
def test_failed_cutover_restores_files_link_runtime_and_service_state(tmp_path, fault):
    result, host, initial = run_install(tmp_path, fault)
    assert result.returncode != 0, result.stdout
    assert (host / 'migration-applied').read_text() == 'forward-only'
    for name in FILES:
        assert (host / name).read_text() == 'old:' + name, result.stderr
    assert (host / 'opt/feetforceplate/app').resolve().name == 'old'
    assert (host / 'var/lib/feetforceplate/runtime/venv/version').read_text() == 'old-runtime'
    state = json.loads((host / 'state.json').read_text())
    assert {u: state[u] for u in initial} == initial
    assert 'existing 7443 service was not changed' not in result.stderr


def test_recovery_failure_keeps_material_and_reports_manual_action(tmp_path):
    result, host, _ = run_install(tmp_path, 'ingress', recovery_fail=True)
    assert result.returncode != 0
    assert 'manual recovery' in result.stderr.lower()
    assert list((host / 'var/lib/feetforceplate').glob('.seed-recovery.*/files/*'))


def test_existing_nginx_7443_topology_completes(tmp_path):
    result, host, _ = run_install(tmp_path, '')
    assert result.returncode == 0, result.stderr
    assert (host / 'opt/feetforceplate/app').resolve().name == 'a' * 40
    assert 'backup=verified-once' in result.stdout


def test_unmanaged_listener_is_refused_before_database_mutation(tmp_path):
    result, host, initial = run_install(tmp_path, '', unmanaged=True)
    assert result.returncode != 0
    assert not (host / 'migration-applied').exists()
    assert json.loads((host / 'state.json').read_text()) == initial
    assert 'manual cutover' in result.stderr


def test_absent_link_and_tls_key_are_removed_on_recovery(tmp_path):
    result, host, _ = run_install(tmp_path, 'ingress', absent=True)
    assert result.returncode != 0
    assert not (host / 'opt/feetforceplate/app').is_symlink()
    assert not (host / 'etc/feetforceplate/tls/seed.key').exists()


@pytest.mark.parametrize('fault', ['restart:postgresql', 'ingress'])
def test_first_install_missing_units_restore_to_absence(tmp_path, fault):
    result, host, _ = run_install(tmp_path, fault, fresh=True)
    assert (host / 'migration-applied').exists(), result.stderr
    assert result.returncode != 0
    assert 'reversible host state restored' in result.stderr
    assert not list((host / 'etc/systemd/system').glob('feetforceplate-*'))


def test_unknown_installed_consumer_does_not_replace_possibly_live_runtime(tmp_path):
    result, host, _ = run_install(tmp_path, 'ingress', recovery_fail='unknown')
    assert result.returncode != 0
    assert 'manual recovery' in result.stderr.lower()
    assert (host / 'var/lib/feetforceplate/runtime/venv/version').read_text() == 'new-runtime'
    assert (host / 'opt/feetforceplate/app').resolve().name == 'a' * 40
