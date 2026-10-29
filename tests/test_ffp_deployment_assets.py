from __future__ import annotations

import os
from pathlib import Path
import re
import stat
import tempfile
import tomllib

ROOT = Path(__file__).resolve().parents[1] / "deploy/aliyun/seed"


def _read_repository_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_repository_text_reader_uses_utf8() -> None:
    with tempfile.TemporaryDirectory() as directory:
        metadata = Path(directory) / "project.toml"
        expected = 'name = "足底压力"\n'
        metadata.write_text(expected, encoding="utf-8")

        assert _read_repository_text(metadata) == expected


def test_systemd_service_is_unprivileged_hardened_and_loopback_only() -> None:
    text = _read_repository_text(ROOT / "feetforceplate-seed.service")
    for token in (
        "User=feetforceplate", "Group=feetforceplate", "NoNewPrivileges=true",
        "PrivateTmp=true", "ProtectSystem=strict", "ProtectHome=true",
        "ReadWritePaths=/var/lib/feetforceplate/objects",
        "ReadWritePaths=/var/lib/feetforceplate/validation-telemetry",
        "ReadWritePaths=/var/lib/feetforceplate/runtime",
        "FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv",
        "XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache",
        "EnvironmentFile=/etc/feetforceplate/seed.env", "Restart=on-failure",
        "FEETFORCEPLATE_BIND_HOST=127.0.0.1", "FEETFORCEPLATE_BIND_PORT=8743",
    ):
        assert token in text
    assert "User=root" not in text


def test_nginx_7443_ingress_has_tls_limits_rates_and_no_private_static_mapping() -> None:
    text = _read_repository_text(ROOT / "nginx-feetforceplate-seed.conf")
    for token in (
        "listen 7443 ssl", "ssl_protocols TLSv1.2 TLSv1.3",
        "client_max_body_size", "client_header_timeout", "client_body_timeout",
        "proxy_connect_timeout", "proxy_read_timeout", "limit_req_zone",
        "limit_req zone=seed_general", "limit_req zone=seed_auth",
        "X-Request-ID", "proxy_pass http://127.0.0.1:8743", "limit_req_status 429",
    ):
        assert token in text
    assert "Authorization" not in text.split("log_format", 1)[1].split(";", 1)[0]
    assert "/var/lib/feetforceplate/objects" not in text
    assert "/var/lib/feetforceplate/backups" not in text
    assert "alias " not in text and "root " not in text


def test_postgres_roles_are_non_privileged_and_network_is_loopback_only() -> None:
    text = _read_repository_text(ROOT / "postgresql-role-grants.sql")
    for role in ("ffp_seed_tenant", "ffp_seed_activation", "ffp_seed_platform"):
        assert role in text
    assert text.count("NOSUPERUSER") >= 3
    assert text.count("NOBYPASSRLS") >= 3
    assert "listen_addresses = '127.0.0.1,::1'" in text
    assert "0.0.0.0" not in text
    assert text.count("NOBYPASSRLS") >= 3
    assert "ffp_seed_backup" in text and "BYPASSRLS" in text
    assert "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA sales TO ffp_seed_backup;" in text
    assert "SET password_encryption = 'scram-sha-256'" in text


def test_managed_nginx_and_postgres_configs_expose_only_seed_loopback_boundaries() -> None:
    nginx = _read_repository_text(ROOT / "nginx.conf")
    pg_hba = _read_repository_text(ROOT / "pg_hba.conf")
    assert "include /etc/nginx/conf.d/*.conf" in nginx
    assert "listen" not in nginx
    assert "127.0.0.1/32" in pg_hba and "::1/128" in pg_hba
    assert "trust" not in pg_hba
    assert "0.0.0.0" not in pg_hba
    for role in (
        "ffp_seed_tenant", "ffp_seed_activation", "ffp_seed_platform", "ffp_seed_backup",
    ):
        assert role in pg_hba


def test_layout_and_secret_checker_enforce_ownership_without_printing_values() -> None:
    layout = _read_repository_text(ROOT / "install-layout.sh")
    checker = _read_repository_text(ROOT / "check-secrets.sh")
    for path in (
        "/opt/feetforceplate/releases", "/opt/feetforceplate/app",
        "/etc/feetforceplate/seed.env", "/var/lib/feetforceplate/objects",
        "/var/lib/feetforceplate/backups",
        "/var/lib/feetforceplate/validation-telemetry",
        "/var/lib/feetforceplate/runtime",
    ):
        assert path in layout
    assert "-user root" in layout
    assert "must not be root-owned" in layout
    assert "0600" in layout and "0700" in layout
    assert "stat" in checker and "printf" in checker
    assert "source " not in checker and "cat " not in checker
    assert "cut " not in checker and "awk " not in checker


def test_host_prerequisites_are_idempotent_and_do_not_cut_over_7443() -> None:
    text = _read_repository_text(ROOT / "host-prerequisites.sh")
    for token in (
        "dnf install -y nginx postgresql-server postgresql-contrib",
        "/var/lib/pgsql/data/PG_VERSION",
        "postgresql-setup --initdb",
        "systemctl enable --now postgresql",
        "useradd --system --no-create-home",
        "/var/lib/feetforceplate/runtime",
        "/usr/local/bin/age-keygen",
    ):
        assert token in text
    assert "systemctl stop" not in text
    assert "pkill" not in text
    assert "kill " not in text
    assert "nginx-feetforceplate-seed.conf" not in text


def test_oss_configuration_uses_ecs_role_without_long_lived_access_keys() -> None:
    path = ROOT / "configure-oss.sh"
    text = _read_repository_text(path)
    for token in (
        "FEETFORCEPLATE_OBJECT_BACKEND=aliyun-oss",
        "FEETFORCEPLATE_OSS_REGION",
        "FEETFORCEPLATE_OSS_BUCKET",
        "FEETFORCEPLATE_OSS_ENDPOINT",
        "FEETFORCEPLATE_OSS_SERVER_SIDE_ENCRYPTION",
        "FEETFORCEPLATE_OSS_ECS_RAM_ROLE",
        "FEETFORCEPLATE_VALIDATION_TELEMETRY_ROOT",
        "oss_configuration=updated",
        "values=not-printed",
    ):
        assert token in text
    assert "ACCESS_KEY" not in text
    assert "source " not in text
    if os.name != "nt":
        assert path.stat().st_mode & stat.S_IXUSR


def test_backup_metadata_includes_sales_inventory_schema_version() -> None:
    text = _read_repository_text(ROOT / "backup.sh")
    assert "0005_sales_inventory_activation" in text
    assert "0006_inventory_activation_pairing" in text


def test_backup_metadata_names_only_shipped_migrations_and_ends_at_the_ledger() -> None:
    from techflex_cloud_foundation.schema import DEFAULT_PLAN

    text = _read_repository_text(ROOT / "backup.sh")
    listed = next(
        line for line in text.splitlines() if line.startswith("schema_versions=")
    ).split('"')[1].split(",")
    files = [step.filename.removesuffix(".sql") for step in DEFAULT_PLAN if step.filename]
    assert set(listed) <= set(files)
    assert listed[-1] == "0017_schema_migrations"
    assert [name for name in files if name in listed] == listed
    assert "0012_terminal_activation,0013_insole_inventory" in text
    assert "0015_terminal_data_plane_projection,0016_insole_session_archive" in text


def test_sales_inventory_server_bootstrap_reads_release_manifest() -> None:
    text = _read_repository_text(ROOT / "feetforceplate-sales-inventory-server.sh")
    assert 'release_manifest="/home/rui/feetforceplate-sales-inventory-release.env"' in text
    assert 'source "$release_manifest"' in text
    assert 'release_sha="${RELEASE_SHA:?missing RELEASE_SHA}"' in text
    assert 'archive_sha="${ARCHIVE_SHA256:?missing ARCHIVE_SHA256}"' in text
    assert 'archive="${ARCHIVE_PATH:?missing ARCHIVE_PATH}"' in text


def test_remote_release_deploy_stages_a_wrapper_before_tty_sudo() -> None:
    text = _read_repository_text(ROOT / "deploy-sales-inventory-release.sh")
    assert 'remote_wrapper_source="$repo_root/deploy/aliyun/seed/feetforceplate-seed-release-server.sh"' in text
    assert 'remote_wrapper="/home/rui/$(basename "$remote_wrapper_source")"' in text
    assert "ssh -tt" in text
    assert 'scp "$archive" "$foundation_wheel" "$remote_wrapper_source" "$server:/home/rui/"' in text
    assert 'ssh -tt "$server" sudo /bin/bash "$remote_wrapper"' in text
    assert "/bin/bash -s" not in text


def test_remote_release_deploy_ships_the_git_archive_and_checked_wheel() -> None:
    text = _read_repository_text(ROOT / "deploy-sales-inventory-release.sh")
    assert (
        'git -C "$repo_root" archive --format=tar.gz --output="$archive" "$release_sha" '
        "deploy scripts tests"
    ) in text
    assert "deploy/aliyun/seed/runtime/uv.lock" in text
    # RAY-814: the operator downloads and checks the locked wheel, then uploads it.
    assert 'foundation release wheel digest mismatch' in text
    assert "prepare_foundation_artifact" not in text
    assert ".foundation-artifacts" not in text


def test_remote_seed_release_wrapper_is_root_gated_and_validates_the_archive() -> None:
    text = _read_repository_text(ROOT / "feetforceplate-seed-release-server.sh")
    assert '[[ "${EUID}" -ne 0 ]]' in text
    assert 'archive must be located under /home/rui' in text
    assert 'release archive checksum mismatch' in text
    assert 'source /etc/feetforceplate/seed.env' in text
    assert 'install-seed-release.sh' in text
    assert 'secrets=not-printed' in text


def test_systemd_entry_scripts_are_executable() -> None:
    for relative in (
        "deploy/aliyun/seed/run-seed.sh",
        "deploy/aliyun/seed/venv-python.sh",
        "deploy/aliyun/seed/backup.sh",
        "deploy/aliyun/seed/check-secrets.sh",
        "deploy/aliyun/seed/restore-verify.sh",
        "deploy/aliyun/seed/run-restore-drill.sh",
        "deploy/aliyun/seed/run-live-acceptance.sh",
        "deploy/aliyun/seed/configure-oss.sh",
        "deploy/aliyun/seed/resume-seed-cutover.sh",
    ):
        path = ROOT.parents[2] / relative
        if os.name != "nt":
            assert path.stat().st_mode & stat.S_IXUSR


def test_resume_cutover_requires_persistent_readiness_before_stopping_legacy() -> None:
    text = _read_repository_text(ROOT / "resume-seed-cutover.sh")
    assert text.index("http://127.0.0.1:8743/health/ready") < text.index("kill -TERM")
    assert text.index("https://127.0.0.1:17443/health/ready") < text.index("kill -TERM")
    assert "uvicorn cloud.api.integration:app_from_environment" in text
    assert "\"postgres\":\"ready\"" in text
    assert "\"object_store\":\"ready\"" in text
    assert "systemctl start feetforceplate-backup.service" in text


def test_live_acceptance_uses_the_service_owned_uv_runtime() -> None:
    text = _read_repository_text(ROOT / "run-live-acceptance.sh")
    assert text.count("FEETFORCEPLATE_VENV=/var/lib/feetforceplate/runtime/venv") >= 3
    assert text.count("XDG_CACHE_HOME=/var/lib/feetforceplate/runtime/cache") >= 3
    assert "PYTEST_DISABLE_PLUGIN_AUTOLOAD=1" in text
    assert "scripts/verify_aliyun_oss_live.py" in text
    assert "aliyun-oss-summary.json" in text


def test_runtime_project_pins_the_server_extra_and_the_installer_requires_its_lock() -> None:
    project = tomllib.loads((ROOT / "runtime" / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    assert len(dependencies) == 1
    assert re.fullmatch(r"techflex-cloud-foundation\[server\]==\d+\.\d+\.\d+", dependencies[0])
    assert project["tool"]["uv"]["package"] is False
    source = project["tool"]["uv"]["sources"]["techflex-cloud-foundation"]["url"]
    version = dependencies[0].rsplit("==", 1)[1]
    assert source == (
        "https://github.com/RGu0/techflex-cloud-foundation/releases/download/"
        f"v{version}/techflex_cloud_foundation-{version}-py3-none-any.whl"
    )
    text = _read_repository_text(ROOT / "install-seed-release.sh")
    assert 'runtime_project="$release_source/deploy/aliyun/seed/runtime"' in text
    assert 'release has no pinned runtime project' in text
    assert text.index("verify_foundation_release_lock.py") < text.index("run_schema apply")


def test_installer_preflights_before_any_change_and_migrates_through_the_runner() -> None:
    path = ROOT / "install-seed-release.sh"
    text = _read_repository_text(path)
    for token in (
        "sha256sum", "scram-sha-256", "17443", "/health/ready",
        'kill -TERM "$old_pid"', "systemctl start feetforceplate-backup.service",
        "secrets=not-printed", "install_tls_file", "readlink -f",
        "foundation release wheel digest mismatch", "foundation_wheel_source",
    ):
        assert token in text
    assert "curl --fail" not in text
    if os.name != "nt":
        assert path.stat().st_mode & stat.S_IXUSR
    # Nothing is changed until the new runtime resolves offline and the postgres
    # OS user can run the migration runner.
    runtime_ready = text.index("cannot run the migration runtime")
    assert text.index("uv sync --frozen --no-dev") < runtime_ready
    assert runtime_ready < text.index("openssl rand")
    assert runtime_ready < text.index("createdb")
    # The runner replaces the per-file psql sequence.
    assert "cloud/migrations" not in text
    assert "apply_migration " not in text and "apply_migration_if_column_missing" not in text
    assert "python -m techflex_cloud_foundation.schema" not in text.split("run_schema()")[0]
    assert "techflex_cloud_foundation.schema" in text
    # Roles: the runner pauses with exit 3, the role step runs, and it runs once
    # more after the last migration (it grants on tables created by later steps).
    assert "schema_status" in text and "-eq 3" in text
    first_apply = text.index("run_schema apply")
    assert text.index("apply_roles", first_apply) < text.index("run_schema apply", first_apply + 1)
    assert text.count("apply_roles\n") >= 2
    assert '"pending": []' in text
    # The 7443 listener is verified to be the legacy process before it is stopped,
    # and the new stack answered on 8743 and 17443 first.
    assert text.index("http://127.0.0.1:8743/health/ready") < text.index("kill -TERM")
    assert text.index("https://127.0.0.1:17443/health/ready") < text.index("kill -TERM")
    assert text.index("kill -TERM") < text.index("systemctl start nginx", text.index("kill -TERM"))
    assert "uvicorn cloud.api.integration:app_from_environment" in text
    assert '"$release_source/deploy/aliyun/seed/run-restore-drill.sh"' in text
    assert '"$release_source/deploy/aliyun/seed/configure-oss.sh"' in text
    assert '"$release_source/deploy/aliyun/seed/run-seed.sh"' in text


def test_seed_entry_scripts_use_the_pinned_runtime_not_a_source_checkout() -> None:
    for name in (
        "run-seed.sh", "backup.sh", "run-live-acceptance.sh",
        "feetforceplate-sales-inventory-server.sh", "install-seed-release.sh",
    ):
        text = _read_repository_text(ROOT / name)
        assert "local-env.sh" not in text and "./dev" not in text, name
        assert "cloud/api" not in text and "cloud/tests" not in text, name
    run_seed = _read_repository_text(ROOT / "run-seed.sh")
    assert "techflex_cloud_foundation.server.seed" in run_seed
    helper = _read_repository_text(ROOT / "venv-python.sh")
    assert "uv sync --frozen --no-dev" in helper
    assert "UV_PROJECT_ENVIRONMENT" in helper
    assert "deploy/aliyun/seed/runtime" in helper
    service = _read_repository_text(ROOT / "feetforceplate-seed.service")
    assert "ExecStart=/opt/feetforceplate/app/deploy/aliyun/seed/run-seed.sh" in service
    assert "UV_OFFLINE=1" in service
    sales = _read_repository_text(ROOT / "feetforceplate-sales-inventory-server.sh")
    assert "techflex_cloud_foundation.server.access_control.cli" in sales
    acceptance = _read_repository_text(ROOT / "run-live-acceptance.sh")
    assert "tests/test_ffp_postgres_access_repository.py" in acceptance
    assert "FEETFORCEPLATE_ACCEPTANCE=1" in acceptance


def test_insole_archive_schemas_are_registered_by_every_deployed_app() -> None:
    server = ROOT.parents[2] / "src" / "techflex_cloud_foundation" / "server"
    for name in ("seed.py", "integration.py"):
        source = (server / name).read_text(encoding="utf-8")
        assert 'supported_payload_schemas={"raw-segment/1", INSOLE_ARCHIVE_PAYLOAD_SCHEMA}' in source
        assert 'supported_manifest_schemas={"session-manifest/1", INSOLE_MANIFEST_SCHEMA}' in source
