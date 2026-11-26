"""RAY-1030: nginx 5xx scan and DingTalk alert (deploy/aliyun/seed/nginx_5xx_alert.py)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import re
import sys
import urllib.error
import urllib.parse

import pytest

ROOT = Path(__file__).resolve().parents[1] / "deploy/aliyun/seed"
_spec = importlib.util.spec_from_file_location("nginx_5xx_alert", ROOT / "nginx_5xx_alert.py")
assert _spec is not None and _spec.loader is not None
alert = importlib.util.module_from_spec(_spec)
sys.modules["nginx_5xx_alert"] = alert
_spec.loader.exec_module(alert)

WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=tok-SECRET-1234"
SECRET = "SECsigning-secret-5678"
SESSION = "4ed74bd5-6f19-5f39-be61-dce1571d3563"


def line(status: int, path: str = "/v1/sessions", method: str = "POST", when: str = "2026-11-26T14:00:00+08:00") -> str:
    return f'203.0.113.7 [{when}] "{method} {path} HTTP/1.1" {status} 123 request_id=abc123def456\n'


class FakeDingTalk:
    def __init__(self, replies: list[object] | None = None) -> None:
        self.replies = list(replies or [])
        self.calls: list[tuple[str, dict]] = []

    def __call__(self, url: str, body: bytes) -> bytes:
        self.calls.append((url, json.loads(body.decode("utf-8"))))
        reply = self.replies.pop(0) if self.replies else {"errcode": 0, "errmsg": "ok"}
        if isinstance(reply, BaseException):
            raise reply
        return json.dumps(reply).encode("utf-8")

    @property
    def contents(self) -> list[str]:
        return [body["text"]["content"] for _, body in self.calls]


@pytest.fixture()
def env(tmp_path: Path) -> dict[str, str]:
    logs = tmp_path / "logs"
    logs.mkdir()
    return {
        "FFP_ALERT_DINGTALK_WEBHOOK": WEBHOOK,
        "FFP_ALERT_DINGTALK_SECRET": SECRET,
        "FFP_ALERT_LOGS": f"{logs}/seed.access.log:{logs}/production.access.log",
        "STATE_DIRECTORY": str(tmp_path / "state"),
    }


def log_path(env: dict[str, str], index: int = 0) -> Path:
    return Path(env["FFP_ALERT_LOGS"].split(":")[index])


def append(path: Path, *lines: str) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.writelines(lines)


def run(env: dict[str, str], fake: FakeDingTalk, capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, str]:
    code = alert.main(list(argv), environ=env, send=fake)
    captured = capsys.readouterr()
    return code, captured.out + captured.err


# --- parsing and masking ----------------------------------------------------


def test_only_5xx_lines_are_hits_and_query_ip_and_request_id_never_survive() -> None:
    hits = alert.parse_hits([
        line(200), line(404), line(499),
        line(500, f"/v1/sessions/{SESSION}/segments/0", "PUT"),
        line(503), "garbage that is not a log line\n",
    ])
    assert [(h.status, h.method, h.path) for h in hits] == [
        ("500", "PUT", "/v1/sessions/<id>/segments/0"),
        ("503", "POST", "/v1/sessions"),
    ]
    text = alert.build_message("integration", hits, [], "host-a")
    for secret in ("203.0.113.7", "abc123def456", SESSION):
        assert secret not in text


@pytest.mark.parametrize(
    ("path", "masked"),
    [
        (f"/v1/sessions/{SESSION}/segments/12", "/v1/sessions/<id>/segments/12"),
        ("/v1/reports/aGVsbG8td29ybGQtMTIzNDU2", "/v1/reports/<id>"),
        ("/v1/tenants/1234567/accounts", "/v1/tenants/<id>/accounts"),
        ("/v1/platform/tenants", "/v1/platform/tenants"),
        ("/health/ready", "/health/ready"),
        # Route words stay readable, even when 16+ long.
        ("/v1/terminal-diagnostics/upload", "/v1/terminal-diagnostics/upload"),
        ("/v1/access/terminal-refresh", "/v1/access/terminal-refresh"),
        # Token shapes from review: base64 with + or =, matrix params, letter-only
        # tokens, e-mail addresses, numbers inside a segment.
        ("/reset/Ab3dE+fGh7iJkLm9==", "/reset/<id>"),
        ("/x;jsessionid=ABC", "/<id>"),
        ("/invite/AbcDefGhiJklMnoPq", "/invite/<id>"),
        ("/u/alice@example.com", "/u/<id>"),
        ("/v1/orders/ord_12345678", "/v1/orders/<id>"),
    ],
)
def test_identifier_segments_are_masked(path: str, masked: str) -> None:
    assert alert.mask_path(path) == masked


def test_message_groups_counts_and_caps_the_list() -> None:
    hits = [alert.Hit(f"2026-11-26T14:0{i % 10}:00+08:00", "500", "GET", f"/p{i}") for i in range(20)]
    hits += [alert.Hit("2026-11-26T14:09:30+08:00", "500", "GET", "/p0")] * 3
    text = alert.build_message("integration", hits, ["note-x"], "host-a")
    assert "5xx 总数: 23" in text
    assert "- 500 GET /p0 × 4" in text
    assert "其余 5 组，共 5 次" in text
    assert "2026-11-26T14:00:00+08:00 ~ 2026-11-26T14:09:30+08:00" in text
    assert "注意: note-x" in text


# --- runs, cursors, rotation ------------------------------------------------


def test_first_run_records_the_end_without_alerting_on_history(env, capsys) -> None:
    append(log_path(env), line(500), line(502))
    fake = FakeDingTalk()
    assert run(env, fake, capsys)[0] == 0
    assert fake.calls == []
    # Only lines written after the first run count.
    append(log_path(env), line(200))
    assert run(env, fake, capsys)[0] == 0
    assert fake.calls == []


def test_any_new_5xx_sends_exactly_one_message_and_each_line_is_processed_once(env, capsys) -> None:
    fake = FakeDingTalk()
    log_path(env).touch()
    log_path(env, 1).touch()
    run(env, fake, capsys)  # baseline
    append(log_path(env), line(200), line(500, f"/v1/sessions/{SESSION}/segments/0", "PUT"))
    append(log_path(env, 1), line(502))
    code, output = run(env, fake, capsys)
    assert code == 0 and len(fake.calls) == 1
    assert "5xx 总数: 2" in fake.contents[0]
    assert "- 500 PUT /v1/sessions/<id>/segments/0 × 1" in fake.contents[0]
    assert "hits=2 alerted=yes" in output
    run(env, fake, capsys)
    assert len(fake.calls) == 1  # nothing new, nothing resent


def test_a_partial_trailing_line_waits_for_its_newline(env, capsys) -> None:
    fake = FakeDingTalk()
    log_path(env).touch()
    run(env, fake, capsys)
    partial = line(500)
    with log_path(env).open("a", encoding="utf-8") as handle:
        handle.write(partial[:30])
    run(env, fake, capsys)
    assert fake.calls == []
    with log_path(env).open("a", encoding="utf-8") as handle:
        handle.write(partial[30:])
    run(env, fake, capsys)
    assert len(fake.calls) == 1


def test_rotation_reads_the_rest_of_the_moved_file_then_the_new_one(env, capsys) -> None:
    fake = FakeDingTalk()
    log = log_path(env)
    append(log, line(200))
    run(env, fake, capsys)
    append(log, line(500, "/before-rotation"))
    os.rename(log, f"{log}-20261126")  # dateext + delaycompress: newest rotated file stays plain
    append(log, line(504, "/after-rotation"))
    run(env, fake, capsys)
    assert len(fake.calls) == 1
    assert "/before-rotation" in fake.contents[0] and "/after-rotation" in fake.contents[0]
    run(env, fake, capsys)
    assert len(fake.calls) == 1


def test_rotation_into_an_already_compressed_file_is_reported_not_silent(env, capsys) -> None:
    fake = FakeDingTalk()
    log = log_path(env)
    append(log, line(200))
    run(env, fake, capsys)
    os.rename(log, f"{log}-20261126.zst")
    append(log, line(500))
    run(env, fake, capsys)
    assert "lines may be missed" in fake.contents[0]


def test_truncation_restarts_from_the_beginning(env, capsys) -> None:
    fake = FakeDingTalk()
    log = log_path(env)
    append(log, line(200), line(200), line(200))
    run(env, fake, capsys)
    log.write_text(line(500), encoding="utf-8")
    run(env, fake, capsys)
    assert len(fake.calls) == 1 and "truncated" in fake.contents[0]


# --- delivery failure and retry ----------------------------------------------


@pytest.mark.parametrize(
    "failure",
    [
        {"errcode": 310000, "errmsg": "sign not match"},
        urllib.error.URLError(OSError("network down")),
        urllib.error.HTTPError(WEBHOOK, 502, "bad gateway", hdrs=None, fp=None),
    ],
)
def test_failed_delivery_keeps_the_cursor_and_the_next_run_retries(env, capsys, failure) -> None:
    fake = FakeDingTalk([failure])
    log_path(env).touch()
    run(env, fake, capsys)
    append(log_path(env), line(500))
    code, output = run(env, fake, capsys)
    assert code == 1 and "cursors not advanced" in output
    code, _ = run(env, fake, capsys)
    assert code == 0 and len(fake.calls) == 2
    assert fake.contents[0] == fake.contents[1]


def test_any_sender_exception_is_a_delivery_failure_without_the_url(env, capsys) -> None:
    # e.g. http.client.InvalidURL is a ValueError whose message holds the request path.
    fake = FakeDingTalk([ValueError(f"URL can't contain control characters. {WEBHOOK}")])
    log_path(env).touch()
    run(env, fake, capsys)
    append(log_path(env), line(500))
    code, output = run(env, fake, capsys)
    assert code == 1 and "DingTalk request failed (ValueError)" in output
    assert "tok-SECRET-1234" not in output and "Traceback" not in output


def test_a_rotated_file_bigger_than_the_read_cap_is_reported(env, capsys, monkeypatch) -> None:
    fake = FakeDingTalk()
    log = log_path(env)
    append(log, line(200))
    run(env, fake, capsys)
    monkeypatch.setattr(alert, "MAX_READ_BYTES", 300)
    append(log, *[line(500, f"/r{i}") for i in range(10)])
    os.rename(log, f"{log}-20261126")
    append(log, line(200))
    run(env, fake, capsys)
    assert "unread bytes; lines may be missed" in fake.contents[0]


def test_cursor_identifies_the_file_by_device_and_inode(env, capsys) -> None:
    log_path(env).touch()
    run(env, FakeDingTalk(), capsys)
    [cursor_file] = Path(env["STATE_DIRECTORY"]).glob("cursor-*.json")
    cursor = json.loads(cursor_file.read_text(encoding="utf-8"))
    stat = os.stat(log_path(env))
    assert (cursor["device"], cursor["inode"]) == (stat.st_dev, stat.st_ino)


def test_secrets_never_appear_in_any_output(env, capsys) -> None:
    fake = FakeDingTalk([urllib.error.URLError(OSError(WEBHOOK + " " + SECRET))])
    log_path(env).touch()
    outputs = [run(env, fake, capsys)[1]]
    append(log_path(env), line(500))
    outputs.append(run(env, fake, capsys)[1])
    outputs.append(run(env, fake, capsys)[1])
    outputs.append(run(env, fake, capsys, "--test-message")[1])
    joined = "\n".join(outputs + fake.contents)
    assert SECRET not in joined and "tok-SECRET-1234" not in joined


# --- signing, configuration, test message ----------------------------------


def test_signature_follows_the_dingtalk_scheme() -> None:
    url = alert.signed_url(WEBHOOK, SECRET, 1700000000000)
    query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)
    expected = base64.b64encode(
        hmac.new(SECRET.encode(), f"1700000000000\n{SECRET}".encode(), hashlib.sha256).digest()
    ).decode()
    assert query["timestamp"] == ["1700000000000"]
    assert query["sign"] == [expected]
    assert query["access_token"] == ["tok-SECRET-1234"]


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"FFP_ALERT_DINGTALK_WEBHOOK": ""}, "WEBHOOK is not set"),
        ({"FFP_ALERT_DINGTALK_SECRET": ""}, "SECRET is not set"),
        ({"FFP_ALERT_DINGTALK_WEBHOOK": "http://oapi.dingtalk.com/robot/send?access_token=x"}, "https"),
        ({"FFP_ALERT_DINGTALK_WEBHOOK": "https://oapi.dingtalk.com/robot/send"}, "access_token"),
        # systemd EnvironmentFile keeps trailing text; reject it before urllib sees it.
        ({"FFP_ALERT_DINGTALK_WEBHOOK": WEBHOOK + "  # group X"}, "whitespace"),
        ({"FFP_ALERT_DINGTALK_SECRET": SECRET + " # x"}, "whitespace"),
    ],
)
def test_missing_or_invalid_configuration_fails_loudly(env, capsys, change, reason) -> None:
    fake = FakeDingTalk()
    code, output = run({**env, **change}, fake, capsys)
    assert code == 2 and "not configured" in output and reason in output
    assert fake.calls == []
    assert not Path(env["STATE_DIRECTORY"]).exists()


def test_test_message_is_sent_without_touching_cursors(env, capsys) -> None:
    fake = FakeDingTalk()
    append(log_path(env), line(500))
    code, output = run(env, fake, capsys, "--test-message")
    assert code == 0 and "test message delivered" in output
    assert len(fake.calls) == 1 and "测试消息" in fake.contents[0]
    assert not Path(env["STATE_DIRECTORY"]).exists()


# --- shipped assets ------------------------------------------------------------


def _settings(text: str) -> dict[str, list[str]]:
    settings: dict[str, list[str]] = {}
    for raw in text.splitlines():
        if "=" in raw and not raw.lstrip().startswith("#"):
            key, value = raw.split("=", 1)
            settings.setdefault(key.strip(), []).append(value.strip())
    return settings


def test_timer_fires_every_five_minutes_for_the_alert_service() -> None:
    timer = _settings((ROOT / "feetforceplate-5xx-alert.timer").read_text(encoding="utf-8"))
    assert timer["OnCalendar"] == ["*:0/5"]
    assert timer["Unit"] == ["feetforceplate-5xx-alert.service"]
    assert timer["WantedBy"] == ["timers.target"]


def test_service_uses_system_python_requires_its_env_file_and_drops_capabilities() -> None:
    service = _settings((ROOT / "feetforceplate-5xx-alert.service").read_text(encoding="utf-8"))
    assert service["ExecStart"] == [
        "/usr/bin/python3 /opt/feetforceplate/app/deploy/aliyun/seed/nginx_5xx_alert.py"
    ]
    # No leading "-": a missing configuration file fails the unit.
    assert service["EnvironmentFile"] == ["/etc/feetforceplate/alert.env"]
    assert service["CapabilityBoundingSet"] == [""]
    assert service["ProtectSystem"] == ["strict"]
    assert service["NoNewPrivileges"] == ["true"]
    assert service["StateDirectory"] == ["feetforceplate-alert"]
    text = (ROOT / "feetforceplate-5xx-alert.service").read_text(encoding="utf-8")
    assert "venv" not in text.replace("never the shared service venv", "")


def test_script_uses_only_the_standard_library() -> None:
    source = (ROOT / "nginx_5xx_alert.py").read_text(encoding="utf-8")
    imported = set(re.findall(r"^(?:from|import) (\w+)", source, re.MULTILINE))
    assert imported <= set(sys.stdlib_module_names) | {"__future__"}


def test_installer_installs_enables_and_starts_the_alert_timer() -> None:
    text = (ROOT / "install-seed-release.sh").read_text(encoding="utf-8")
    for unit in ("feetforceplate-5xx-alert.service", "feetforceplate-5xx-alert.timer"):
        assert (
            f'install -o root -g root -m 0644 "$release_target/deploy/aliyun/seed/{unit}" \\\n'
            f"    /etc/systemd/system/{unit}"
        ) in text
        assert text.index(f"/etc/systemd/system/{unit}") < text.index("systemctl daemon-reload")
    enable = text[text.index("systemctl enable "):text.index("systemctl restart feetforceplate-seed")]
    assert "feetforceplate-5xx-alert.timer" in enable
    assert "feetforceplate-5xx-alert.service" not in enable
    assert text.index("systemctl start feetforceplate-5xx-alert.timer") > text.index(
        "curl -kfsS https://127.0.0.1:7443/health/ready"
    )
    assert "alert_5xx=timer-enabled" in text and "secrets=not-printed" in text


def test_installer_recovery_snapshots_the_alert_units() -> None:
    text = (ROOT / "installer-recovery.sh").read_text(encoding="utf-8")
    for unit in ("feetforceplate-5xx-alert.service", "feetforceplate-5xx-alert.timer"):
        assert f"/etc/systemd/system/{unit}" in text
        assert unit in text[text.index("recovery_units=("):text.index("prepare_recovery()")]


def test_nginx_log_retention_is_not_changed_by_this_scope() -> None:
    shipped = {path.name for path in ROOT.iterdir()}
    assert not any("logrotate" in name for name in shipped)
