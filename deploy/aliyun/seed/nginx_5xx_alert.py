#!/usr/bin/python3
"""Alert a DingTalk group when nginx served any 5xx since the last run (RAY-1030).

Runs from ``feetforceplate-5xx-alert.timer`` every five minutes with the host's
system Python and the standard library only, so it never touches the shared
service venv. For each configured access log it keeps a cursor (inode and byte
offset) under the state directory and reads only the lines appended since the
previous run, following a logrotate rotation into the rotated file. Any line
with a 5xx status produces exactly one message for the run, listing counts per
status, method and path. Paths have IDs masked; client addresses, request IDs
and query strings never leave the host (nginx logs ``$uri``, which carries no
query string).

The cursors are saved only after the message was accepted, so a failed delivery
is retried on the next run and the unit exits non-zero, visible in the journal.
The first run for a log records its current end without alerting on history.

Configuration comes from the environment (``/etc/feetforceplate/alert.env``,
root-only, written by the operator):

* ``FFP_ALERT_DINGTALK_WEBHOOK``: the robot URL including ``access_token``.
* ``FFP_ALERT_DINGTALK_SECRET``: the robot's signing secret (``SEC...``).
* ``FFP_ALERT_LABEL`` (optional): environment name shown in the message.
* ``FFP_ALERT_LOGS`` (optional): ``:``-separated access log paths.

Neither the webhook nor the secret is ever printed. ``--test-message`` sends a
fixed message and leaves the cursors untouched.
"""

from __future__ import annotations

import argparse
import base64
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
import glob
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_LOGS = (
    "/var/log/nginx/feetforceplate-seed.access.log",
    "/var/log/nginx/feetforceplate-production.access.log",
)
DEFAULT_LABEL = "integration"
MAX_GROUPS = 15
MAX_PATH = 160
MAX_READ_BYTES = 64 * 1024 * 1024
_COMPRESSED = (".gz", ".zst", ".xz", ".bz2", ".lz4")

# log_format: '$remote_addr [$time_iso8601] "$request_method $uri $server_protocol" '
#             '$status $body_bytes_sent request_id=$request_id'
_LINE = re.compile(
    r'^\S+ \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<path>.*) (?P<protocol>\S+)" '
    r"(?P<status>\d{3}) (?:\d+|-)(?: .*)?$"
)
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_TOKEN = re.compile(r"^(?=[A-Za-z0-9_.~-]*\d)[A-Za-z0-9_.~-]{16,}$")
_NUMBER = re.compile(r"^\d{6,}$")
_UNPRINTABLE = re.compile(r"[^\x21-\x7e]")


class ConfigurationError(Exception):
    """The alert is not configured; the unit must fail rather than skip."""


class DeliveryError(Exception):
    """DingTalk did not accept the message."""


@dataclass(frozen=True)
class Config:
    webhook: str
    secret: str
    label: str
    logs: tuple[str, ...]
    state_dir: Path


@dataclass(frozen=True)
class Hit:
    time: str
    status: str
    method: str
    path: str


def load_config(environ: dict[str, str] | os._Environ[str]) -> Config:
    webhook = environ.get("FFP_ALERT_DINGTALK_WEBHOOK", "").strip()
    secret = environ.get("FFP_ALERT_DINGTALK_SECRET", "").strip()
    if not webhook:
        raise ConfigurationError("FFP_ALERT_DINGTALK_WEBHOOK is not set")
    if not secret:
        raise ConfigurationError("FFP_ALERT_DINGTALK_SECRET is not set")
    parsed = urllib.parse.urlsplit(webhook)
    if parsed.scheme != "https" or not parsed.netloc:
        raise ConfigurationError("FFP_ALERT_DINGTALK_WEBHOOK must be an https URL")
    if "access_token=" not in parsed.query:
        raise ConfigurationError("FFP_ALERT_DINGTALK_WEBHOOK has no access_token")
    logs = tuple(p for p in environ.get("FFP_ALERT_LOGS", "").split(":") if p) or DEFAULT_LOGS
    state = environ.get("STATE_DIRECTORY", "").split(":")[0] or "/var/lib/feetforceplate-alert"
    label = _clean(environ.get("FFP_ALERT_LABEL", "").strip(), 40) or DEFAULT_LABEL
    return Config(webhook, secret, label, logs, Path(state))


def _clean(text: str, limit: int) -> str:
    text = _UNPRINTABLE.sub("?", text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def mask_path(path: str) -> str:
    """Replace identifier-like segments with ``<id>``."""
    parts = []
    for segment in path.split("/"):
        if _UUID.match(segment) or _TOKEN.match(segment) or _NUMBER.match(segment):
            parts.append("<id>")
        else:
            parts.append(segment)
    return _clean("/".join(parts), MAX_PATH)


def parse_hits(lines: Iterable[str]) -> list[Hit]:
    hits = []
    for line in lines:
        match = _LINE.match(line.rstrip("\n"))
        if match is None or not match["status"].startswith("5"):
            continue
        hits.append(
            Hit(
                time=_clean(match["time"], 40),
                status=match["status"],
                method=_clean(match["method"], 12),
                path=mask_path(match["path"]),
            )
        )
    return hits


# --- cursors -----------------------------------------------------------------


def _state_file(state_dir: Path, log: str) -> Path:
    digest = hashlib.sha256(log.encode("utf-8")).hexdigest()[:16]
    return state_dir / f"cursor-{digest}.json"


def _load_cursor(state_dir: Path, log: str) -> dict[str, int] | None:
    try:
        data = json.loads(_state_file(state_dir, log).read_text(encoding="utf-8"))
        return {"inode": int(data["inode"]), "offset": int(data["offset"])}
    except FileNotFoundError:
        return None
    except (ValueError, KeyError, TypeError):
        # A corrupt cursor is treated as a first run: no history alert, no crash.
        return None


def _save_cursor(state_dir: Path, log: str, cursor: dict[str, int]) -> None:
    state_dir.mkdir(parents=True, exist_ok=True)
    target = _state_file(state_dir, log)
    descriptor, tmp = tempfile.mkstemp(dir=state_dir, prefix=".cursor-")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump({"log": log, **cursor}, handle)
        os.replace(tmp, target)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _read_complete_lines(path: str, offset: int) -> tuple[list[str], int]:
    """Read whole lines from ``offset``; a trailing partial line is left for later."""
    with open(path, "rb") as handle:
        handle.seek(offset)
        data = handle.read(MAX_READ_BYTES)
    end = data.rfind(b"\n")
    if end < 0:
        return [], offset
    chunk = data[: end + 1]
    return chunk.decode("utf-8", errors="replace").splitlines(), offset + len(chunk)


def _find_rotated(log: str, inode: int) -> str | None:
    for candidate in sorted(glob.glob(glob.escape(log) + "-*") + glob.glob(glob.escape(log) + ".*")):
        if candidate.endswith(_COMPRESSED):
            continue
        try:
            if os.stat(candidate).st_ino == inode:
                return candidate
        except OSError:
            continue
    return None


@dataclass
class LogScan:
    log: str
    lines: list[str]
    cursor: dict[str, int] | None
    notes: list[str]


def scan_log(state_dir: Path, log: str) -> LogScan:
    try:
        current = os.stat(log)
    except FileNotFoundError:
        return LogScan(log, [], None, [])
    previous = _load_cursor(state_dir, log)
    if previous is None:
        # First run: start at the current end, never alert on history.
        return LogScan(log, [], {"inode": current.st_ino, "offset": current.st_size}, [])
    lines: list[str] = []
    notes: list[str] = []
    if previous["inode"] == current.st_ino:
        offset = previous["offset"] if previous["offset"] <= current.st_size else 0
        if previous["offset"] > current.st_size:
            notes.append(f"{Path(log).name} was truncated; read from the start")
        new_lines, new_offset = _read_complete_lines(log, offset)
        return LogScan(log, new_lines, {"inode": current.st_ino, "offset": new_offset}, notes)
    rotated = _find_rotated(log, previous["inode"])
    if rotated is not None:
        rest, _ = _read_complete_lines(rotated, previous["offset"])
        lines.extend(rest)
    else:
        notes.append(f"{Path(log).name} rotated and the previous file is already compressed; lines may be missed")
    new_lines, new_offset = _read_complete_lines(log, 0)
    lines.extend(new_lines)
    return LogScan(log, lines, {"inode": current.st_ino, "offset": new_offset}, notes)


# --- message and delivery ----------------------------------------------------


def build_message(label: str, hits: list[Hit], notes: list[str], hostname: str) -> str:
    groups = Counter((hit.status, hit.method, hit.path) for hit in hits)
    times = sorted(hit.time for hit in hits)
    lines = [
        f"[FeetForcePlate {label}] 服务端 5xx 告警",
        f"主机: {_clean(hostname, 64)}",
        f"时间: {times[0]} ~ {times[-1]}",
        f"5xx 总数: {len(hits)}",
        "明细（状态 方法 路径 × 次数）:",
    ]
    for (status, method, path), count in groups.most_common(MAX_GROUPS):
        lines.append(f"- {status} {method} {path} × {count}")
    if len(groups) > MAX_GROUPS:
        rest = sum(count for _, count in groups.most_common()[MAX_GROUPS:])
        lines.append(f"- 其余 {len(groups) - MAX_GROUPS} 组，共 {rest} 次")
    lines.extend(f"注意: {note}" for note in notes)
    lines.append("排查: journalctl -u feetforceplate-seed.service --since <时间>")
    return "\n".join(lines)


def signed_url(webhook: str, secret: str, now_ms: int) -> str:
    string_to_sign = f"{now_ms}\n{secret}".encode()
    digest = hmac.new(secret.encode("utf-8"), string_to_sign, hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(digest))
    return f"{webhook}&timestamp={now_ms}&sign={sign}"


Sender = Callable[[str, bytes], bytes]


def _urllib_send(url: str, body: bytes) -> bytes:
    request = urllib.request.Request(
        url, data=body, method="POST", headers={"Content-Type": "application/json; charset=utf-8"}
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # noqa: S310 - https enforced in config
        return response.read(65536)


def deliver(config: Config, content: str, *, send: Sender = _urllib_send, now_ms: int | None = None) -> None:
    body = json.dumps({"msgtype": "text", "text": {"content": content}}, ensure_ascii=False).encode()
    url = signed_url(config.webhook, config.secret, now_ms if now_ms is not None else int(time.time() * 1000))
    try:
        raw = send(url, body)
    except urllib.error.HTTPError as exc:
        raise DeliveryError(f"DingTalk HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        reason = getattr(exc, "reason", exc)
        raise DeliveryError(f"DingTalk unreachable ({type(reason).__name__})") from None
    try:
        reply = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise DeliveryError("DingTalk returned a non-JSON reply") from None
    if not isinstance(reply, dict) or reply.get("errcode") != 0:
        code = reply.get("errcode") if isinstance(reply, dict) else None
        raise DeliveryError(f"DingTalk rejected the message (errcode={code})")


# --- entry point -------------------------------------------------------------


def run(config: Config, *, send: Sender = _urllib_send, hostname: str | None = None) -> int:
    scans = [scan_log(config.state_dir, log) for log in config.logs]
    hits = [hit for scan in scans for hit in parse_hits(scan.lines)]
    notes = [note for scan in scans for note in scan.notes]
    if hits:
        deliver(config, build_message(config.label, hits, notes, hostname or socket.gethostname()), send=send)
    elif notes:
        print("; ".join(notes))
    for scan in scans:
        if scan.cursor is not None:
            _save_cursor(config.state_dir, scan.log, scan.cursor)
    lines = sum(len(scan.lines) for scan in scans)
    print(f"nginx_5xx_alert: lines={lines} hits={len(hits)} alerted={'yes' if hits else 'no'}")
    return 0


def main(argv: list[str] | None = None, environ: dict[str, str] | None = None, send: Sender = _urllib_send) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--test-message", action="store_true", help="send a fixed test message; cursors untouched")
    args = parser.parse_args(argv)
    try:
        config = load_config(environ if environ is not None else os.environ)
        if args.test_message:
            deliver(
                config,
                f"[FeetForcePlate {config.label}] 5xx 告警测试消息（RAY-1030），主机 {_clean(socket.gethostname(), 64)}",
                send=send,
            )
            print("nginx_5xx_alert: test message delivered")
            return 0
        return run(config, send=send)
    except ConfigurationError as exc:
        print(f"nginx_5xx_alert: not configured: {exc}", file=sys.stderr)
        return 2
    except DeliveryError as exc:
        print(f"nginx_5xx_alert: delivery failed, cursors not advanced: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
