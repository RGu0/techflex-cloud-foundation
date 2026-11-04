#!/usr/bin/env python3
"""RAY-802 real-TLS smoke of the terminal diagnostic package routes (RAY-927 R1).

Run it from a workstation against the integration endpoint. It asks for three
passwords with getpass (the test institution, a ``PLATFORM_SUPPORT`` identity
and a ``PLATFORM_OWNER`` identity) and writes redacted JSON: no password,
token, login or account name, tenant identifier or planted identity value
reaches the output. Packages are recorded by ``diagnostic_id`` and digest only.

One synthetic terminal is activated, so the run needs one free seat. With its
token it exercises ``POST /v1/diagnostics``:

* a synthetic ``gait-insole-diagnostics/1`` package is 201, and a replay of the
  same key and body is 200 with the identical body;
* the same key with another body (another digest) is 409 ``E-API-409``;
* a package with a planted synthetic mobile number is 422
  ``E-DIA-422-CONTENT-REJECTED`` with ``details.reason`` ``identity_detected``.

Then, on ``/v1/platform/tenants/{tenant_id}/diagnostics``:

* the ``PLATFORM_SUPPORT`` identity lists the package and reads its content
  with a ``ticket_reference``; the content must equal the uploaded bytes;
* the ``PLATFORM_OWNER`` identity and the terminal token are 403 ``E-PLT-403``.

Every list, read and denial is audited server side under the run's
``ticket_reference`` (recorded in the output); the runbook checks the audit
rows on the host. The run then revokes its terminal. The accepted package stays
behind until the 30-day purge; it holds only synthetic text labelled
``ray802-smoke``. When a step fails, the terminal is still revoked.

Run it from the repository root with the pinned runtime (``python -m
scripts.run_ray802_diagnostics_smoke ...``): it imports ``scripts`` and the
installed ``techflex_cloud_foundation`` contracts.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import getpass
import hashlib
from http.client import HTTPException
import json
from pathlib import Path
import secrets
import string
import sys
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import Request

from scripts.run_ray785_route_smoke import (
    Client as _JsonClient,
)
from scripts.run_ray785_route_smoke import (
    Recorder,
    SmokeFailure,
    _activate,
    _git_head,
    _now,
)
from scripts.run_ray815_data_plane_smoke import _cleanup
from techflex_cloud_foundation.contracts.access_control import PlatformLoginResponse, PlatformRole
from techflex_cloud_foundation.contracts.terminal_access import TerminalSummary
from techflex_cloud_foundation.contracts.terminal_diagnostics import (
    DIAGNOSTICS_FORMAT,
    DIAGNOSTICS_MEDIA_TYPE,
    DiagnosticListResponse,
    DiagnosticUploadResponse,
)

SCHEMA_VERSION = "ray802-diagnostics-smoke/1"
LABEL = "ray802-smoke"
SUPPORT_ROLES = {PlatformRole.SUPPORT, PlatformRole.ENGINEER}


class Client(_JsonClient):
    def fetch(
        self, path: str, *, token: str
    ) -> tuple[int, dict[str, str], bytes]:
        """GET a non-JSON body (the package content) with its headers."""
        request = Request(self._base_url + path, method="GET")
        request.add_header("Authorization", f"Bearer {token}")
        try:
            with self._opener.open(request, timeout=30) as response:
                return response.status, {k.lower(): v for k, v in response.headers.items()}, \
                    response.read()
        except HTTPError as error:
            return error.code, {k.lower(): v for k, v in error.headers.items()}, error.read()


def _nonce() -> str:
    # Letters only: a digit run could look like a phone number to the screen.
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(12))


def _package(tenant_id: str, terminal_id: str, *messages: str) -> bytes:
    exported_at = datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    lines: list[dict[str, Any]] = [{
        "kind": "header", "exported_at": exported_at, "app_version": LABEL,
        "cloud_environment": "integration", "platform": "android", "os_version": LABEL,
        "terminal_id": terminal_id, "tenant_id": tenant_id, "format": DIAGNOSTICS_FORMAT,
        "dropped_lines": 0,
    }]
    lines += [
        {"kind": "log", "t": exported_at, "level": "info", "cat": "smoke", "msg": message,
         "fields": {"label": LABEL}}
        for message in messages
    ]
    return "".join(
        json.dumps(line, ensure_ascii=False, separators=(",", ":")) + "\n" for line in lines
    ).encode("utf-8")


def _upload(client: Client, token: str, key: str, body: bytes) -> tuple[int, dict[str, Any]]:
    return client.call(
        "POST", "/v1/diagnostics", token=token, content=body,
        headers={
            "Content-Type": DIAGNOSTICS_MEDIA_TYPE,
            "Idempotency-Key": key,
            "X-Content-SHA256": hashlib.sha256(body).hexdigest(),
        },
    )


def _login(
    client: Client, recorder: Recorder, name: str, login_name: str, password: str
) -> PlatformLoginResponse:
    login = recorder.expect(
        name,
        client.call("POST", "/v1/platform/login",
                    body={"login_name": login_name, "password": password}),
        status={200},
        model=PlatformLoginResponse,
    )
    recorder.note(roles=sorted(role.value for role in login.roles))
    return login


def _require(recorder: Recorder, name: str, ok: bool, **fields: Any) -> None:
    recorder.note(**fields)
    if not ok:
        recorder.note(passed=False)
        raise SmokeFailure(name)


def run(
    args: argparse.Namespace, password: str, support_password: str, owner_password: str
) -> dict[str, Any]:
    client = Client(args.base_url, args.ca_file)
    recorder = Recorder()
    state: dict[str, Any] = {}
    run_tag = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    ticket = f"{LABEL}-{run_tag}"
    # Synthetic mobile number, never a real person's; it must not reach the evidence.
    planted = "139" + "".join(secrets.choice(string.digits) for _ in range(8))
    sensitive = [
        password, support_password, owner_password, args.account_name,
        args.support_login, args.owner_login, planted,
    ]
    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "started_at": _now(),
        "endpoint": args.base_url,
        "account_name_sha256": hashlib.sha256(args.account_name.encode()).hexdigest(),
        "support_login_sha256": hashlib.sha256(args.support_login.encode()).hexdigest(),
        "owner_login_sha256": hashlib.sha256(args.owner_login.encode()).hexdigest(),
        "ca_file_sha256": hashlib.sha256(Path(args.ca_file).read_bytes()).hexdigest(),
        "script_commit": _git_head(),
        "ticket_reference": ticket,
        "secrets_included": False,
        "steps": recorder.steps,
    }
    try:
        recorder.expect("readiness", client.call("GET", "/health/ready"), status={200})
        terminal = _activate(
            client, recorder, "terminal_activate", args.account_name, password,
            f"{LABEL}-{run_tag}",
        )
        token = terminal.access_token
        tenant_id = str(terminal.tenant_id)
        installation_id = str(terminal.client_installation_id)
        state.update(token=token, installation_id=installation_id)
        sensitive += [token, terminal.refresh_token, tenant_id]

        key = f"{LABEL}-{_nonce()}"
        body = _package(tenant_id, installation_id, f"{LABEL} synthetic package {_nonce()}")
        digest = hashlib.sha256(body).hexdigest()
        created = recorder.expect(
            "diagnostic_upload", _upload(client, token, key, body),
            status={201}, model=DiagnosticUploadResponse,
        )
        _require(
            recorder, "diagnostic_upload",
            created.sha256 == digest and created.size_bytes == len(body)
            and created.format == DIAGNOSTICS_FORMAT,
            diagnostic_id=str(created.diagnostic_id), sha256=created.sha256,
            size_bytes=created.size_bytes,
            retention_days=(created.expires_at - created.received_at).days,
        )

        replayed = recorder.expect(
            "diagnostic_upload_replay", _upload(client, token, key, body),
            status={200}, model=DiagnosticUploadResponse,
        )
        _require(recorder, "diagnostic_upload_replay", replayed == created,
                 identical=replayed == created)

        other = _package(tenant_id, installation_id, f"{LABEL} other package {_nonce()}")
        recorder.expect(
            "diagnostic_upload_key_reused", _upload(client, token, key, other),
            status={409}, error_code="E-API-409",
        )

        status, rejected = _upload(
            client, token, f"{LABEL}-{_nonce()}",
            _package(tenant_id, installation_id, f"{LABEL} call {planted} back"),
        )
        recorder.expect(
            "diagnostic_upload_identity_planted", (status, rejected),
            status={422}, error_code="E-DIA-422-CONTENT-REJECTED",
        )
        details = (rejected.get("error") or {}).get("details") or {}
        _require(
            recorder, "diagnostic_upload_identity_planted",
            details == {"line": 2, "reason": "identity_detected"},
            reason=details.get("reason"), line=details.get("line"),
        )

        support = _login(
            client, recorder, "support_login", args.support_login, support_password)
        sensitive += [support.access_token, support.refresh_token]
        _require(recorder, "support_login", PlatformRole.SUPPORT in support.roles)

        list_path = f"/v1/platform/tenants/{tenant_id}/diagnostics"
        query = urlencode({"ticket_reference": ticket})
        listed = recorder.expect(
            "support_list",
            client.call("GET", f"{list_path}?{query}", token=support.access_token),
            status={200}, model=DiagnosticListResponse,
        )
        row = next((item for item in listed.items
                    if item.diagnostic_id == created.diagnostic_id), None)
        _require(
            recorder, "support_list",
            row is not None and row.sha256 == digest and row.deleted_at is None
            and str(row.client_installation_id) == installation_id,
            found=row is not None, items=len(listed.items),
        )

        status, headers, content = client.fetch(
            f"{list_path}/{created.diagnostic_id}/content?{query}", token=support.access_token)
        recorder.steps.append({"step": "support_read", "status": status, "passed": status == 200})
        _require(
            recorder, "support_read",
            status == 200 and content == body
            and headers.get("x-content-sha256") == digest
            and headers.get("cache-control") == "no-store"
            and (headers.get("content-type") or "").startswith(DIAGNOSTICS_MEDIA_TYPE),
            content_matches=content == body, sha256=hashlib.sha256(content).hexdigest(),
            cache_control=headers.get("cache-control"),
        )

        owner = _login(client, recorder, "owner_login", args.owner_login, owner_password)
        sensitive += [owner.access_token, owner.refresh_token]
        # An owner that also holds a support role would be allowed, proving nothing.
        _require(
            recorder, "owner_login",
            PlatformRole.OWNER in owner.roles and not set(owner.roles) & SUPPORT_ROLES,
        )
        recorder.expect(
            "owner_list_refused",
            client.call("GET", f"{list_path}?{query}", token=owner.access_token),
            status={403}, error_code="E-PLT-403",
        )
        recorder.expect(
            "terminal_list_refused",
            client.call("GET", f"{list_path}?{query}", token=token),
            status={403}, error_code="E-PLT-403",
        )

        revoked = recorder.expect(
            "cleanup_terminal_self_revoke",
            client.call("POST", f"/v1/access/terminals/{installation_id}/revoke", token=token),
            status={200},
            model=TerminalSummary,
        )
        state["terminal_revoked"] = True
        recorder.note(terminal_status=revoked.status)
        summary["result"] = "passed"
    except SmokeFailure as failure:
        summary["result"] = "failed"
        summary["failed_step"] = str(failure)
    except (OSError, ValueError, HTTPException) as error:
        # Transport, TLS, timeout or a non-JSON body: still write evidence.
        summary["result"] = "failed"
        summary["failed_step"] = f"transport:{type(error).__name__}"
    finally:
        # Any other exception, an interrupt included, still gives the seat back.
        if summary.get("result") != "passed":
            summary.setdefault("result", "failed")
            summary.setdefault("failed_step", "interrupted")
            _cleanup(client, recorder, state)
    summary["finished_at"] = _now()
    return _redacted(summary, sensitive)


def _redacted(summary: dict[str, Any], sensitive: list[str]) -> dict[str, Any]:
    """Drop every step rather than write evidence that holds a sensitive value."""
    rendered = json.dumps(summary, ensure_ascii=False, sort_keys=True)
    # A value with quotes or backslashes appears escaped in the JSON.
    forms = {form for value in sensitive if value
             for form in (value, json.dumps(value, ensure_ascii=False)[1:-1])}
    if not any(form in rendered for form in forms):
        return summary
    return {
        key: summary[key]
        for key in ("schema_version", "started_at", "finished_at", "endpoint", "script_commit")
    } | {
        "result": "failed",
        "failed_step": "redaction_check",
        "secrets_included": False,
        "steps": [],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True, help="https://<host>:7443")
    parser.add_argument("--ca-file", required=True, help="private CA certificate (PEM)")
    parser.add_argument("--account-name", required=True, help="test institution account")
    parser.add_argument("--support-login", required=True, help="PLATFORM_SUPPORT login name")
    parser.add_argument("--owner-login", required=True, help="PLATFORM_OWNER login name")
    parser.add_argument("--output", required=True, type=Path, help="redacted JSON evidence")
    args = parser.parse_args()
    if urlparse(args.base_url).scheme != "https":
        parser.error("--base-url must be https")
    password = getpass.getpass("Test institution password: ")
    support_password = getpass.getpass("PLATFORM_SUPPORT password: ")
    owner_password = getpass.getpass("PLATFORM_OWNER password: ")
    summary = run(args, password, support_password, owner_password)
    rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if any(value and value in rendered for value in (password, support_password, owner_password)):
        print("refusing to write evidence that contains a password", file=sys.stderr)
        return 2
    args.output.write_text(rendered, encoding="utf-8")
    print(f"diagnostics_smoke={summary['result']} output={args.output} secrets=not-printed")
    return 0 if summary["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
