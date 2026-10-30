#!/usr/bin/env python3
"""RAY-785 real-TLS smoke of the terminal-activation and insole-inventory routes.

Run it from a workstation against the integration endpoint. It asks for the
test institution password with getpass and writes redacted JSON: no password,
token, account name, signature or tenant identifier ever reaches the output.

Two synthetic terminals are activated so revocation is exercised as one
terminal revoking another, not as self-revocation (still open under RAY-728).
Terminal A registers and retires a synthetic insole pair; terminal B sees it
in the cursor download and reports battery and state for it. A then revokes
B, and B's refresh must fail with ``E-TRM-401-REVOKED``. Finally A revokes
itself so the run gives back both seats.
"""

from __future__ import annotations

import argparse
import base64
from datetime import UTC, datetime
import getpass
import hashlib
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import sys
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urlencode, urlparse
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import BaseModel, ValidationError

from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.insole_inventory import (
    InsoleChangesResponse,
    InsoleRegistrationResponse,
    InsoleReportResponse,
    InsoleRetireResponse,
)
from techflex_cloud_foundation.contracts.terminal_access import (
    TerminalCredentialResponse,
    TerminalListResponse,
    TerminalSummary,
)

SCHEMA_VERSION = "ray785-route-smoke/1"
MAX_CHANGE_PAGES = 50


class SmokeFailure(RuntimeError):
    pass


class Client:
    def __init__(self, base_url: str, ca_file: str) -> None:
        self._base_url = base_url.rstrip("/")
        context = ssl.create_default_context(cafile=ca_file)
        # The integration host is reached directly; a workstation proxy must
        # not sit between the client and the private-CA TLS endpoint.
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))

    def call(
        self,
        method: str,
        path: str,
        *,
        token: str | None = None,
        body: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
    ) -> tuple[int, dict[str, Any]]:
        request = Request(self._base_url + path, method=method)
        request.add_header("Accept", "application/json")
        if token is not None:
            request.add_header("Authorization", f"Bearer {token}")
        for name, value in (headers or {}).items():
            request.add_header(name, value)
        # Raw bodies (segment uploads) normally name their own Content-Type;
        # never let urllib fall back to form encoding.
        data = content
        if content is not None and not request.has_header("Content-type"):
            request.add_header("Content-Type", "application/octet-stream")
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            request.add_header("Content-Type", "application/json")
        try:
            with self._opener.open(request, data=data, timeout=30) as response:
                return response.status, json.loads(response.read() or b"{}")
        except HTTPError as error:
            payload = error.read()
            try:
                return error.code, json.loads(payload or b"{}")
            except json.JSONDecodeError:
                return error.code, {}


class Recorder:
    def __init__(self) -> None:
        self.steps: list[dict[str, Any]] = []

    def expect(
        self,
        name: str,
        result: tuple[int, dict[str, Any]],
        *,
        status: set[int],
        model: type[BaseModel] | None = None,
        error_code: str | None = None,
    ) -> Any:
        code, payload = result
        step: dict[str, Any] = {
            "step": name,
            "status": code,
            "request_id": (payload.get("meta") or {}).get("request_id"),
        }
        error = payload.get("error") or {}
        if error:
            step["error_code"] = error.get("code")
        parsed = None
        ok = code in status
        if ok and error_code is not None:
            ok = error.get("code") == error_code
        if ok and model is not None:
            try:
                parsed = model.model_validate(payload.get("data"))
                step["contract_valid"] = True
            except ValidationError as exc:
                step["contract_valid"] = False
                step["contract_errors"] = [
                    ".".join(str(part) for part in item["loc"]) for item in exc.errors()
                ]
                ok = False
        step["passed"] = ok
        self.steps.append(step)
        if not ok:
            raise SmokeFailure(name)
        return parsed

    def note(self, **fields: Any) -> None:
        self.steps[-1].update(fields)


def _public_key(path: str) -> Ed25519PublicKey:
    raw = Path(path).read_bytes()
    if len(raw) != 32:
        raw = base64.b64decode(raw.decode("ascii").strip(), validate=True)
    return Ed25519PublicKey.from_public_bytes(raw)


def _license_check(
    credential: TerminalCredentialResponse, public_key_path: str | None
) -> dict[str, Any]:
    signed = credential.signed_license
    check: dict[str, Any] = {
        "schema_version": signed.document.schema_version,
        "key_id": signed.key_id,
        "license_status": signed.document.status,
        "seats": signed.document.seats,
    }
    if public_key_path is None:
        check["signature_verified"] = None
        return check
    try:
        _public_key(public_key_path).verify(
            base64.b64decode(signed.signature, validate=True),
            canonical_json_bytes(signed.document),
        )
        check["signature_verified"] = True
    except (InvalidSignature, ValueError):
        check["signature_verified"] = False
    check["public_key_sha256"] = hashlib.sha256(Path(public_key_path).read_bytes()).hexdigest()
    return check


def _synthetic_mac() -> str:
    # Locally administered, unicast: never collides with a real insole MAC.
    octets = [0x02] + [secrets.randbelow(256) for _ in range(5)]
    return ":".join(f"{octet:02X}" for octet in octets)


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _activate(
    client: Client, recorder: Recorder, name: str, account: str, password: str, label: str
) -> TerminalCredentialResponse:
    installation_id = str(uuid4())
    credential = recorder.expect(
        name,
        client.call(
            "POST",
            "/v1/access/terminal-activate",
            body={
                "account_name": account,
                "password": password,
                "terminal_name": label,
                "client_installation_id": installation_id,
                "platform": "android",
            },
        ),
        status={201},
        model=TerminalCredentialResponse,
    )
    recorder.note(client_installation_id=installation_id, terminal_name=label)
    return credential


def _find_in_changes(
    client: Client, recorder: Recorder, token: str, insole_id: str
) -> None:
    cursor: str | None = None
    for page in range(1, MAX_CHANGE_PAGES + 1):
        query = urlencode({"limit": 100, **({"cursor": cursor} if cursor else {})})
        changes = recorder.expect(
            "insole_download_by_terminal_b",
            client.call("GET", f"/v1/inventory/insoles?{query}", token=token),
            status={200},
            model=InsoleChangesResponse,
        )
        match = next((item for item in changes.items if str(item.insole_id) == insole_id), None)
        if match is not None:
            recorder.note(
                pages=page,
                found=True,
                revision=match.revision,
                state=match.state,
                size=match.size,
            )
            return
        if not changes.has_more:
            break
        cursor = changes.next_cursor
        recorder.steps.pop()
    recorder.note(found=False, passed=False)
    raise SmokeFailure("insole_download_by_terminal_b")


def run(args: argparse.Namespace, password: str) -> dict[str, Any]:
    client = Client(args.base_url, args.ca_file)
    recorder = Recorder()
    run_tag = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    summary: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "started_at": _now(),
        "endpoint": args.base_url,
        "account_name_sha256": hashlib.sha256(args.account_name.encode()).hexdigest(),
        "ca_file_sha256": hashlib.sha256(Path(args.ca_file).read_bytes()).hexdigest(),
        "script_commit": _git_head(),
        "secrets_included": False,
        "steps": recorder.steps,
    }
    try:
        recorder.expect(
            "readiness", client.call("GET", "/health/ready"), status={200}
        )
        a = _activate(
            client, recorder, "terminal_a_activate", args.account_name, password,
            f"ray785-smoke-a-{run_tag}",
        )
        summary["license"] = _license_check(a, args.license_public_key)
        a_id = str(a.client_installation_id)

        rotated = recorder.expect(
            "terminal_a_refresh",
            client.call(
                "POST",
                "/v1/access/terminal-refresh",
                body={"refresh_token": a.refresh_token, "client_installation_id": a_id},
            ),
            status={200},
            model=TerminalCredentialResponse,
        )
        recorder.note(refresh_rotated=rotated.refresh_token != a.refresh_token)
        if rotated.refresh_token == a.refresh_token:
            recorder.note(passed=False)
            raise SmokeFailure("terminal_a_refresh")
        a_token = rotated.access_token

        listing = recorder.expect(
            "terminal_list_before_b",
            client.call("GET", "/v1/access/terminals", token=a_token),
            status={200},
            model=TerminalListResponse,
        )
        recorder.note(seats=listing.seats, seats_used=listing.seats_used)
        if listing.seats_used >= listing.seats:
            recorder.note(passed=False, reason="no free seat for terminal B")
            raise SmokeFailure("terminal_list_before_b")

        b = _activate(
            client, recorder, "terminal_b_activate", args.account_name, password,
            f"ray785-smoke-b-{run_tag}",
        )
        b_id = str(b.client_installation_id)

        identities = {
            side: {"identity": {"kind": "mac", "value": _synthetic_mac(), "provenance": "ray785-smoke"}}
            for side in ("left", "right")
        }
        registration = recorder.expect(
            "insole_register_by_terminal_a",
            client.call(
                "POST",
                "/v1/inventory/insoles",
                token=a_token,
                headers={"Idempotency-Key": f"ray785-smoke-{uuid4()}"},
                body={
                    "institution_number": f"SMOKE-{run_tag[-7:-1]}",
                    "size": 40,
                    **identities,
                },
            ),
            status={201},
            model=InsoleRegistrationResponse,
        )
        insole_id = str(registration.insole.insole_id)
        recorder.note(
            insole_id=insole_id,
            revision=registration.insole.revision,
            state=registration.insole.state,
            idempotent_replay=registration.idempotent_replay,
        )

        _find_in_changes(client, recorder, b.access_token, insole_id)

        observed = _now()
        report = recorder.expect(
            "insole_report_by_terminal_b",
            client.call(
                "POST",
                f"/v1/inventory/insoles/{insole_id}/reports",
                token=b.access_token,
                body={
                    "left": {"millivolts": 3900, "percent": 80, "read_at": observed},
                    "right": {"millivolts": 3850, "percent": 76, "read_at": observed},
                    "state": {"state": "in_use", "observed_at": observed},
                },
            ),
            status={200},
            model=InsoleReportResponse,
        )
        recorder.note(applied=report.applied.model_dump(mode="json"), state=report.insole.state)

        retired = recorder.expect(
            "insole_retire_by_terminal_a",
            client.call("POST", f"/v1/inventory/insoles/{insole_id}/retire", token=a_token),
            status={200},
            model=InsoleRetireResponse,
        )
        recorder.note(state=retired.insole.state, revision=retired.insole.revision)

        revoked = recorder.expect(
            "terminal_a_revokes_b",
            client.call("POST", f"/v1/access/terminals/{b_id}/revoke", token=a_token),
            status={200},
            model=TerminalSummary,
        )
        recorder.note(terminal_status=revoked.status)

        recorder.expect(
            "terminal_b_refresh_after_revoke",
            client.call(
                "POST",
                "/v1/access/terminal-refresh",
                body={"refresh_token": b.refresh_token, "client_installation_id": b_id},
            ),
            status={401},
            error_code="E-TRM-401-REVOKED",
        )

        after = recorder.expect(
            "terminal_list_after_revoke",
            client.call("GET", "/v1/access/terminals", token=a_token),
            status={200},
            model=TerminalListResponse,
        )
        b_entry = next(
            (t for t in after.terminals if str(t.client_installation_id) == b_id), None
        )
        recorder.note(
            b_status=b_entry.status if b_entry else None,
            seats=after.seats,
            seats_used=after.seats_used,
        )

        recorder.expect(
            "cleanup_terminal_a_revoke",
            client.call("POST", f"/v1/access/terminals/{a_id}/revoke", token=a_token),
            status={200},
            model=TerminalSummary,
        )
        summary["result"] = "passed"
    except SmokeFailure as failure:
        summary["result"] = "failed"
        summary["failed_step"] = str(failure)
    summary["finished_at"] = _now()
    return summary


def _git_head() -> str | None:
    try:
        return subprocess.run(
            ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True, help="https://<host>:7443")
    parser.add_argument("--ca-file", required=True, help="private CA certificate (PEM)")
    parser.add_argument("--account-name", required=True, help="test institution account")
    parser.add_argument(
        "--license-public-key",
        help="optional exported License public key; verifies the signed terminal-license/1",
    )
    parser.add_argument("--output", required=True, type=Path, help="redacted JSON evidence")
    args = parser.parse_args()
    if urlparse(args.base_url).scheme != "https":
        parser.error("--base-url must be https")
    password = getpass.getpass("Test institution password: ")
    summary = run(args, password)
    args.output.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    for secret in (password,):
        if secret and secret in args.output.read_text(encoding="utf-8"):
            args.output.unlink()
            print("refusing to keep evidence that contains the password", file=sys.stderr)
            return 2
    print(f"route_smoke={summary['result']} output={args.output} secrets=not-printed")
    return 0 if summary["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
