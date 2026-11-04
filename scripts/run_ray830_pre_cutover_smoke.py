#!/usr/bin/env python3
"""RAY-830 gait ingestion / diagnostic upload smoke with redacted evidence.

Writes synthetic records and temporarily consumes one terminal seat. Revokes that
terminal on success or failure; uploaded sessions/diagnostics remain (diagnostics
expire after 30 days). Run with python -m scripts.run_ray830_pre_cutover_smoke.
Rehearsal is loopback only; production requires --allow-production-write.
This tool never deploys or changes the service. A failed gait probe is a blocker.
"""
from __future__ import annotations

import argparse
import base64
from datetime import timedelta
import getpass
import gzip
import hashlib
import ipaddress
import json
from pathlib import Path
import ssl
from typing import Any
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, build_opener
from uuid import UUID, uuid4

from scripts.run_ray785_route_smoke import (
    Client as BaseClient,
)
from scripts.run_ray785_route_smoke import (
    Recorder,
    SmokeFailure,
    _activate,
    _git_head,
    _now,
)
from techflex_cloud_foundation.contracts.cloud import (
    ManifestCompletionResponse,
    SegmentAcknowledgement,
    SegmentListResponse,
    SessionCreateResponse,
    SessionStatusResponse,
)
from techflex_cloud_foundation.contracts.terminal_access import TerminalSummary
from techflex_cloud_foundation.contracts.terminal_diagnostics import DiagnosticUploadResponse


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Never forward a terminal token or raw upload to a redirected host.
        return None


class Client(BaseClient):
    def __init__(self, base_url: str, ca_file: str) -> None:
        self._base_url = base_url.rstrip("/")
        context = ssl.create_default_context(cafile=ca_file)
        self._opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context), NoRedirect())


def validate_target(url: str, environment: str, allow_production: bool) -> None:
    target = urlsplit(url)
    if (target.scheme != "https" or not target.hostname or target.username is not None
            or target.password is not None or target.query or target.fragment
            or target.path not in ("", "/")):
        raise ValueError("target must be an HTTPS origin without credentials, path or query")
    if environment == "rehearsal":
        try:
            loopback = ipaddress.ip_address(target.hostname).is_loopback
        except ValueError:
            loopback = False
        if not loopback or target.port != 27443:
            raise ValueError("rehearsal requires a loopback IP on port 27443")
    elif environment != "production" or not allow_production:
        raise ValueError("production writes require explicit acknowledgement")


def canonical(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def gait_documents(installation_id: UUID) -> tuple[dict, list[tuple[dict, bytes]], dict]:
    """Build a genuine small compressed byte archive using the RAY-833 contract."""
    archive = gzip.compress(b'{"synthetic":true,"samples":[1,2,3]}\n', mtime=0)
    part_size = 32
    parts = []
    for offset in range(0, len(archive), part_size):
        blob = archive[offset:offset + part_size]
        parts.append(({
            "segment_index": len(parts), "offset": offset, "size_bytes": len(blob),
            "sha256": hashlib.sha256(blob).hexdigest(),
            "payload_schema_version": "gait-session-archive/1",
        }, blob))
    request = {
        "session_id": str(uuid4()), "site_id": None,
        "client_installation_id": str(installation_id), "started_at": _now(),
        "versions": {"app": "ray830-smoke/1", "payload_schema": "gait-session-archive/1"},
        "config_snapshot": {"synthetic": True},
    }
    manifest = {
        "schema_version": "gait-session-manifest/1", "segment_count": len(parts),
        "total_bytes": len(archive), "codec": "gzip", "archive_size": len(archive),
        "archive_sha256": hashlib.sha256(archive).hexdigest(), "part_size": part_size,
        "segments": [{"index": m["segment_index"], "offset": m["offset"],
                      "size_bytes": m["size_bytes"], "sha256": m["sha256"]} for m, _ in parts],
    }
    return request, parts, manifest


def require(recorder: Recorder, name: str, passed: bool) -> None:
    recorder.steps.append({"step": name, "passed": bool(passed)})
    if not passed:
        raise SmokeFailure(name)


def gait(client, recorder, terminal) -> None:
    request, parts, manifest = gait_documents(terminal.client_installation_id)
    token = terminal.access_token
    sid = request["session_id"]
    headers = {"X-Terminal-ID": str(terminal.client_installation_id)}
    created = recorder.expect("gait_session_create", client.call(
        "POST", "/v1/sessions", token=token, body=request,
        headers={**headers, "Idempotency-Key": f"ray830-{sid}"}),
        status={201}, model=SessionCreateResponse)
    require(recorder, "gait_session_identity", str(created.session_id) == sid)
    for metadata, blob in parts:
        ack = recorder.expect(f"gait_segment_{metadata['segment_index']}", client.call(
            "PUT", f"/v1/sessions/{sid}/segments/{metadata['segment_index']}", token=token,
            content=blob, headers={**headers, "Content-Type": "application/octet-stream",
                "X-Content-SHA256": metadata["sha256"],
                "X-Schema-Version": metadata["payload_schema_version"],
                "X-Segment-Metadata": base64.b64encode(canonical(metadata)).decode()}),
            status={201}, model=SegmentAcknowledgement)
        require(recorder, f"gait_segment_{metadata['segment_index']}_identity",
                str(ack.session_id) == sid and ack.index == metadata["segment_index"] and ack.sha256 == metadata["sha256"])
    listing = recorder.expect("gait_segments_list", client.call(
        "GET", f"/v1/sessions/{sid}/segments", token=token, headers=headers),
        status={200}, model=SegmentListResponse)
    require(recorder, "gait_segments_present", not listing.missing and
            len(listing.received) == len(parts))
    digest = hashlib.sha256(canonical(manifest)).hexdigest()
    completed = recorder.expect("gait_complete", client.call(
        "POST", f"/v1/sessions/{sid}/complete", token=token, body=manifest,
        headers={**headers, "Idempotency-Key": f"ray830-complete-{sid}",
                 "X-Content-SHA256": digest, "X-Schema-Version": manifest["schema_version"]}),
        status={200}, model=ManifestCompletionResponse)
    require(recorder, "gait_completion_receipt", str(completed.session_id) == sid and
            completed.ingest_status == "INGESTED" and completed.manifest_sha256 == digest)
    status = recorder.expect("gait_status", client.call(
        "GET", f"/v1/sessions/{sid}/status", token=token, headers=headers),
        status={200}, model=SessionStatusResponse)
    require(recorder, "gait_ingested", str(status.session_id) == sid and
            status.ingest_status == "INGESTED")


def diagnostics(client, recorder, terminal) -> None:
    package = canonical({
        "kind": "header", "format": "gait-insole-diagnostics/1", "exported_at": _now(),
        "app_version": "ray830-smoke/1", "cloud_environment": "integration",
        "platform": "android", "os_version": "synthetic", "dropped_lines": 0,
        "tenant_id": str(terminal.tenant_id),
        "terminal_id": str(terminal.client_installation_id),
    }) + b'\n' + canonical({"kind": "log", "t": _now(), "level": "info",
                            "cat": "smoke", "msg": "synthetic readiness check"}) + b'\n'
    digest = hashlib.sha256(package).hexdigest()
    key = f"ray830-diagnostics-{uuid4()}"

    def upload():
        return client.call("POST", "/v1/diagnostics", token=terminal.access_token,
                           content=package, headers={"Content-Type": "application/x-ndjson",
                           "Idempotency-Key": key, "X-Content-SHA256": digest})

    first = recorder.expect("diagnostics_upload", upload(), status={201},
                            model=DiagnosticUploadResponse)
    require(recorder, "diagnostics_receipt", first.sha256 == digest and
            first.size_bytes == len(package) and first.format == "gait-insole-diagnostics/1"
            and first.expires_at - first.received_at == timedelta(days=30))
    replay = recorder.expect("diagnostics_replay", upload(), status={200},
                             model=DiagnosticUploadResponse)
    require(recorder, "diagnostics_replay_identical", first == replay)


def run(args: argparse.Namespace, password: str) -> dict[str, Any]:
    recorder = Recorder()
    sensitive = [password, args.account_name]
    summary = {"schema_version": "ray830-pre-cutover-smoke/1", "mode": args.mode,
               "environment": args.environment, "started_at": _now(),
               "script_commit": _git_head(), "result": "failed",
               "secrets_included": False, "steps": recorder.steps}
    client = None
    terminal = None
    try:
        summary["ca_sha256"] = hashlib.sha256(Path(args.ca_file).read_bytes()).hexdigest()
        client = Client(args.base_url, args.ca_file)
        recorder.expect("readiness", client.call("GET", "/health/ready"), status={200})
        terminal = _activate(client, recorder, "terminal_activate", args.account_name,
                             password, f"ray830-smoke-{uuid4().hex[:8]}")
        sensitive.extend([terminal.access_token, terminal.refresh_token, str(terminal.tenant_id)])
        (gait if args.mode == "gait" else diagnostics)(client, recorder, terminal)
        summary["result"] = "passed"
    except SmokeFailure as error:
        summary["failed_step"] = str(error)
    except (OSError, ValueError) as error:
        summary["failed_step"] = f"transport_or_contract:{type(error).__name__}"
    finally:
        if terminal is not None and client is not None:
            try:
                revoked = recorder.expect("cleanup_terminal_self_revoke", client.call(
                    "POST", f"/v1/access/terminals/{terminal.client_installation_id}/revoke",
                    token=terminal.access_token), status={200}, model=TerminalSummary)
                require(recorder, "cleanup_revoked", revoked.status == "REVOKED")
            except (SmokeFailure, OSError, ValueError):
                summary["result"] = "failed"
                summary.setdefault("failed_step", "cleanup_terminal_self_revoke")
                summary["cleanup_failed"] = True
        summary["finished_at"] = _now()
    # Evidence is an allowlist, never server messages, package contents or exception text.
    # Fail closed even if a server-controlled request ID contains a credential.
    rendered = json.dumps(summary, ensure_ascii=False)
    forms = {form for value in sensitive if value for form in
             (value, json.dumps(value, ensure_ascii=False)[1:-1])}
    if any(value in rendered for value in forms):
        return {"schema_version": "ray830-pre-cutover-smoke/1", "result": "failed",
                "failed_step": "redaction_check", "secrets_included": False, "steps": []}
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["gait", "diagnostics"], required=True)
    parser.add_argument("--environment", choices=["rehearsal", "production"], required=True)
    parser.add_argument("--allow-production-write", action="store_true")
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--account-name", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        validate_target(args.base_url, args.environment, args.allow_production_write)
    except ValueError as error:
        parser.error(str(error))
    # Open before writes so a bad evidence path cannot cause an unrecorded run.
    with args.output.open("x", encoding="utf-8") as output:
        result = run(args, getpass.getpass("Test institution password: "))
        output.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    print(f"{args.mode}_smoke={result['result']}")
    return 0 if result["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
