#!/usr/bin/env python3
"""RAY-815 real-TLS smoke of the terminal data plane (RAY-728) on integration.

Run it from a workstation against the integration endpoint. It asks for the
test institution password with getpass and writes redacted JSON: no password,
token, account name, external identifier or tenant identifier reaches the
output.

One synthetic terminal is activated, so the run needs one free seat. It
registers a synthetic insole pair and uses its ``insole_id`` as the session
``device_id``; creates a synthetic subject and consent; creates a session,
uploads one segment, completes it and requires ``INGESTED``. It then retires
the pair, revokes itself, and requires the revoked token to get
``E-TRM-401-REVOKED`` on the data plane. Subject, consent and session rows stay
behind, labelled ``ray815-smoke``. When a step fails, the run still retires
the pair and revokes the terminal, so a failed run gives its seat back.

Run it from the repository root (``./scripts/local-env.sh python
scripts/run_ray815_data_plane_smoke.py ...``): it imports ``scripts`` and
``shared``.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
import getpass
import hashlib
import json
from pathlib import Path
import secrets
import sys
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

from scripts.run_ray785_route_smoke import (
    Client,
    Recorder,
    SmokeFailure,
    _activate,
    _git_head,
    _now,
    _synthetic_mac,
)
from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    ConsentCreateRequest,
    ConsentResponse,
    ExternalIdentifierInput,
    IngestStatus,
    ManifestCompletionResponse,
    ManifestSegment,
    SegmentAcknowledgement,
    SegmentListResponse,
    SegmentMetadata,
    SessionCreateRequest,
    SessionCreateResponse,
    SessionManifest,
    SessionStatusResponse,
    SessionVersions,
    SubjectCreateRequest,
    SubjectSummary,
    TestProtocol,
)
from techflex_cloud_foundation.contracts.insole_inventory import (
    InsoleRegistrationResponse,
    InsoleRetireResponse,
)
from techflex_cloud_foundation.contracts.terminal_access import TerminalSummary

SCHEMA_VERSION = "ray815-data-plane-smoke/1"
SEGMENT_CONTENT_TYPE = "application/vnd.feetforceplate.segment.v1+octet-stream"


def _cleanup(client: Client, recorder: Recorder, state: dict[str, Any]) -> None:
    """Best effort after a failure; never changes the recorded failed step."""
    if state.get("insole_id") is not None and not state.get("insole_retired"):
        try:
            recorder.expect(
                "cleanup_insole_retire",
                client.call(
                    "POST",
                    f"/v1/inventory/insoles/{state['insole_id']}/retire",
                    token=state["token"],
                ),
                status={200},
            )
        except (SmokeFailure, OSError, ValueError):
            pass
    if state.get("installation_id") is not None and not state.get("terminal_revoked"):
        try:
            # Self-revoke is idempotent (RAY-728 self_revoke.repeat).
            recorder.expect(
                "cleanup_terminal_self_revoke",
                client.call(
                    "POST",
                    f"/v1/access/terminals/{state['installation_id']}/revoke",
                    token=state["token"],
                ),
                status={200},
            )
        except (SmokeFailure, OSError, ValueError):
            pass


def run(args: argparse.Namespace, password: str) -> dict[str, Any]:
    client = Client(args.base_url, args.ca_file)
    recorder = Recorder()
    state: dict[str, Any] = {}
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
        recorder.expect("readiness", client.call("GET", "/health/ready"), status={200})
        terminal = _activate(
            client, recorder, "terminal_activate", args.account_name, password,
            f"ray815-smoke-{run_tag}",
        )
        token = terminal.access_token
        installation_id = terminal.client_installation_id
        state.update(token=token, installation_id=installation_id)
        # Optional on the data plane; when sent it must match (RAY-728 D1).
        terminal_header = {"X-Terminal-ID": str(installation_id)}

        registration = recorder.expect(
            "insole_register",
            client.call(
                "POST",
                "/v1/inventory/insoles",
                token=token,
                headers={"Idempotency-Key": f"ray815-smoke-{uuid4()}"},
                body={
                    "institution_number": f"SMOKE-{run_tag[-7:-1]}-{secrets.token_hex(2)}",
                    "size": 40,
                    **{
                        side: {
                            "identity": {
                                "kind": "mac",
                                "value": _synthetic_mac(),
                                "provenance": "ray815-smoke",
                            }
                        }
                        for side in ("left", "right")
                    },
                },
            ),
            status={201},
            model=InsoleRegistrationResponse,
        )
        insole_id = registration.insole.insole_id
        state["insole_id"] = insole_id
        recorder.note(insole_id=str(insole_id), state=registration.insole.state)

        identifier = ExternalIdentifierInput(
            issuer="ray815-smoke",
            id_type="smoke_subject",
            external_id=f"SMOKE-{run_tag}-{secrets.token_hex(4)}",
        )
        subject_id = uuid4()
        created = recorder.expect(
            "subject_create",
            client.call(
                "POST",
                "/v1/subjects",
                token=token,
                headers={"Idempotency-Key": f"ray815-subject-{subject_id}", **terminal_header},
                body=SubjectCreateRequest(
                    subject_uuid=subject_id, external_identifier=identifier
                ).model_dump(mode="json"),
            ),
            status={201},
            model=SubjectSummary,
        )
        recorder.note(subject_uuid=str(created.subject_uuid), conflict=created.conflict)

        resolved = recorder.expect(
            "subject_resolve",
            client.call(
                "POST",
                "/v1/subjects/resolve",
                token=token,
                headers=terminal_header,
                body=identifier.model_dump(mode="json"),
            ),
            status={200},
            model=SubjectSummary,
        )
        recorder.note(matches_created=resolved.subject_uuid == subject_id)
        if resolved.subject_uuid != subject_id:
            recorder.note(passed=False)
            raise SmokeFailure("subject_resolve")

        now = datetime.now(UTC).replace(microsecond=0)
        consent_id = uuid4()
        consent = recorder.expect(
            "consent_create",
            client.call(
                "POST",
                "/v1/consents",
                token=token,
                headers={"Idempotency-Key": f"ray815-consent-{consent_id}", **terminal_header},
                body=ConsentCreateRequest(
                    consent_record_id=consent_id,
                    subject_uuid=subject_id,
                    policy_version="ray815-smoke/1",
                    purpose_codes=("SCREENING_SERVICE",),
                    data_categories=("PRESSURE_RAW",),
                    granted_at=now,
                    evidence_type="OPERATOR_CONFIRMED",
                    terminal_signature="ray815-smoke-synthetic-evidence",
                ).model_dump(mode="json"),
            ),
            status={201},
            model=ConsentResponse,
        )
        recorder.note(consent_record_id=str(consent.consent_record_id))

        session_id = uuid4()
        session = recorder.expect(
            "session_create",
            client.call(
                "POST",
                "/v1/sessions",
                token=token,
                headers={"Idempotency-Key": f"ray815-session-{session_id}", **terminal_header},
                body=SessionCreateRequest(
                    session_id=session_id,
                    subject_uuid=subject_id,
                    consent_record_id=consent_id,
                    site_id=None,
                    terminal_id=installation_id,
                    client_installation_id=installation_id,
                    device_id=insole_id,
                    test_protocol=TestProtocol(id="ray815-smoke", version="1"),
                    versions=SessionVersions(
                        app="ray815-smoke",
                        protocol_profile="insole/1",
                        payload_schema="raw-segment/1",
                        calibration="calibration/1",
                    ),
                    started_at=now,
                ).model_dump(mode="json"),
            ),
            status={201},
            model=SessionCreateResponse,
        )
        recorder.note(session_id=str(session_id), ingest_status=session.ingest_status)

        payload = secrets.token_bytes(256)
        metadata = SegmentMetadata(
            segment_index=0,
            start_frame_index=0,
            frame_count=10,
            start_monotonic_ns=100,
            end_monotonic_ns=200,
            compression="none",
            cipher="aes-256-gcm",
            size_bytes=len(payload),
            sha256=hashlib.sha256(payload).hexdigest(),
            payload_schema_version="raw-segment/1",
        )
        segment = recorder.expect(
            "segment_put",
            client.call(
                "PUT",
                f"/v1/sessions/{session_id}/segments/0",
                token=token,
                headers={
                    **terminal_header,
                    "X-Content-SHA256": metadata.sha256,
                    "X-Schema-Version": metadata.payload_schema_version,
                    "X-Segment-Metadata": encode_segment_metadata(metadata),
                    "Content-Type": SEGMENT_CONTENT_TYPE,
                },
                content=payload,
            ),
            status={201},
            model=SegmentAcknowledgement,
        )
        recorder.note(segment_status=segment.status)

        listing = recorder.expect(
            "segment_list",
            client.call(
                "GET", f"/v1/sessions/{session_id}/segments", token=token, headers=terminal_header
            ),
            status={200},
            model=SegmentListResponse,
        )
        recorder.note(received=len(listing.received), missing=list(listing.missing))
        if listing.missing:
            recorder.note(passed=False)
            raise SmokeFailure("segment_list")

        manifest = SessionManifest(
            segment_count=1,
            total_frames=metadata.frame_count,
            total_bytes=metadata.size_bytes,
            segments=(
                ManifestSegment(
                    index=0,
                    sha256=metadata.sha256,
                    size_bytes=metadata.size_bytes,
                    frame_count=metadata.frame_count,
                ),
            ),
            ended_at=now + timedelta(seconds=1),
            local_quality_outcome="VALID",
        )
        completion = recorder.expect(
            "session_complete",
            client.call(
                "POST",
                f"/v1/sessions/{session_id}/complete",
                token=token,
                headers={
                    **terminal_header,
                    "Idempotency-Key": f"ray815-complete-{session_id}",
                    "X-Content-SHA256": canonical_sha256(manifest),
                    "X-Schema-Version": manifest.schema_version,
                },
                body=manifest.model_dump(mode="json"),
            ),
            status={200},
            model=ManifestCompletionResponse,
        )
        recorder.note(
            ingest_status=completion.ingest_status,
            eligibility_reason=completion.eligibility_reason,
        )

        status = recorder.expect(
            "session_status",
            client.call(
                "GET", f"/v1/sessions/{session_id}/status", token=token, headers=terminal_header
            ),
            status={200},
            model=SessionStatusResponse,
        )
        recorder.note(
            ingest_status=status.ingest_status, validity_status=status.validity_status
        )
        if status.ingest_status != IngestStatus.INGESTED:
            recorder.note(passed=False)
            raise SmokeFailure("session_status")

        retired = recorder.expect(
            "cleanup_insole_retire",
            client.call("POST", f"/v1/inventory/insoles/{insole_id}/retire", token=token),
            status={200},
            model=InsoleRetireResponse,
        )
        state["insole_retired"] = True
        recorder.note(state=retired.insole.state)

        revoked = recorder.expect(
            "cleanup_terminal_self_revoke",
            client.call("POST", f"/v1/access/terminals/{installation_id}/revoke", token=token),
            status={200},
            model=TerminalSummary,
        )
        state["terminal_revoked"] = True
        recorder.note(terminal_status=revoked.status)

        recorder.expect(
            "data_plane_after_revoke",
            client.call(
                "GET", f"/v1/sessions/{session_id}/status", token=token, headers=terminal_header
            ),
            status={401},
            error_code="E-TRM-401-REVOKED",
        )
        summary["result"] = "passed"
    except SmokeFailure as failure:
        summary["result"] = "failed"
        summary["failed_step"] = str(failure)
    except (OSError, ValueError) as error:
        # Transport, TLS, timeout or a non-JSON body: still write evidence.
        summary["result"] = "failed"
        summary["failed_step"] = f"transport:{type(error).__name__}"
    if summary["result"] == "failed":
        _cleanup(client, recorder, state)
    summary["finished_at"] = _now()
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--base-url", required=True, help="https://<host>:7443")
    parser.add_argument("--ca-file", required=True, help="private CA certificate (PEM)")
    parser.add_argument("--account-name", required=True, help="test institution account")
    parser.add_argument("--output", required=True, type=Path, help="redacted JSON evidence")
    args = parser.parse_args()
    if urlparse(args.base_url).scheme != "https":
        parser.error("--base-url must be https")
    password = getpass.getpass("Test institution password: ")
    summary = run(args, password)
    rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    if password and password in rendered:
        print("refusing to write evidence that contains the password", file=sys.stderr)
        return 2
    args.output.write_text(rendered, encoding="utf-8")
    print(f"data_plane_smoke={summary['result']} output={args.output} secrets=not-printed")
    return 0 if summary["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
