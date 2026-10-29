#!/usr/bin/env python3
"""RAY-825 real-TLS smoke of insole-session-archive/1 uploads on integration.

Run it from a workstation against the integration endpoint. It asks for the
test institution password with getpass and writes redacted JSON: no password,
token, account name, external identifier or tenant identifier reaches the
output.

One synthetic terminal is activated, so the run needs one free seat. It
registers a synthetic insole pair (its ``insole_id`` is the session
``device_id``) and creates a synthetic subject and consent. It then uploads two
sessions with the terminal token, each to ``INGESTED``:

* an ``insole-session-archive/1`` session of two archive parts (a full 4 MiB
  part and a short tail) whose ``config_snapshot`` holds Chinese text
  (RAY-834), after first checking that a ``session-manifest/1`` manifest is
  refused for it with ``UPDATE_CLIENT``;
* a ``raw-segment/1`` session, to show the force-plate schema still works.

It finally retires the pair, revokes itself, and requires the revoked token to
get ``E-TRM-401-REVOKED``. Subject, consent and session rows stay behind,
labelled ``ray825-smoke``. When a step fails, the run still retires the pair and
revokes the terminal, so a failed run gives its seat back.

Run it from the repository root (``./scripts/local-env.sh python
scripts/run_ray825_insole_archive_smoke.py ...``): it imports ``scripts`` and
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
from scripts.run_ray815_data_plane_smoke import _cleanup
from techflex_cloud_foundation.contracts.client_sync import (
    canonical_sha256,
    encode_segment_metadata,
)
from techflex_cloud_foundation.contracts.cloud import (
    INSOLE_ARCHIVE_PAYLOAD_SCHEMA,
    INSOLE_MANIFEST_SCHEMA,
    AnySegmentMetadata,
    AnySessionManifest,
    ArchiveManifestSegment,
    ArchiveSegmentMetadata,
    ConsentCreateRequest,
    ConsentResponse,
    ExternalIdentifierInput,
    IngestStatus,
    InsoleSessionManifest,
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

SCHEMA_VERSION = "ray825-insole-archive-smoke/1"
ARCHIVE_PART_BYTES = 4 * 1024 * 1024


def _upload_session(
    client: Client,
    recorder: Recorder,
    *,
    label: str,
    token: str,
    headers: dict[str, str],
    request: SessionCreateRequest,
    parts: list[tuple[AnySegmentMetadata, bytes]],
    manifest: AnySessionManifest,
    rejected_manifest: AnySessionManifest | None = None,
) -> None:
    """Create, PUT every part, list, complete and require INGESTED."""
    session_id = request.session_id
    created = recorder.expect(
        f"{label}_session_create",
        client.call(
            "POST", "/v1/sessions", token=token,
            headers={"Idempotency-Key": f"ray825-session-{session_id}", **headers},
            body=request.model_dump(mode="json"),
        ),
        status={201},
        model=SessionCreateResponse,
    )
    recorder.note(
        session_id=str(session_id), payload_schema=request.versions.payload_schema,
        ingest_status=created.ingest_status,
    )
    for metadata, payload in parts:
        ack = recorder.expect(
            f"{label}_segment_put_{metadata.segment_index}",
            client.call(
                "PUT", f"/v1/sessions/{session_id}/segments/{metadata.segment_index}",
                token=token,
                headers={
                    **headers,
                    "X-Content-SHA256": metadata.sha256,
                    "X-Schema-Version": metadata.payload_schema_version,
                    "X-Segment-Metadata": encode_segment_metadata(metadata),
                    "Content-Type": "application/octet-stream",
                },
                content=payload,
            ),
            status={201},
            model=SegmentAcknowledgement,
        )
        recorder.note(segment_status=ack.status, size_bytes=metadata.size_bytes)

    listing = recorder.expect(
        f"{label}_segment_list",
        client.call("GET", f"/v1/sessions/{session_id}/segments", token=token, headers=headers),
        status={200},
        model=SegmentListResponse,
    )
    recorder.note(received=len(listing.received), missing=list(listing.missing))
    if listing.missing or len(listing.received) != len(parts):
        recorder.note(passed=False)
        raise SmokeFailure(f"{label}_segment_list")

    def complete(manifest_: AnySessionManifest):
        return client.call(
            "POST", f"/v1/sessions/{session_id}/complete", token=token,
            headers={
                **headers,
                "Idempotency-Key": f"ray825-complete-{canonical_sha256(manifest_)}",
                "X-Content-SHA256": canonical_sha256(manifest_),
                "X-Schema-Version": manifest_.schema_version,
            },
            body=manifest_.model_dump(mode="json"),
        )

    if rejected_manifest is not None:
        status, body = complete(rejected_manifest)
        recorder.expect(
            f"{label}_crossed_manifest_rejected", (status, body), status={422},
            error_code="E-CLD-422",
        )
        action = (body.get("error") or {}).get("action")
        recorder.note(action=action)
        if action != "UPDATE_CLIENT":
            recorder.note(passed=False)
            raise SmokeFailure(f"{label}_crossed_manifest_rejected")

    completion = recorder.expect(
        f"{label}_session_complete", complete(manifest), status={200},
        model=ManifestCompletionResponse,
    )
    recorder.note(
        ingest_status=completion.ingest_status, manifest_sha256=completion.manifest_sha256
    )
    status = recorder.expect(
        f"{label}_session_status",
        client.call("GET", f"/v1/sessions/{session_id}/status", token=token, headers=headers),
        status={200},
        model=SessionStatusResponse,
    )
    recorder.note(ingest_status=status.ingest_status, validity_status=status.validity_status)
    if status.ingest_status != IngestStatus.INGESTED:
        recorder.note(passed=False)
        raise SmokeFailure(f"{label}_session_status")


def _archive_contracts(now: datetime) -> tuple[list, InsoleSessionManifest, SessionManifest]:
    blobs = [secrets.token_bytes(ARCHIVE_PART_BYTES), secrets.token_bytes(1531)]
    parts = [
        (
            ArchiveSegmentMetadata(
                segment_index=index, size_bytes=len(blob),
                sha256=hashlib.sha256(blob).hexdigest(),
                payload_schema_version=INSOLE_ARCHIVE_PAYLOAD_SCHEMA,
            ),
            blob,
        )
        for index, blob in enumerate(blobs)
    ]
    manifest = InsoleSessionManifest(
        schema_version=INSOLE_MANIFEST_SCHEMA,
        segment_count=len(parts),
        total_bytes=sum(len(blob) for blob in blobs),
        segments=tuple(
            ArchiveManifestSegment(index=m.segment_index, sha256=m.sha256, size_bytes=m.size_bytes)
            for m, _ in parts
        ),
        # Microseconds exercise the canonical datetime form of the digest.
        ended_at=now + timedelta(seconds=60, microseconds=250000),
        local_quality_outcome="VALID",
    )
    crossed = SessionManifest(
        segment_count=len(parts), total_frames=len(parts), total_bytes=manifest.total_bytes,
        segments=tuple(
            ManifestSegment(index=m.segment_index, sha256=m.sha256, size_bytes=m.size_bytes,
                            frame_count=1)
            for m, _ in parts
        ),
        ended_at=manifest.ended_at, local_quality_outcome="VALID",
    )
    return parts, manifest, crossed


def _raw_contracts(now: datetime) -> tuple[list, SessionManifest]:
    payload = secrets.token_bytes(256)
    metadata = SegmentMetadata(
        segment_index=0, start_frame_index=0, frame_count=10, start_monotonic_ns=100,
        end_monotonic_ns=200, compression="none", cipher="aes-256-gcm",
        size_bytes=len(payload), sha256=hashlib.sha256(payload).hexdigest(),
        payload_schema_version="raw-segment/1",
    )
    manifest = SessionManifest(
        segment_count=1, total_frames=10, total_bytes=len(payload),
        segments=(ManifestSegment(index=0, sha256=metadata.sha256, size_bytes=len(payload),
                                  frame_count=10),),
        ended_at=now + timedelta(seconds=1), local_quality_outcome="VALID",
    )
    return [(metadata, payload)], manifest


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
            f"ray825-smoke-{run_tag}",
        )
        token = terminal.access_token
        installation_id = terminal.client_installation_id
        state.update(token=token, installation_id=installation_id)
        terminal_header = {"X-Terminal-ID": str(installation_id)}

        registration = recorder.expect(
            "insole_register",
            client.call(
                "POST", "/v1/inventory/insoles", token=token,
                headers={"Idempotency-Key": f"ray825-smoke-{uuid4()}"},
                body={
                    "institution_number": f"SMOKE-{run_tag[-7:-1]}-{secrets.token_hex(2)}",
                    "size": 40,
                    **{
                        side: {"identity": {"kind": "mac", "value": _synthetic_mac(),
                                            "provenance": "ray825-smoke"}}
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
            issuer="ray825-smoke", id_type="smoke_subject",
            external_id=f"SMOKE-{run_tag}-{secrets.token_hex(4)}",
        )
        subject_id = uuid4()
        created = recorder.expect(
            "subject_create",
            client.call(
                "POST", "/v1/subjects", token=token,
                headers={"Idempotency-Key": f"ray825-subject-{subject_id}", **terminal_header},
                body=SubjectCreateRequest(
                    subject_uuid=subject_id, external_identifier=identifier
                ).model_dump(mode="json"),
            ),
            status={201},
            model=SubjectSummary,
        )
        recorder.note(subject_uuid=str(created.subject_uuid))

        now = datetime.now(UTC).replace(microsecond=0)
        consent_id = uuid4()
        consent = recorder.expect(
            "consent_create",
            client.call(
                "POST", "/v1/consents", token=token,
                headers={"Idempotency-Key": f"ray825-consent-{consent_id}", **terminal_header},
                body=ConsentCreateRequest(
                    consent_record_id=consent_id, subject_uuid=subject_id,
                    policy_version="ray825-smoke/1", purpose_codes=("SCREENING_SERVICE",),
                    data_categories=("PRESSURE_RAW",), granted_at=now,
                    evidence_type="OPERATOR_CONFIRMED",
                    terminal_signature="ray825-smoke-synthetic-evidence",
                ).model_dump(mode="json"),
            ),
            status={201},
            model=ConsentResponse,
        )
        recorder.note(consent_record_id=str(consent.consent_record_id))

        def session_request(
            payload_schema: str, config_snapshot: dict[str, Any] | None = None
        ) -> SessionCreateRequest:
            return SessionCreateRequest(
                session_id=uuid4(), subject_uuid=subject_id, consent_record_id=consent_id,
                site_id=None, terminal_id=installation_id,
                client_installation_id=installation_id, device_id=insole_id,
                test_protocol=TestProtocol(id="ray825-smoke", version="1"),
                versions=SessionVersions(
                    app="ray825-smoke", protocol_profile="insole/1",
                    payload_schema=payload_schema, calibration="calibration/1",
                ),
                started_at=now,
                config_snapshot=config_snapshot or {},
            )

        archive_parts, archive_manifest, crossed = _archive_contracts(now)
        _upload_session(
            client, recorder, label="archive", token=token, headers=terminal_header,
            # RAY-834: a Chinese test plan, as the insole app sends, must be stored.
            request=session_request(
                INSOLE_ARCHIVE_PAYLOAD_SCHEMA,
                {"测试计划": "步行 60 秒", "项目": ["步行", "其他"]},
            ),
            parts=archive_parts,
            manifest=archive_manifest, rejected_manifest=crossed,
        )
        raw_parts, raw_manifest = _raw_contracts(now)
        raw_request = session_request("raw-segment/1")
        _upload_session(
            client, recorder, label="raw", token=token, headers=terminal_header,
            request=raw_request, parts=raw_parts, manifest=raw_manifest,
        )

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
                "GET", f"/v1/sessions/{raw_request.session_id}/status", token=token,
                headers=terminal_header,
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
    finally:
        # Any other exception, an interrupt included, still gives the seat back.
        if summary.get("result") != "passed":
            summary.setdefault("result", "failed")
            summary.setdefault("failed_step", "interrupted")
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
    print(f"insole_archive_smoke={summary['result']} output={args.output} secrets=not-printed")
    return 0 if summary["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
