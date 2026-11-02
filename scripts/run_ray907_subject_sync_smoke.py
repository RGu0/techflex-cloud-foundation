#!/usr/bin/env python3
"""RAY-907 real-TLS smoke of the five subject sync routes on integration.

Run it from a workstation against the integration endpoint. It asks for the
test institution password with getpass and writes redacted JSON: no password,
token, account name, display name, external identifier or tenant identifier
reaches the output. Subjects are recorded by ``subject_uuid`` and revision
only, tags by ``tag_id`` only.

One synthetic terminal is activated, so the run needs one free seat. It
creates a synthetic subject labelled ``ray907-smoke`` with a synthetic display
name, then exercises, with the terminal token:

* ``GET /v1/subjects``: pages with ``cursor`` until the subject appears, and
  requires ascending revisions and a ``next_cursor`` on every page;
* ``PATCH /v1/subjects/{subject_uuid}``: a current ``base_revision`` raises the
  revision, a replay of the same key returns the same record, the same key with
  another body is ``E-API-409`` and a stale ``base_revision`` is
  ``E-SUB-409-REVISION-CONFLICT`` carrying ``details.current``;
* ``POST /v1/subjects/search-by-name``: the display name finds the subject;
* ``POST /v1/subject-tags``: a new tag is 201, another ``tag_id`` with the same
  normalized name is 200 with ``conflict: true``; the tag is then set on the
  subject through PATCH;
* ``GET /v1/subject-tags``: pages until the tag appears.

It then archives the subject, revokes itself, and requires the revoked token to
get ``E-TRM-401-REVOKED``. The archived subject and the tag stay behind,
labelled ``ray907-smoke``; R1 cannot delete tags, so each run adds one tag to
the institution's dictionary. When a step fails, the run still archives the
subject (best effort) and revokes the terminal, so a failed run gives its seat
back and leaves no active smoke subject.

Run it from the repository root (``./scripts/local-env.sh python
scripts/run_ray907_subject_sync_smoke.py ...``): it imports ``scripts`` and
``shared``.
"""

from __future__ import annotations

import argparse
from datetime import UTC, datetime
import getpass
import hashlib
import json
from pathlib import Path
import secrets
import sys
from typing import Any
from urllib.parse import urlencode, urlparse
from uuid import UUID, uuid4

from pydantic import BaseModel, ValidationError

from scripts.run_ray785_route_smoke import (
    Client,
    Recorder,
    SmokeFailure,
    _activate,
    _git_head,
    _now,
)
from scripts.run_ray815_data_plane_smoke import _cleanup
from techflex_cloud_foundation.contracts.cloud import (
    ExternalIdentifierInput,
    IdentityProfileInput,
    SubjectCreateRequest,
    SubjectSummary,
)
from techflex_cloud_foundation.contracts.subject_sync import (
    SUBJECT_PAGE_MAX_LIMIT,
    SubjectChangesResponse,
    SubjectEditableStatus,
    SubjectNameSearchRequest,
    SubjectNameSearchResponse,
    SubjectPatchRequest,
    SubjectRecord,
    SubjectStatus,
    SubjectTagChangesResponse,
    SubjectTagCreateRequest,
    SubjectTagCreateResponse,
)
from techflex_cloud_foundation.contracts.terminal_access import TerminalSummary

SCHEMA_VERSION = "ray907-subject-sync-smoke/1"
LABEL = "ray907-smoke"
MAX_PAGES = 200


def _page_until(
    client: Client,
    recorder: Recorder,
    name: str,
    path: str,
    model: type[SubjectChangesResponse] | type[SubjectTagChangesResponse],
    token: str,
    match: UUID,
    key: str,
) -> Any:
    """Page with ``cursor`` until the item whose ``key`` is ``match`` arrives.

    Only one step is kept; it records the pages read, whether every page had a
    ``next_cursor`` and whether revisions ascended across all of them.
    """
    cursor: str | None = None
    last_revision = 0
    ascending = True
    for page in range(1, MAX_PAGES + 1):
        query = urlencode(
            {"limit": SUBJECT_PAGE_MAX_LIMIT, **({"cursor": cursor} if cursor else {})}
        )
        changes = recorder.expect(
            name,
            client.call("GET", f"{path}?{query}", token=token),
            status={200},
            model=model,
        )
        for item in changes.items:
            ascending = ascending and item.revision > last_revision
            last_revision = item.revision
        found = next((item for item in changes.items if getattr(item, key) == match), None)
        cursor_returned = bool(changes.next_cursor)
        if found is not None or not changes.has_more or not cursor_returned or not ascending:
            recorder.note(
                pages=page, found=found is not None, revisions_ascending=ascending,
                next_cursor_returned=cursor_returned,
                **({"revision": found.revision} if found is not None else {}),
            )
            if found is None or not ascending or not cursor_returned:
                recorder.note(passed=False)
                raise SmokeFailure(name)
            return found
        cursor = changes.next_cursor
        recorder.steps.pop()
    # The scan cap, not the server, ended the search.
    recorder.note(pages=MAX_PAGES, found=False, cap_reached=True, passed=False)
    raise SmokeFailure(name)


def _patch(
    client: Client, token: str, subject_uuid: UUID, key: str, request: SubjectPatchRequest
) -> tuple[int, dict[str, Any]]:
    return client.call(
        "PATCH", f"/v1/subjects/{subject_uuid}", token=token,
        headers={"Idempotency-Key": key},
        body=request.model_dump(mode="json", exclude_none=True),
    )


def _profile(weight_kg: float) -> dict[str, Any]:
    return {"weight_kg": {"state": "PROVIDED", "value": weight_kg}}


def _validate(model: type[BaseModel], payload: Any) -> Any:
    try:
        return model.model_validate(payload)
    except ValidationError:
        return None


def _archive_after_failure(client: Client, recorder: Recorder, state: dict[str, Any]) -> None:
    """Best effort: keep a failed run's subject out of the active roster.

    Never changes the recorded failed step. A stale revision is retried once
    with the server's current one.
    """
    if state.get("subject_uuid") is None or state.get("subject_archived"):
        return
    # Before the download there is no known revision; the conflict supplies it.
    revision = state.get("subject_revision", 1)
    for _ in range(2):
        try:
            status, body = _patch(
                client, state["token"], state["subject_uuid"], f"{LABEL}-archive-{uuid4()}",
                SubjectPatchRequest(
                    base_revision=revision, status=SubjectEditableStatus.ARCHIVED
                ),
            )
        except (OSError, ValueError):
            return
        if not isinstance(body, dict):
            return
        try:
            recorder.expect("cleanup_subject_archive", (status, body), status={200})
            return
        except SmokeFailure:
            current = _validate(
                SubjectRecord, ((body.get("error") or {}).get("details") or {}).get("current")
            )
            if current is None:
                return
            revision = current.revision


def run(args: argparse.Namespace, password: str) -> dict[str, Any]:
    client = Client(args.base_url, args.ca_file)
    recorder = Recorder()
    state: dict[str, Any] = {}
    run_tag = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    # Synthetic, unique per run; none of them may reach the evidence.
    display_name = f"RAY907 Smoke {secrets.token_hex(6)}"
    external_id = f"SMOKE-{run_tag}-{secrets.token_hex(4)}"
    tag_name = f"{LABEL}-{secrets.token_hex(4)}"
    sensitive = [password, args.account_name, display_name, external_id]
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
            f"{LABEL}-{run_tag}",
        )
        token = terminal.access_token
        installation_id = terminal.client_installation_id
        state.update(token=token, installation_id=installation_id)
        sensitive += [token, terminal.refresh_token, str(terminal.tenant_id)]

        subject_uuid = uuid4()
        # Set before the call: a create that commits but fails here is still archived.
        state["subject_uuid"] = subject_uuid
        created = recorder.expect(
            "subject_create",
            client.call(
                "POST", "/v1/subjects", token=token,
                headers={"Idempotency-Key": f"{LABEL}-subject-{subject_uuid}",
                         "X-Terminal-ID": str(installation_id)},
                body=SubjectCreateRequest(
                    subject_uuid=subject_uuid,
                    external_identifier=ExternalIdentifierInput(
                        issuer=LABEL, id_type="smoke_subject", external_id=external_id
                    ),
                    identity_profile=IdentityProfileInput(display_name=display_name),
                    analysis_profile=_profile(60.0),
                ).model_dump(mode="json", exclude_none=True),
            ),
            status={201},
            model=SubjectSummary,
        )
        recorder.note(subject_uuid=str(created.subject_uuid))

        downloaded: SubjectRecord = _page_until(
            client, recorder, "subject_download", "/v1/subjects", SubjectChangesResponse,
            token, subject_uuid, "subject_uuid",
        )
        base_revision = downloaded.revision
        state["subject_revision"] = base_revision

        patch_key = f"{LABEL}-patch-{uuid4()}"
        patch_request = SubjectPatchRequest(
            base_revision=base_revision, analysis_profile=_profile(61.5)
        )
        patched = recorder.expect(
            "subject_patch",
            _patch(client, token, subject_uuid, patch_key, patch_request),
            status={200},
            model=SubjectRecord,
        )
        state["subject_revision"] = patched.revision
        recorder.note(base_revision=base_revision, revision=patched.revision)
        if patched.revision <= base_revision:
            recorder.note(passed=False)
            raise SmokeFailure("subject_patch")

        replayed = recorder.expect(
            "subject_patch_replay",
            _patch(client, token, subject_uuid, patch_key, patch_request),
            status={200},
            model=SubjectRecord,
        )
        recorder.note(revision=replayed.revision, identical=replayed == patched)
        if replayed != patched:
            recorder.note(passed=False)
            raise SmokeFailure("subject_patch_replay")

        recorder.expect(
            "subject_patch_key_reused",
            _patch(client, token, subject_uuid, patch_key, SubjectPatchRequest(
                base_revision=base_revision, analysis_profile=_profile(62.0)
            )),
            status={409},
            error_code="E-API-409",
        )

        status, body = _patch(
            client, token, subject_uuid, f"{LABEL}-stale-{uuid4()}",
            SubjectPatchRequest(base_revision=base_revision, analysis_profile=_profile(63.0)),
        )
        recorder.expect(
            "subject_patch_stale_revision", (status, body), status={409},
            error_code="E-SUB-409-REVISION-CONFLICT",
        )
        current = _validate(
            SubjectRecord, ((body.get("error") or {}).get("details") or {}).get("current")
        )
        recorder.note(
            base_revision=base_revision,
            current_valid=current is not None,
            current_revision=getattr(current, "revision", None),
        )
        if current is None or current != patched:
            recorder.note(passed=False)
            raise SmokeFailure("subject_patch_stale_revision")

        search = recorder.expect(
            "subject_search_by_name",
            client.call(
                "POST", "/v1/subjects/search-by-name", token=token,
                body=SubjectNameSearchRequest(display_name=display_name).model_dump(mode="json"),
            ),
            status={200},
            model=SubjectNameSearchResponse,
        )
        found = any(item.subject_uuid == subject_uuid for item in search.items)
        recorder.note(matches=len(search.items), found=found)
        if not found:
            recorder.note(passed=False)
            raise SmokeFailure("subject_search_by_name")

        tag_id = uuid4()
        tag = recorder.expect(
            "tag_create",
            client.call(
                "POST", "/v1/subject-tags", token=token,
                headers={"Idempotency-Key": f"{LABEL}-tag-{tag_id}"},
                body=SubjectTagCreateRequest(tag_id=tag_id, name=tag_name).model_dump(mode="json"),
            ),
            status={201},
            model=SubjectTagCreateResponse,
        )
        recorder.note(tag_id=str(tag.tag.tag_id), conflict=tag.conflict, revision=tag.tag.revision)
        if tag.conflict or tag.tag.tag_id != tag_id:
            recorder.note(passed=False)
            raise SmokeFailure("tag_create")

        # Case folding makes the upper-case spelling the same normalized name.
        other_id = uuid4()
        conflict = recorder.expect(
            "tag_create_name_conflict",
            client.call(
                "POST", "/v1/subject-tags", token=token,
                headers={"Idempotency-Key": f"{LABEL}-tag-{other_id}"},
                body=SubjectTagCreateRequest(
                    tag_id=other_id, name=tag_name.upper()
                ).model_dump(mode="json"),
            ),
            status={200},
            model=SubjectTagCreateResponse,
        )
        recorder.note(tag_id=str(conflict.tag.tag_id), conflict=conflict.conflict)
        if not conflict.conflict or conflict.tag != tag.tag:
            recorder.note(passed=False)
            raise SmokeFailure("tag_create_name_conflict")

        tagged = recorder.expect(
            "subject_patch_tags",
            _patch(client, token, subject_uuid, f"{LABEL}-tags-{uuid4()}", SubjectPatchRequest(
                base_revision=patched.revision, tag_ids=(tag_id,)
            )),
            status={200},
            model=SubjectRecord,
        )
        state["subject_revision"] = tagged.revision
        recorder.note(
            base_revision=patched.revision, revision=tagged.revision,
            tag_ids=[str(value) for value in tagged.tag_ids],
        )
        if tagged.tag_ids != (tag_id,) or tagged.revision <= patched.revision:
            recorder.note(passed=False)
            raise SmokeFailure("subject_patch_tags")

        _page_until(
            client, recorder, "tag_download", "/v1/subject-tags", SubjectTagChangesResponse,
            token, tag_id, "tag_id",
        )

        # Keep the institution's roster clean: the smoke subject is archived.
        archived = recorder.expect(
            "subject_archive",
            _patch(client, token, subject_uuid, f"{LABEL}-archive-{uuid4()}", SubjectPatchRequest(
                base_revision=tagged.revision, status=SubjectEditableStatus.ARCHIVED
            )),
            status={200},
            model=SubjectRecord,
        )
        recorder.note(revision=archived.revision, subject_status=archived.status)
        if archived.status != SubjectStatus.ARCHIVED or archived.revision <= tagged.revision:
            recorder.note(passed=False)
            raise SmokeFailure("subject_archive")
        state["subject_archived"] = True

        revoked = recorder.expect(
            "cleanup_terminal_self_revoke",
            client.call("POST", f"/v1/access/terminals/{installation_id}/revoke", token=token),
            status={200},
            model=TerminalSummary,
        )
        state["terminal_revoked"] = True
        recorder.note(terminal_status=revoked.status)

        recorder.expect(
            "subject_download_after_revoke",
            client.call("GET", "/v1/subjects", token=token),
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
            try:
                _archive_after_failure(client, recorder, state)
            finally:
                # The seat is returned even when archiving raises.
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
    print(f"subject_sync_smoke={summary['result']} output={args.output} secrets=not-printed")
    return 0 if summary["result"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
