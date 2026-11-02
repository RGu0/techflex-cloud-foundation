"""Institutional subject sync: download, edit, name lookup and tags (RAY-907 R1).

Any ACTIVE terminal of the institution reads the shared roster; reads stay
available while the License is inactive, writes (PATCH, tag create) need a
usable License. Subject creation keeps the RAY-728 D6 rule (ACTIVE terminal
only) and is not routed through here. All conflict rules live here, once,
over the repository's per-tenant write transaction.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime
from typing import Any
import unicodedata
from uuid import UUID

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.subject_sync import (
    SUBJECT_CURSOR_SCHEMA,
    SUBJECT_NAME_SEARCH_MAX_RESULTS,
    SUBJECT_PAGE_DEFAULT_LIMIT,
    SUBJECT_PAGE_MAX_LIMIT,
    SUBJECT_TAG_CURSOR_SCHEMA,
    SubjectChangesResponse,
    SubjectIdentity,
    SubjectNameSearchRequest,
    SubjectNameSearchResponse,
    SubjectPatchRequest,
    SubjectRecord,
    SubjectStatus,
    SubjectTagChangesResponse,
    SubjectTagCreateRequest,
    SubjectTagCreateResponse,
)
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    ResourceNotFound,
    SubjectCursorInvalid,
    SubjectNotEditable,
    SubjectNumberTaken,
    SubjectRevisionConflict,
    SubjectUnknownTag,
)
from techflex_cloud_foundation.server.access_auth import TerminalAccessContext
from techflex_cloud_foundation.server.subject_service import IdentityProtector

from .repository import (
    IdempotencyEntry,
    IdentityChange,
    NameSearchAudit,
    NumberChange,
    StoredIdentity,
    StoredSubject,
    SubjectChanges,
    SubjectSyncRepository,
    SubjectWriteTransaction,
)

# Revisions are PostgreSQL bigint.
_MAX_REVISION = 2**63 - 1
PATCH_SCOPE = "subject.patch"
TAG_CREATE_SCOPE = "subject-tag.create"
_EDITABLE = (SubjectStatus.ACTIVE, SubjectStatus.ARCHIVED)
# Identity is downlinked only while the subject is in normal use.
_IDENTITY_VISIBLE = _EDITABLE


def encode_cursor(schema: str, revision: int) -> str:
    raw = f"{schema}:{revision}".encode("ascii")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(schema: str, cursor: str | None) -> int:
    if cursor is None or cursor == "":
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise SubjectCursorInvalid("cursor is not a valid cursor") from exc
    prefix, separator, value = raw.partition(":")
    if (
        prefix != schema
        or not separator
        or not value.isascii()
        or not value.isdigit()
        or int(value) > _MAX_REVISION
    ):
        raise SubjectCursorInvalid("cursor is not a valid cursor")
    return int(value)


def tag_name_key(name: str) -> str:
    """One tag per name after NFKC, trimming and case folding."""

    return unicodedata.normalize("NFKC", name).strip().casefold()


def _page_size(limit: int | None) -> int:
    size = SUBJECT_PAGE_DEFAULT_LIMIT if limit is None else limit
    if not 1 <= size <= SUBJECT_PAGE_MAX_LIMIT:
        raise RequestContractError(f"limit must be between 1 and {SUBJECT_PAGE_MAX_LIMIT}")
    return size


class SubjectSyncService:
    def __init__(
        self,
        repository: SubjectSyncRepository,
        terminal_access: Any,
        identity: IdentityProtector,
        *,
        now: Any = None,
    ) -> None:
        self._repository = repository
        # TerminalAccessService: ``active_terminal`` for reads,
        # ``writable_terminal`` (also checks the License) for writes.
        self._terminals = terminal_access
        self._identity = identity
        self._now = now or (lambda: datetime.now(UTC))

    def _record(self, tenant_id: UUID, stored: StoredSubject) -> SubjectRecord:
        return SubjectRecord(
            subject_uuid=stored.subject_uuid,
            revision=stored.revision,
            status=stored.status,
            merged_into_subject_uuid=stored.merged_into_subject_uuid,
            external_identifier=stored.external_identifier,
            identity_profile=(
                self._display_identity(tenant_id, stored)
                if stored.status in _IDENTITY_VISIBLE
                else None
            ),
            analysis_profile=stored.analysis_profile,
            profile_schema_version=stored.profile_schema_version,
            tag_ids=stored.tag_ids,
            consents=stored.consents,
            created_at=stored.created_at,
            updated_at=stored.updated_at,
        )

    def _display_identity(self, tenant_id: UUID, stored: StoredSubject) -> SubjectIdentity | None:
        if stored.identity is None:
            return None
        try:
            profile = self._identity.unprotect_identity_profile(
                stored.identity.ciphertext,
                stored.identity.nonce,
                stored.identity.key_version,
                tenant_id=str(tenant_id),
                subject_uuid=str(stored.subject_uuid),
            )
        except Exception:  # noqa: BLE001 - one unreadable profile must not fail a page
            return None
        if profile.display_name is None:
            return None
        return SubjectIdentity(display_name=profile.display_name)

    async def changes(
        self, context: TerminalAccessContext, *, cursor: str | None, limit: int | None
    ) -> SubjectChangesResponse:
        caller = await self._terminals.active_terminal(context)
        after = decode_cursor(SUBJECT_CURSOR_SCHEMA, cursor)
        size = _page_size(limit)
        rows = await self._repository.changes(
            caller.tenant_id, after_revision=after, limit=size + 1
        )
        items = rows[:size]
        return SubjectChangesResponse(
            items=tuple(self._record(caller.tenant_id, row) for row in items),
            next_cursor=encode_cursor(
                SUBJECT_CURSOR_SCHEMA, items[-1].revision if items else after
            ),
            has_more=len(rows) > size,
        )

    async def search_by_name(
        self,
        context: TerminalAccessContext,
        request: SubjectNameSearchRequest,
        *,
        correlation_id: UUID | None = None,
    ) -> SubjectNameSearchResponse:
        caller = await self._terminals.active_terminal(context)
        rows = await self._repository.search_by_name(
            caller.tenant_id,
            self._identity.name_digest(request.display_name, tenant_id=str(caller.tenant_id)),
            limit=SUBJECT_NAME_SEARCH_MAX_RESULTS,
            audit=NameSearchAudit(
                actor_id=caller.client_installation_id, correlation_id=correlation_id
            ),
        )
        return SubjectNameSearchResponse(
            items=tuple(self._record(caller.tenant_id, row) for row in rows)
        )

    async def patch(
        self,
        context: TerminalAccessContext,
        subject_uuid: UUID,
        request: SubjectPatchRequest,
        idempotency_key: str,
    ) -> SubjectRecord:
        caller = await self._terminals.writable_terminal(context)
        tenant_id = caller.tenant_id
        digest = canonical_sha256({"subject_uuid": str(subject_uuid), "patch": request})
        async with self._repository.subject_writer(tenant_id) as tx:
            await tx.lock_key(PATCH_SCOPE, idempotency_key)
            stored = await tx.lock_subject(subject_uuid)
            previous = await tx.idempotency(PATCH_SCOPE, idempotency_key)
            if previous is not None:
                if previous.request_sha256 != digest:
                    raise IdempotencyConflict(
                        "Idempotency-Key was used for a different request", scope=PATCH_SCOPE
                    )
                if stored is None:  # pragma: no cover - subjects are never deleted
                    raise ResourceNotFound("subject does not exist")
                # A replay answers with the subject's current record.
                return self._record(tenant_id, stored)
            if stored is None:
                raise ResourceNotFound("subject does not exist")
            if stored.status not in _EDITABLE:
                raise SubjectNotEditable("subject is merged or restricted")
            if stored.revision != request.base_revision:
                raise SubjectRevisionConflict(
                    "base_revision is not the current revision",
                    current=self._record(tenant_id, stored).model_dump(mode="json"),
                )
            if request.tag_ids:
                unknown = await tx.unknown_tags(request.tag_ids)
                if unknown:
                    raise SubjectUnknownTag("tag_ids name tags the institution does not have")
            changes = SubjectChanges(
                number=await self._number_change(tx, tenant_id, subject_uuid, request),
                identity=self._identity_change(tenant_id, subject_uuid, request),
                analysis_profile=(
                    None
                    if request.analysis_profile is None and request.profile_schema_version is None
                    else {**stored.analysis_profile, **(request.analysis_profile or {})}
                ),
                profile_schema_version=(
                    None
                    if request.analysis_profile is None and request.profile_schema_version is None
                    else request.profile_schema_version or stored.profile_schema_version
                ),
                tag_ids=None if request.tag_ids is None else tuple(sorted(request.tag_ids)),
                status=request.status,
            )
            updated = await tx.apply(subject_uuid, changes)
            await tx.save_idempotency(
                PATCH_SCOPE,
                idempotency_key,
                IdempotencyEntry(
                    request_sha256=digest,
                    response_status=200,
                    response={"subject_uuid": str(subject_uuid), "revision": updated.revision},
                ),
                subject_uuid,
            )
        return self._record(tenant_id, updated)

    async def _number_change(
        self, tx: SubjectWriteTransaction, tenant_id: UUID, subject_uuid: UUID,
        request: SubjectPatchRequest,
    ) -> NumberChange | None:
        external = request.external_identifier
        if external is None:
            return None
        protected = self._identity.protect(
            external.external_id,
            tenant_id=str(tenant_id),
            issuer=external.issuer,
            id_type=external.id_type,
        )
        owner = await tx.number_owner(external.issuer, external.id_type, protected.normalized_hmac)
        if owner is None:
            return NumberChange(external.issuer, external.id_type, protected)
        if owner.subject_uuid == subject_uuid:
            return None  # already this subject's active number
        raise SubjectNumberTaken(
            "institution number belongs to another subject",
            subject_uuid=str(owner.subject_uuid),
            external_id_masked=owner.external_id_masked,
        )

    def _identity_change(
        self, tenant_id: UUID, subject_uuid: UUID, request: SubjectPatchRequest
    ) -> IdentityChange | None:
        profile = request.identity_profile
        if profile is None:
            return None
        protected = self._identity.protect_identity_profile(
            profile, tenant_id=str(tenant_id), subject_uuid=str(subject_uuid)
        )
        return IdentityChange(
            protected=StoredIdentity(protected.ciphertext, protected.nonce, protected.key_version),
            # None (not searchable) without a display name or for a blank one.
            name_lookup_hmac=(
                None
                if profile.display_name is None
                else self._identity.name_digest(profile.display_name, tenant_id=str(tenant_id))
            ),
        )

    async def tag_changes(
        self, context: TerminalAccessContext, *, cursor: str | None, limit: int | None
    ) -> SubjectTagChangesResponse:
        caller = await self._terminals.active_terminal(context)
        after = decode_cursor(SUBJECT_TAG_CURSOR_SCHEMA, cursor)
        size = _page_size(limit)
        rows = await self._repository.tag_changes(
            caller.tenant_id, after_revision=after, limit=size + 1
        )
        items = rows[:size]
        return SubjectTagChangesResponse(
            items=items,
            next_cursor=encode_cursor(
                SUBJECT_TAG_CURSOR_SCHEMA, items[-1].revision if items else after
            ),
            has_more=len(rows) > size,
        )

    async def create_tag(
        self,
        context: TerminalAccessContext,
        request: SubjectTagCreateRequest,
        idempotency_key: str,
    ) -> tuple[SubjectTagCreateResponse, int]:
        """Return the response and its status: 201 created, 200 name conflict."""

        caller = await self._terminals.writable_terminal(context)
        digest = canonical_sha256(request)
        name_key = tag_name_key(request.name)
        async with self._repository.tag_writer(caller.tenant_id) as tx:
            previous = await tx.idempotency(TAG_CREATE_SCOPE, idempotency_key)
            if previous is not None:
                if previous.request_sha256 != digest:
                    raise IdempotencyConflict(
                        "Idempotency-Key was used for a different request",
                        scope=TAG_CREATE_SCOPE,
                    )
                stored = await tx.tag(UUID(previous.response["tag_id"]))
                if stored is None:  # pragma: no cover - tags are never deleted
                    raise ResourceNotFound("tag does not exist")
                return (
                    SubjectTagCreateResponse(
                        tag=stored[0], conflict=bool(previous.response["conflict"])
                    ),
                    previous.response_status,
                )
            same_id = await tx.tag(request.tag_id)
            if same_id is not None:
                tag, stored_key = same_id
                if stored_key != name_key:
                    raise IdempotencyConflict("tag_id already names another tag")
                response, status = SubjectTagCreateResponse(tag=tag, conflict=False), 201
            else:
                existing = await tx.tag_by_key(name_key)
                if existing is not None:
                    response, status = SubjectTagCreateResponse(tag=existing, conflict=True), 200
                else:
                    tag = await tx.insert_tag(
                        tag_id=request.tag_id,
                        name=request.name,
                        name_key=name_key,
                        created_by=caller.client_installation_id,
                        created_at=self._now(),
                    )
                    response, status = SubjectTagCreateResponse(tag=tag, conflict=False), 201
            await tx.save_idempotency(
                TAG_CREATE_SCOPE,
                idempotency_key,
                IdempotencyEntry(
                    request_sha256=digest,
                    response_status=status,
                    response={"tag_id": str(response.tag.tag_id), "conflict": response.conflict},
                ),
                response.tag.tag_id,
            )
        return response, status


__all__ = [
    "PATCH_SCOPE",
    "SubjectSyncService",
    "TAG_CREATE_SCOPE",
    "decode_cursor",
    "encode_cursor",
    "tag_name_key",
]
