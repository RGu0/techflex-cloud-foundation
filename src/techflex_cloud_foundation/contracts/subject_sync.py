"""Versioned institutional subject sync contracts (RAY-907 R1).

Every terminal of an institution shares one subject roster. Terminals
download it incrementally, edit a subject with whole-record optimistic
concurrency, look a subject up by exact display name and share one tag
dictionary.

Download (R1): a subject is never deleted. Archiving is a status, so an
archived subject is delivered like any other change and the client hides it.
The record carries ``display_name`` (D1) but never ``contact`` (D2), and the
institution number only masked (D3).

Edit (R1 D4): ``base_revision`` must equal the stored ``revision``; otherwise
the server answers ``E-SUB-409-REVISION-CONFLICT`` with the current record and
merges nothing. ``analysis_profile`` merges per field; ``identity_profile``
and ``tag_ids`` replace the stored value; a new ``external_identifier``
supersedes the active one.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Final
from uuid import UUID

from pydantic import Field, StringConstraints, field_validator, model_validator

from .cloud import (
    ContractModel,
    ExternalIdentifierInput,
    IdentityProfileInput,
    ProfileValue,
    SchemaVersion,
)

SUBJECT_CURSOR_SCHEMA: Final = "subject-cursor/1"
SUBJECT_TAG_CURSOR_SCHEMA: Final = "subject-tag-cursor/1"
SUBJECT_PAGE_DEFAULT_LIMIT: Final = 100
SUBJECT_PAGE_MAX_LIMIT: Final = 500
SUBJECT_NAME_SEARCH_MAX_RESULTS: Final = 20
SUBJECT_TAGS_MAX: Final = 64
SUBJECT_TAG_NAME_MAX_LENGTH: Final = 32

Revision = Annotated[int, Field(gt=0)]
DisplayName = Annotated[str, StringConstraints(min_length=1, max_length=256)]
TagName = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=SUBJECT_TAG_NAME_MAX_LENGTH
    ),
]


class SubjectStatus(StrEnum):
    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"
    MERGED = "MERGED"
    RESTRICTED = "RESTRICTED"


class SubjectEditableStatus(StrEnum):
    """The statuses a terminal may set; MERGED and RESTRICTED are server-side."""

    ACTIVE = "ACTIVE"
    ARCHIVED = "ARCHIVED"


class SubjectExternalIdentifier(ContractModel):
    """The active institution number, masked; look a number up with resolve."""

    external_identifier_id: UUID
    issuer: str
    id_type: str
    external_id_masked: str


class SubjectIdentity(ContractModel):
    """Identity downlinked to the institution's own terminals (D1); no contact."""

    display_name: DisplayName


class SubjectConsentRecord(ContractModel):
    consent_record_id: UUID
    policy_version: str
    purpose_codes: tuple[str, ...]
    data_categories: tuple[str, ...]
    evidence_type: str
    granted_at: datetime
    revoked_at: datetime | None = None
    revocation_reason_code: str | None = None


class SubjectRecord(ContractModel):
    subject_uuid: UUID
    # Tenant-wide, strictly increasing change sequence; the download cursor and
    # the PATCH ``base_revision``.
    revision: Revision
    status: SubjectStatus
    merged_into_subject_uuid: UUID | None = None
    external_identifier: SubjectExternalIdentifier | None = None
    # Absent when none is stored, when it holds no display name, for MERGED
    # and RESTRICTED subjects, and when it cannot be decrypted.
    identity_profile: SubjectIdentity | None = None
    analysis_profile: dict[str, ProfileValue] = Field(default_factory=dict)
    profile_schema_version: SchemaVersion
    tag_ids: tuple[UUID, ...] = ()
    consents: tuple[SubjectConsentRecord, ...] = ()
    created_at: datetime
    # Server time of the last change; informational, never a cursor.
    updated_at: datetime


class SubjectChangesResponse(ContractModel):
    """One page of changes ordered by ``revision``.

    Pass ``next_cursor`` back as ``cursor``; it is returned on every page, also
    the last one, and is opaque. ``has_more`` says whether to fetch again now.
    """

    items: tuple[SubjectRecord, ...]
    next_cursor: str
    has_more: bool


class SubjectPatchRequest(ContractModel):
    base_revision: Revision
    external_identifier: ExternalIdentifierInput | None = None
    identity_profile: IdentityProfileInput | None = None
    analysis_profile: dict[str, ProfileValue] | None = None
    profile_schema_version: SchemaVersion | None = None
    tag_ids: Annotated[tuple[UUID, ...], Field(max_length=SUBJECT_TAGS_MAX)] | None = None
    status: SubjectEditableStatus | None = None

    @field_validator("tag_ids")
    @classmethod
    def unique_tags(cls, value: tuple[UUID, ...] | None) -> tuple[UUID, ...] | None:
        if value is not None and len(set(value)) != len(value):
            raise ValueError("tag_ids must be unique")
        return value

    @model_validator(mode="after")
    def not_empty(self) -> SubjectPatchRequest:
        if all(
            getattr(self, name) is None
            for name in (
                "external_identifier", "identity_profile", "analysis_profile",
                "profile_schema_version", "tag_ids", "status",
            )
        ):
            raise ValueError("a patch must change at least one field")
        return self


class SubjectNameSearchRequest(ContractModel):
    """Exact lookup after NFKC, trimming and case folding; never a prefix match."""

    display_name: DisplayName


class SubjectNameSearchResponse(ContractModel):
    """ACTIVE and ARCHIVED matches, at most ``SUBJECT_NAME_SEARCH_MAX_RESULTS``."""

    items: tuple[SubjectRecord, ...]


class SubjectTag(ContractModel):
    tag_id: UUID
    name: TagName
    created_at: datetime
    # Tenant-wide tag sequence, independent of subject revisions.
    revision: Revision


class SubjectTagCreateRequest(ContractModel):
    tag_id: UUID
    name: TagName


class SubjectTagCreateResponse(ContractModel):
    """``conflict`` is true when the normalized name already names ``tag``."""

    tag: SubjectTag
    conflict: bool


class SubjectTagChangesResponse(ContractModel):
    items: tuple[SubjectTag, ...]
    next_cursor: str
    has_more: bool


__all__ = [
    "SUBJECT_CURSOR_SCHEMA",
    "SUBJECT_NAME_SEARCH_MAX_RESULTS",
    "SUBJECT_PAGE_DEFAULT_LIMIT",
    "SUBJECT_PAGE_MAX_LIMIT",
    "SUBJECT_TAGS_MAX",
    "SUBJECT_TAG_CURSOR_SCHEMA",
    "SUBJECT_TAG_NAME_MAX_LENGTH",
    "SubjectChangesResponse",
    "SubjectConsentRecord",
    "SubjectEditableStatus",
    "SubjectExternalIdentifier",
    "SubjectIdentity",
    "SubjectNameSearchRequest",
    "SubjectNameSearchResponse",
    "SubjectPatchRequest",
    "SubjectRecord",
    "SubjectStatus",
    "SubjectTag",
    "SubjectTagChangesResponse",
    "SubjectTagCreateRequest",
    "SubjectTagCreateResponse",
]
