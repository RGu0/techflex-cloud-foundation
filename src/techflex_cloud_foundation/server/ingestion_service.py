from __future__ import annotations

from collections.abc import AsyncIterable
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from techflex_cloud_foundation.contracts.capture_grants import SessionAuthorization
from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.cloud import (
    MANIFEST_SCHEMA_FOR_PAYLOAD,
    AnySegmentMetadata,
    AnySessionManifest,
    ManifestCompletionResponse,
    ReceivedSegment,
    SegmentAcknowledgement,
    SegmentListResponse,
    SegmentReceiptStatus,
    SessionCreateRequest,
    SessionCreateResponse,
    SessionStatusResponse,
    ValidityStatus,
)
from techflex_cloud_foundation.platform_errors import (
    DigestMismatch,
    QualityGateRejected,
    SchemaUnsupported,
    SegmentDigestConflict,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.auth import TerminalContext
from techflex_cloud_foundation.server.principal import (
    IngestionPrincipal,
    coerce_ingestion_principal,
)
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore as ObjectStore

# CP-06 completion receipt: the eligibility decision recorded on every
# completed manifest. Bump the policy version when the gates change.
COMPLETION_ELIGIBILITY_POLICY_VERSION = "seed-completion-eligibility/1"
_COMPLETION_ELIGIBILITY_REASON = (
    "principal can_upload; manifest digest matched; schema supported; local quality gate VALID"
)


def _require_terminal_request(context: IngestionPrincipal, request: SessionCreateRequest) -> None:
    # RAY-728 D2/D4: an activated terminal creates sessions only as itself,
    # and terminal activation carries no site.
    if not context.terminal_access:
        return
    if (
        request.terminal_id != context.terminal_id
        or request.client_installation_id != context.terminal_id
    ):
        raise TenantAccessDenied("会话终端与终端凭据不一致", terminal_id=str(request.terminal_id))
    if request.site_id is not None:
        raise TenantAccessDenied("终端会话不支持站点")


class IngestionService:
    def __init__(
        self,
        repository: Any,
        object_store: ObjectStore,
        *,
        supported_payload_schemas: set[str],
        supported_manifest_schemas: set[str],
    ) -> None:
        self._repository = repository
        self._objects = object_store
        self._payload_schemas = frozenset(supported_payload_schemas)
        self._manifest_schemas = frozenset(supported_manifest_schemas)

    async def create_session(
        self,
        context: IngestionPrincipal | TerminalContext,
        request: SessionCreateRequest,
        idempotency_key: str,
        authorization: SessionAuthorization | None = None,
    ) -> SessionCreateResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        if request.versions.payload_schema not in self._payload_schemas:
            raise SchemaUnsupported(
                "客户端原始分段模式不受支持",
                schema_version=request.versions.payload_schema,
            )
        _require_terminal_request(context, request)
        return cast(
            "SessionCreateResponse",
            await self._repository.create_session(context, request, idempotency_key, authorization),
        )

    async def _session(self, context: IngestionPrincipal, session_id: UUID) -> Any:
        session = await self._repository.session(context, session_id)
        # RAY-728 D2: a terminal reads and writes only the sessions it created.
        if (
            context.terminal_access
            and session.request.client_installation_id != context.terminal_id
        ):
            raise TenantAccessDenied("会话不属于当前终端", session_id=str(session_id))
        return session

    async def put_segment(
        self,
        context: IngestionPrincipal | TerminalContext,
        session_id: UUID,
        route_index: int,
        metadata: AnySegmentMetadata,
        chunks: AsyncIterable[bytes],
    ) -> SegmentAcknowledgement:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        if route_index != metadata.segment_index:
            raise ValueError("route segment index must equal signed metadata index")
        if metadata.payload_schema_version not in self._payload_schemas:
            raise SchemaUnsupported(
                "分段模式不受支持", schema_version=metadata.payload_schema_version
            )
        session = await self._session(context, session_id)
        if session.request.versions.payload_schema != metadata.payload_schema_version:
            raise SchemaUnsupported(
                "分段模式与会话模式不一致",
                session_schema=session.request.versions.payload_schema,
                segment_schema=metadata.payload_schema_version,
            )
        existing = await self._repository.get_segment(context, session_id, route_index)
        if existing is not None:
            if existing.metadata.sha256 != metadata.sha256:
                await self._repository.mark_segment_conflict(context, session_id, route_index)
                raise SegmentDigestConflict(
                    "同一分段索引已存在不同内容",
                    session_id=str(session_id),
                    segment_index=route_index,
                )
            return SegmentAcknowledgement(
                session_id=session_id,
                index=route_index,
                sha256=metadata.sha256,
                status=SegmentReceiptStatus.ACKNOWLEDGED,
                object_key=existing.object_key,
                idempotent_replay=True,
            )
        stored = await self._objects.put_segment(context.tenant_id, session_id, metadata, chunks)
        try:
            record = await self._repository.register_segment(
                context, session_id, metadata, stored.object_key
            )
        except SegmentDigestConflict:
            if not await self._repository.object_is_referenced(
                context.tenant_id, stored.object_key
            ):
                await self._objects.delete(stored.object_key)
            await self._repository.mark_segment_conflict(context, session_id, route_index)
            raise
        except Exception:
            if not await self._repository.object_is_referenced(
                context.tenant_id, stored.object_key
            ):
                await self._objects.delete(stored.object_key)
            raise
        return SegmentAcknowledgement(
            session_id=session_id,
            index=route_index,
            sha256=metadata.sha256,
            status=SegmentReceiptStatus.ACKNOWLEDGED,
            object_key=record.object_key,
        )

    async def list_segments(
        self, context: IngestionPrincipal | TerminalContext, session_id: UUID
    ) -> SegmentListResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        if context.terminal_access:
            await self._session(context, session_id)
        accepted = await self._repository.list_segments(context, session_id)
        indices = [record.metadata.segment_index for record in accepted]
        expected_count = await self._repository.expected_segment_count(context, session_id)
        upper_bound = expected_count if expected_count is not None else max(indices, default=-1) + 1
        received_indices = set(indices)
        return SegmentListResponse(
            session_id=session_id,
            received=tuple(
                ReceivedSegment(
                    index=record.metadata.segment_index,
                    sha256=record.metadata.sha256,
                    status=SegmentReceiptStatus.ACKNOWLEDGED,
                )
                for record in accepted
            ),
            missing=tuple(index for index in range(upper_bound) if index not in received_indices),
        )

    async def complete_session(
        self,
        context: IngestionPrincipal | TerminalContext,
        session_id: UUID,
        manifest: AnySessionManifest,
        expected_sha256: str,
        idempotency_key: str,
    ) -> ManifestCompletionResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        actual_sha256 = canonical_sha256(manifest)
        if actual_sha256 != expected_sha256:
            raise DigestMismatch(
                "最终清单请求摘要不一致",
                expected=expected_sha256,
                actual=actual_sha256,
            )
        if manifest.schema_version not in self._manifest_schemas:
            raise SchemaUnsupported("最终清单模式不受支持", schema_version=manifest.schema_version)
        if manifest.local_quality_outcome is not ValidityStatus.VALID:
            raise QualityGateRejected(
                "未通过本地质量门控的会话不能启动正式分析",
                validity_status=manifest.local_quality_outcome.value,
            )
        session = await self._session(context, session_id)
        # RAY-825: a session completes only with its payload schema's manifest.
        session_schema = session.request.versions.payload_schema
        if MANIFEST_SCHEMA_FOR_PAYLOAD.get(session_schema) != manifest.schema_version:
            raise SchemaUnsupported(
                "最终清单模式与会话模式不一致",
                session_schema=session_schema,
                manifest_schema=manifest.schema_version,
            )
        stored = await self._objects.put_manifest(
            context.tenant_id, session_id, manifest, expected_sha256
        )
        try:
            return cast(
                "ManifestCompletionResponse",
                await self._repository.complete_manifest(
                    context,
                    session_id,
                    manifest,
                    expected_sha256,
                    stored.object_key,
                    idempotency_key,
                    eligibility_reason=_COMPLETION_ELIGIBILITY_REASON,
                    eligibility_policy_version=COMPLETION_ELIGIBILITY_POLICY_VERSION,
                    completed_at=datetime.now(UTC),
                ),
            )
        except Exception:
            if not await self._repository.object_is_referenced(
                context.tenant_id, stored.object_key
            ):
                await self._objects.delete(stored.object_key)
            raise

    async def get_status(
        self, context: IngestionPrincipal | TerminalContext, session_id: UUID
    ) -> SessionStatusResponse:
        context = coerce_ingestion_principal(context)
        context.ensure_can_upload()
        if context.terminal_access:
            await self._session(context, session_id)
        return cast("SessionStatusResponse", await self._repository.status(context, session_id))
