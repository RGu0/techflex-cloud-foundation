"""The 0.9.1 public DTOs retain their terminal-only admission boundary."""
from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from techflex_cloud_foundation.contracts.client_sync import canonical_sha256
from techflex_cloud_foundation.contracts.registered import (
    RegisteredManifest,
    RegisteredSegmentMetadata,
    RegisteredSessionRequest,
)
from techflex_cloud_foundation.object_store import InMemoryObjectStore
from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.ingestion_service import IngestionService
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.repository import InMemoryPlatformRepository
from techflex_cloud_foundation.server.segment_store import SegmentObjectStore
from tests.test_registry_ingestion_http import documents


@pytest.mark.parametrize("direct_repository", [False, True])
@pytest.mark.parametrize("terminal_access,has_site,accepted", [
    (False, False, False), (True, True, False), (True, False, True),
])
def test_public_session_admission(direct_repository, terminal_access, has_site, accepted):
    async def run():
        tenant, terminal = uuid4(), uuid4()
        site = uuid4() if has_site else None
        context = IngestionPrincipal(
            tenant, terminal, datetime.now(UTC) + timedelta(hours=1), True, True,
            terminal_access=terminal_access,
        )
        repository = InMemoryPlatformRepository()
        repository.add_terminal(tenant, site, terminal)
        service = IngestionService(repository, SegmentObjectStore(InMemoryObjectStore()))
        document, metadata, manifest, payload = documents(terminal)
        document["site_id"] = str(site) if site else None
        request = RegisteredSessionRequest.model_validate(document)
        target = repository if direct_repository else service
        if not accepted:
            with pytest.raises(TenantAccessDenied):
                await target.create_session(context, request, "public")
            return
        await target.create_session(context, request, "public")
        parsed_metadata = RegisteredSegmentMetadata.model_validate(metadata)
        if direct_repository:
            await repository.register_segment(context, request.session_id, parsed_metadata, "part")
        else:
            async def chunks():
                yield payload
            await service.put_segment(context, request.session_id, 0, parsed_metadata, chunks())
        parsed_manifest = RegisteredManifest.model_validate(manifest)
        if direct_repository:
            result = await repository.complete_manifest(
                context, request.session_id, parsed_manifest, canonical_sha256(manifest),
                "manifest", "complete", eligibility_reason="registered",
                eligibility_policy_version="1",
                completed_at=datetime.now(UTC),
            )
        else:
            result = await service.complete_session(
                context, request.session_id, parsed_manifest, canonical_sha256(manifest), "complete"
            )
        assert result.ingest_status.value == "INGESTED"
    asyncio.run(run())


def test_public_manifest_rejects_schema_absent_from_injected_registry():
    from techflex_cloud_foundation.payload_contracts import PayloadSchemaRegistry
    from techflex_cloud_foundation.platform_errors import SchemaUnsupported
    from techflex_cloud_foundation.server.ingestion_contracts import adapt_public_registered

    _, _, manifest, _ = documents(uuid4())
    value = RegisteredManifest.model_validate(manifest)
    with pytest.raises(SchemaUnsupported):
        adapt_public_registered(value, registry=PayloadSchemaRegistry())
