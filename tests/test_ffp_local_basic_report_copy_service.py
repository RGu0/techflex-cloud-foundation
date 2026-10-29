"""Every report-copy access rechecks the current session hold."""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from techflex_cloud_foundation.platform_errors import TenantAccessDenied
from techflex_cloud_foundation.server.report_copy.models import LocalBasicCopyRecord
from techflex_cloud_foundation.server.report_copy.service import LocalBasicCopyService


class _Repo:
    def __init__(self, record):
        self.record = record
        self.read_count = 0
        self.audit = []

    async def list_for_tenant(self, tenant_id):
        return (self.record,)

    async def get(self, tenant_id, report_id):
        return self.record

    async def read_pdf(self, record):
        self.read_count += 1
        return b"%PDF-1.4\n%%EOF"

    async def audit_access(self, tenant_id, session_id, actor_id, action, outcome):
        self.audit.append((action, outcome))


class _Holds:
    held = False

    async def is_held(self, tenant_id, session_id):
        return self.held


def test_hold_committed_after_list_blocks_direct_read_and_export() -> None:
    async def exercise():
        tenant_id, session_id, actor_id = uuid4(), uuid4(), uuid4()
        record = LocalBasicCopyRecord(
            tenant_id, session_id, "basic-a", 1, "LOCAL_BASIC_COPY", "{}",
            "a" * 64, "b" * 64, "private/key", 15,
        )
        repo, holds = _Repo(record), _Holds()
        service = LocalBasicCopyService(repo, holds)
        assert len(await service.list_for_tenant(tenant_id, actor_id)) == 1
        holds.held = True
        assert await service.list_for_tenant(tenant_id, actor_id) == ()
        with pytest.raises(TenantAccessDenied):
            await service.get(tenant_id, actor_id, "basic-a")
        with pytest.raises(TenantAccessDenied):
            await service.export_pdf(tenant_id, actor_id, "basic-a")
        assert repo.read_count == 0
        assert ("report-copy.read", "DENIED") in repo.audit
        assert ("report-copy.export", "DENIED") in repo.audit
    asyncio.run(exercise())
