"""Institution report-copy API and live hold behavior."""

from __future__ import annotations

import asyncio
import base64
from datetime import UTC, datetime
from uuid import uuid4

from httpx import ASGITransport, AsyncClient

from techflex_cloud_foundation.contracts.access_control import AccessCapabilities
from techflex_cloud_foundation.server.access_auth import TenantAccessTokenIssuer
from techflex_cloud_foundation.server.app import ServiceContainer, create_app
from techflex_cloud_foundation.server.report_copy.models import LocalBasicCopyReceipt
from techflex_cloud_foundation.server.report_copy.service import LocalBasicCopyService
from tests.test_ffp_local_basic_report_copy import copy_request


def test_upload_list_read_and_export_then_hold_denies_direct_links() -> None:
    async def exercise():
        request = copy_request()
        tenant_id, account_id, terminal_id = uuid4(), uuid4(), uuid4()

        class Repo:
            record = None
            pdf = b""
            audits = []

            async def accept(self, context, copy, key):
                assert context.tenant_id == tenant_id
                assert context.terminal_id == terminal_id
                assert copy.session_id == request.session_id
                assert key == "stable-key"
                from techflex_cloud_foundation.server.report_copy.models import LocalBasicCopyRecord
                self.record = LocalBasicCopyRecord(
                    tenant_id, copy.session_id, copy.report_id, 1, "LOCAL_BASIC_COPY",
                    copy.document_json, copy.document_sha256, copy.pdf_sha256,
                    "private", len(copy.pdf_bytes),
                )
                self.pdf = copy.pdf_bytes
                return LocalBasicCopyReceipt(copy.report_id, 1, copy.document_sha256, copy.pdf_sha256)

            async def list_for_tenant(self, tenant):
                return (self.record,) if self.record else ()

            async def get(self, tenant, report_id):
                return self.record

            async def read_pdf(self, record):
                return self.pdf

            async def audit_access(self, tenant, session, actor, action, outcome):
                self.audits.append((action, outcome))

        class Holds:
            held = False

            async def is_held(self, tenant, session):
                return self.held

        repo, holds = Repo(), Holds()
        issuer = TenantAccessTokenIssuer(secret=b"x" * 32, key_id="test/1")
        token = issuer.issue(
            tenant_id=tenant_id, account_id=account_id, license_id=uuid4(),
            hardware_id="usb-serial-ffffffffffffffffffff", client_installation_id=terminal_id,
            token_version=1, capabilities=AccessCapabilities(
                allow_new_test=False, allow_upload=True, allow_report_view=True,
            ), now=datetime.now(UTC),
        )
        headers = {"Authorization": f"Bearer {token}"}
        app = create_app(ServiceContainer(
            tenant_tokens=issuer, report_copies=LocalBasicCopyService(repo, holds),
        ))
        async with AsyncClient(transport=ASGITransport(app=app), base_url="https://cloud.test") as client:
            body = {
                "report_id": request.report_id, "version": 1, "source": "LOCAL_BASIC_COPY",
                "document_json": request.document_json,
                "pdf_base64": base64.b64encode(request.pdf_bytes).decode(),
                "document_sha256": request.document_sha256, "pdf_sha256": request.pdf_sha256,
                "consent_record_id": str(request.consent_record_id),
            }
            upload = await client.post(
                f"/v1/sessions/{request.session_id}/basic-report-copy",
                headers={**headers, "Idempotency-Key": "stable-key"}, json=body,
            )
            assert upload.status_code == 201, upload.text
            listed = await client.get("/v1/reports", headers=headers)
            assert listed.status_code == 200
            assert listed.headers["cache-control"] == "no-store"
            assert listed.headers["x-content-type-options"] == "nosniff"
            assert listed.json()["data"][0]["source"] == "LOCAL_BASIC_COPY"
            direct = f"/v1/reports/{request.report_id}/versions/1"
            detail = await client.get(direct, headers=headers)
            assert detail.status_code == 200
            assert detail.headers["cache-control"] == "no-store"
            assert detail.headers["x-content-type-options"] == "nosniff"
            pdf = await client.get(direct + "/pdf", headers=headers)
            assert pdf.status_code == 200
            assert pdf.content == request.pdf_bytes
            assert pdf.headers["content-type"] == "application/pdf"
            assert pdf.headers["cache-control"] == "no-store"
            assert pdf.headers["x-content-type-options"] == "nosniff"
            holds.held = True
            assert (await client.get("/v1/reports", headers=headers)).json()["data"] == []
            assert (await client.get(direct, headers=headers)).status_code == 403
            assert (await client.get(direct + "/pdf", headers=headers)).status_code == 403
            assert ("report-copy.export", "DENIED") in repo.audits
            oversized = await client.post(
                f"/v1/sessions/{request.session_id}/basic-report-copy",
                headers={**headers, "Idempotency-Key": "oversize"},
                content=b"x" * (12 * 1024 * 1024 + 1),
            )
            assert oversized.status_code == 400
            assert oversized.headers["cache-control"] == "no-store"
            assert oversized.headers["x-content-type-options"] == "nosniff"
        unavailable = create_app(ServiceContainer(tenant_tokens=issuer))
        async with AsyncClient(transport=ASGITransport(app=unavailable), base_url="https://cloud.test") as client:
            absent = await client.get("/v1/reports", headers=headers)
            assert absent.status_code == 503
            assert absent.headers["cache-control"] == "no-store"
            assert absent.headers["x-content-type-options"] == "nosniff"
    asyncio.run(exercise())
