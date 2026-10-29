"""Report-copy upload must bind to the finalized tenant session and stay immutable."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import hashlib
import json
from uuid import uuid4

import pytest

from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    RequestContractError,
    SessionHeldForReportCopy,
    TenantAccessDenied,
)
from techflex_cloud_foundation.server.principal import IngestionPrincipal
from techflex_cloud_foundation.server.report_copy.postgres import PostgresLocalBasicCopyRepository
from tests.test_ffp_local_basic_report_copy import copy_request


class _Transaction:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return None


class _Connection:
    def __init__(self, *, request, terminal_id, tenant_id):
        self.request, self.terminal_id, self.tenant_id = request, terminal_id, tenant_id
        self.ingest_status = "INGESTED"
        self.validity_status = "VALID"
        self.consent_active = True
        self.held = False
        self.copy = None
        self.subject_id = uuid4()
        self.session_consent_id = request.consent_record_id
        document = json.loads(request.document_json)
        self.protocol_id = document["protocol_id"]
        self.protocol_version = document["protocol_version"]

    def transaction(self):
        return _Transaction()

    async def execute(self, sql, *args):
        if "INSERT INTO reporting.local_basic_report_copies" in sql:
            self.copy = dict(
                tenant_id=args[0], session_id=args[1], report_id=args[2], version=args[3],
                source="LOCAL_BASIC_COPY", document_json=args[7], document_sha256=args[8],
                pdf_sha256=args[9], pdf_object_key=args[10], pdf_size_bytes=args[11],
                idempotency_key_sha256=args[12], consent_record_id=args[5],
            )

    async def fetchrow(self, sql, *args):
        if "FROM screening.sessions" in sql:
            return dict(
                tenant_id=self.tenant_id, session_id=self.request.session_id,
                terminal_id=self.terminal_id, subject_uuid=self.subject_id,
                consent_record_id=self.session_consent_id,
                ingest_status=self.ingest_status, validity_status=self.validity_status,
                test_protocol_id=self.protocol_id, test_protocol_version=self.protocol_version,
            ) if args[0] == self.tenant_id and args[1] == self.request.session_id else None
        if "FROM subject.consents" in sql:
            assert "ARRAY['SCREENING','SCREENING_SERVICE']" in sql
            return {"consent_record_id": self.request.consent_record_id} if self.consent_active else None
        if "FROM reporting.local_basic_report_copies" in sql:
            return self.copy
        return None

    async def fetchval(self, sql, *args):
        if "ops.session_holds" in sql:
            return self.held
        return None


class _Pool:
    def __init__(self, connection):
        self.connection = connection

    def acquire(self):
        class _Lease:
            async def __aenter__(_self):
                return self.connection

            async def __aexit__(_self, *_):
                return None
        return _Lease()


class _Objects:
    def __init__(self):
        self.put_count = 0
        self.deleted = []

    async def put(self, tenant_id, session_id, pdf):
        self.put_count += 1
        return type("Stored", (), {"object_key": f"private/{uuid4()}"})()

    async def delete(self, key):
        self.deleted.append(key)


def _setup():
    request = copy_request()
    tenant_id, terminal_id = uuid4(), uuid4()
    connection = _Connection(request=request, tenant_id=tenant_id, terminal_id=terminal_id)
    objects = _Objects()
    repo = PostgresLocalBasicCopyRepository(_Pool(connection), objects)
    principal = IngestionPrincipal(
        tenant_id=tenant_id, terminal_id=terminal_id,
        expires_at=datetime.now(UTC) + timedelta(minutes=5),
        allow_new_test=False, allow_upload=True,
    )
    return repo, principal, request, connection, objects


def test_accepts_bound_copy_and_idempotent_retry() -> None:
    async def exercise():
        repo, principal, request, db, objects = _setup()
        first = await repo.accept(principal, request, "same-key")
        second = await repo.accept(principal, request, "same-key")
        assert first == second
        assert objects.put_count == 1
        assert db.copy["pdf_object_key"].startswith("private/")
    asyncio.run(exercise())


@pytest.mark.parametrize("failure", ["incomplete", "invalid", "revoked", "held", "terminal", "consent"])
def test_rejects_unusable_or_unbound_session(failure: str) -> None:
    async def exercise():
        repo, principal, request, db, objects = _setup()
        if failure == "incomplete":
            db.ingest_status = "RECEIVING"
        elif failure == "invalid":
            db.validity_status = "INVALID"
        elif failure == "revoked":
            db.consent_active = False
        elif failure == "held":
            db.held = True
        elif failure == "consent":
            db.session_consent_id = uuid4()
        else:
            db.terminal_id = uuid4()
        with pytest.raises((RequestContractError, TenantAccessDenied, SessionHeldForReportCopy)):
            await repo.accept(principal, request, "key")
        assert objects.put_count == 0
    asyncio.run(exercise())


def test_changed_content_or_idempotency_key_conflicts() -> None:
    async def exercise():
        repo, principal, request, _, objects = _setup()
        await repo.accept(principal, request, "key")
        with pytest.raises(IdempotencyConflict):
            await repo.accept(principal, request, "different-key")
        changed_pdf = b"%PDF-1.4\nchanged\n%%EOF"
        with pytest.raises(IdempotencyConflict):
            await repo.accept(principal, replace(
                request, pdf_bytes=changed_pdf,
                pdf_sha256=hashlib.sha256(changed_pdf).hexdigest(),
            ), "key")
        assert objects.put_count == 1
    asyncio.run(exercise())


@pytest.mark.parametrize("field", ["protocol_id", "protocol_version"])
def test_rejects_report_for_another_session_protocol(field: str) -> None:
    async def exercise():
        repo, principal, request, db, objects = _setup()
        setattr(db, field, "a-different-protocol")
        with pytest.raises(RequestContractError, match="protocol binding"):
            await repo.accept(principal, request, "key")
        assert objects.put_count == 0
    asyncio.run(exercise())


def test_listing_filters_held_sessions_before_limit() -> None:
    class ListingConnection:
        async def fetch(self, sql, *_args):
            assert "NOT EXISTS" in sql
            assert "ops.session_holds" in sql
            assert "LIMIT 100" in sql
            return []

        def transaction(self):
            return _Transaction()

        async def execute(self, *_args):
            pass

    async def exercise():
        repo = PostgresLocalBasicCopyRepository(_Pool(ListingConnection()), _Objects())
        assert await repo.list_for_tenant(uuid4()) == ()
    asyncio.run(exercise())
