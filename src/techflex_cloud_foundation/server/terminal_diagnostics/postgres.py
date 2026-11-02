"""PostgreSQL persistence for terminal diagnostic packages (RAY-802).

Uploads write through the activation role pool, as the insole inventory
does; Platform support reads and the purge's tombstone update go through the
platform role pool. Both run inside an RLS-scoped tenant transaction.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from techflex_cloud_foundation.server.postgres import pool_transaction, tenant_transaction

from .repository import DiagnosticRecord

_COLUMNS = (
    "diagnostic_id,tenant_id,client_installation_id,idempotency_key,format,"
    "size_bytes,sha256,object_key,received_at,expires_at,deleted_at"
)


def _record(row: Any) -> DiagnosticRecord:
    return DiagnosticRecord(
        diagnostic_id=row["diagnostic_id"],
        tenant_id=row["tenant_id"],
        client_installation_id=row["client_installation_id"],
        idempotency_key=row["idempotency_key"],
        format=row["format"],
        size_bytes=row["size_bytes"],
        sha256=row["sha256"],
        object_key=row["object_key"],
        received_at=row["received_at"],
        expires_at=row["expires_at"],
        deleted_at=row["deleted_at"],
    )


class PostgresDiagnosticRepository:
    def __init__(self, activation_pool: Any, platform_pool: Any) -> None:
        if activation_pool is None or platform_pool is None:
            raise ValueError("activation_pool and platform_pool are required")
        self._activation = activation_pool
        self._platform = platform_pool

    async def by_key(
        self, tenant_id: UUID, client_installation_id: UUID, idempotency_key: str
    ) -> DiagnosticRecord | None:
        async with tenant_transaction(self._activation, tenant_id) as connection:
            row = await connection.fetchrow(
                f"SELECT {_COLUMNS} FROM ops.terminal_diagnostics "
                "WHERE client_installation_id=$1 AND idempotency_key=$2",
                client_installation_id, idempotency_key,
            )
        return None if row is None else _record(row)

    async def insert(self, record: DiagnosticRecord) -> DiagnosticRecord:
        async with tenant_transaction(self._activation, record.tenant_id) as connection:
            inserted = await connection.fetchrow(
                f"INSERT INTO ops.terminal_diagnostics ({_COLUMNS}) "
                "VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) "
                "ON CONFLICT (tenant_id,client_installation_id,idempotency_key) DO NOTHING "
                f"RETURNING {_COLUMNS}",
                record.diagnostic_id, record.tenant_id, record.client_installation_id,
                record.idempotency_key, record.format, record.size_bytes, record.sha256,
                record.object_key, record.received_at, record.expires_at, record.deleted_at,
            )
            if inserted is not None:
                return _record(inserted)
            existing = await connection.fetchrow(
                f"SELECT {_COLUMNS} FROM ops.terminal_diagnostics "
                "WHERE client_installation_id=$1 AND idempotency_key=$2",
                record.client_installation_id, record.idempotency_key,
            )
        return _record(existing)

    async def list(self, tenant_id: UUID) -> tuple[DiagnosticRecord, ...]:
        async with tenant_transaction(self._platform, tenant_id) as connection:
            rows = await connection.fetch(
                f"SELECT {_COLUMNS} FROM ops.terminal_diagnostics "
                "ORDER BY received_at DESC, diagnostic_id DESC"
            )
        return tuple(_record(row) for row in rows)

    async def get(self, tenant_id: UUID, diagnostic_id: UUID) -> DiagnosticRecord | None:
        async with tenant_transaction(self._platform, tenant_id) as connection:
            row = await connection.fetchrow(
                f"SELECT {_COLUMNS} FROM ops.terminal_diagnostics WHERE diagnostic_id=$1",
                diagnostic_id,
            )
        return None if row is None else _record(row)

    async def expired(self, now: datetime) -> tuple[DiagnosticRecord, ...]:
        # iam.tenants is tenant-scoped under RLS; the access resource directory
        # is the cross-tenant index. A tenant with packages has an account.
        async with pool_transaction(self._platform) as connection:
            tenants: list[UUID] = [
                row["tenant_id"]
                for row in await connection.fetch(
                    "SELECT DISTINCT tenant_id FROM ops.access_resource_directory "
                    "ORDER BY tenant_id"
                )
            ]
        records: list[DiagnosticRecord] = []
        for tenant_id in tenants:
            async with tenant_transaction(self._platform, tenant_id) as connection:
                rows = await connection.fetch(
                    f"SELECT {_COLUMNS} FROM ops.terminal_diagnostics "
                    "WHERE deleted_at IS NULL AND expires_at<=$1 ORDER BY expires_at",
                    now,
                )
            records.extend(_record(row) for row in rows)
        return tuple(records)

    async def mark_deleted(
        self, tenant_id: UUID, diagnostic_id: UUID, deleted_at: datetime
    ) -> None:
        async with tenant_transaction(self._platform, tenant_id) as connection:
            await connection.execute(
                "UPDATE ops.terminal_diagnostics SET deleted_at=$2 "
                "WHERE diagnostic_id=$1 AND deleted_at IS NULL",
                diagnostic_id, deleted_at,
            )


__all__ = ["PostgresDiagnosticRepository"]
