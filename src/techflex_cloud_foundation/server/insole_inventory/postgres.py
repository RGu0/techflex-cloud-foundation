"""PostgreSQL persistence for the institutional insole inventory (RAY-778).

Uses the activation role pool, as terminal management does, inside an
RLS-scoped tenant transaction. ``writer`` first locks the tenant's revision
counter row; every write of that tenant waits on it, which makes commit order
equal revision order.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
import hashlib
from typing import Any, cast
from uuid import UUID

from techflex_cloud_foundation.contracts.insole_inventory import (
    InsoleHolder,
    InsoleIdentity,
    InsoleIdentityKind,
    InsoleNode,
    InsoleRecord,
    InsoleState,
    StoredBatteryReading,
)
from techflex_cloud_foundation.server.postgres import tenant_transaction

from .repository import RegistrationKeyRecord


def insole_device_serial_hmac(insole_id: UUID) -> bytes:
    # device.devices is UNIQUE NULLS NOT DISTINCT on (tenant_id, serial_hmac),
    # so each projected pair needs its own non-null, non-identifying value.
    return hashlib.sha256(b"insole-pair:" + insole_id.bytes).digest()


async def _project_insole(connection: Any, tenant_id: UUID, record: InsoleRecord) -> None:
    """RAY-728 D3/D5: mirror an insole pair into device.devices.

    ``screening.sessions.device_id`` references device.devices; a terminal
    session may name an ACTIVE projection only, so retirement follows.
    """
    await connection.execute(
        """INSERT INTO device.devices
           (device_id,tenant_id,model,serial_hmac,capabilities,status,created_at,updated_at)
           VALUES ($1,$2,'insole-pair',$3,'{}'::jsonb,$4,$5,$5)
           ON CONFLICT (device_id) DO UPDATE
           SET status=EXCLUDED.status,
               updated_at=GREATEST(device.devices.updated_at,EXCLUDED.updated_at)
           WHERE device.devices.model='insole-pair'
             AND device.devices.tenant_id=EXCLUDED.tenant_id""",
        record.insole_id,
        tenant_id,
        insole_device_serial_hmac(record.insole_id),
        "RETIRED" if record.state is InsoleState.RETIRED else "ACTIVE",
        record.updated_at,
    )


def _node(row: Any, side: str) -> InsoleNode:
    battery = None
    if row[f"{side}_battery_read_at"] is not None:
        battery = StoredBatteryReading(
            millivolts=row[f"{side}_battery_millivolts"],
            percent=row[f"{side}_battery_percent"],
            read_at=row[f"{side}_battery_read_at"],
            reported_by_client_installation_id=row[f"{side}_battery_reported_by"],
        )
    return InsoleNode(
        identity=InsoleIdentity(
            kind=InsoleIdentityKind(row[f"{side}_identity_kind"]),
            value=row[f"{side}_identity_value"],
            provenance=row[f"{side}_identity_provenance"],
        ),
        firmware_version=row[f"{side}_firmware_version"],
        battery=battery,
    )


def _record(row: Any) -> InsoleRecord:
    holder = None
    if row["holder_client_installation_id"] is not None:
        holder = InsoleHolder(
            client_installation_id=row["holder_client_installation_id"],
            terminal_name=row["holder_terminal_name"],
        )
    return InsoleRecord(
        insole_id=row["insole_id"],
        institution_number=row["institution_number"],
        size=row["size"],
        left=_node(row, "left"),
        right=_node(row, "right"),
        state=InsoleState(row["state"]),
        state_observed_at=row["state_observed_at"],
        holder=holder,
        registered_at=row["registered_at"],
        registered_by_client_installation_id=row["registered_by"],
        retired_at=row["retired_at"],
        retired_by_client_installation_id=row["retired_by"],
        revision=row["revision"],
        updated_at=row["updated_at"],
    )


def _side_values(node: InsoleNode) -> tuple[Any, ...]:
    battery = node.battery
    return (
        node.identity.kind.value,
        node.identity.value,
        node.identity.provenance,
        node.firmware_version,
        None if battery is None else battery.millivolts,
        None if battery is None else battery.percent,
        None if battery is None else battery.read_at,
        None if battery is None else battery.reported_by_client_installation_id,
    )


def _values(record: InsoleRecord) -> tuple[Any, ...]:
    holder = record.holder
    return (
        record.insole_id,
        record.institution_number,
        record.size,
        *_side_values(record.left),
        *_side_values(record.right),
        record.state.value,
        record.state_observed_at,
        None if holder is None else holder.client_installation_id,
        None if holder is None else holder.terminal_name,
        record.registered_at,
        record.registered_by_client_installation_id,
        record.retired_at,
        record.retired_by_client_installation_id,
        record.revision,
        record.updated_at,
    )


_COLUMNS = (
    "insole_id,institution_number,size,"
    "left_identity_kind,left_identity_value,left_identity_provenance,left_firmware_version,"
    "left_battery_millivolts,left_battery_percent,left_battery_read_at,left_battery_reported_by,"
    "right_identity_kind,right_identity_value,right_identity_provenance,right_firmware_version,"
    "right_battery_millivolts,right_battery_percent,right_battery_read_at,"
    "right_battery_reported_by,"
    "state,state_observed_at,holder_client_installation_id,holder_terminal_name,"
    "registered_at,registered_by,retired_at,retired_by,revision,updated_at"
)
_COLUMN_NAMES = _COLUMNS.split(",")
# $1 is tenant_id; record values follow from $2.
_PLACEHOLDERS = ",".join(f"${index}" for index in range(2, len(_COLUMN_NAMES) + 2))
# Identities, number and registration never change after insert.
_IMMUTABLE = frozenset(
    {
        "insole_id",
        "institution_number",
        "size",
        "registered_at",
        "registered_by",
        "left_identity_kind",
        "left_identity_value",
        "left_identity_provenance",
        "right_identity_kind",
        "right_identity_value",
        "right_identity_provenance",
    }
)
_MUTABLE = tuple(
    (position, name) for position, name in enumerate(_COLUMN_NAMES) if name not in _IMMUTABLE
)
# $1 is tenant_id, $2 insole_id; mutable values follow from $3.
_ASSIGNMENTS = ",".join(f"{name}=${index}" for index, (_, name) in enumerate(_MUTABLE, start=3))


class _PostgresWriteTransaction:
    def __init__(self, connection: Any, tenant_id: UUID) -> None:
        self._connection = connection
        self._tenant_id = tenant_id

    async def registration_key(
        self, client_installation_id: UUID, idempotency_key: str
    ) -> RegistrationKeyRecord | None:
        row = await self._connection.fetchrow(
            "SELECT request_sha256,insole_id FROM device.insole_registration_keys "
            "WHERE client_installation_id=$1 AND idempotency_key=$2",
            client_installation_id,
            idempotency_key,
        )
        if row is None:
            return None
        return RegistrationKeyRecord(
            request_sha256=bytes(row["request_sha256"]), insole_id=row["insole_id"]
        )

    async def save_registration_key(
        self, client_installation_id: UUID, idempotency_key: str, record: RegistrationKeyRecord
    ) -> None:
        await self._connection.execute(
            "INSERT INTO device.insole_registration_keys "
            "(tenant_id,client_installation_id,idempotency_key,request_sha256,insole_id) "
            "VALUES ($1,$2,$3,$4,$5)",
            self._tenant_id,
            client_installation_id,
            idempotency_key,
            record.request_sha256,
            record.insole_id,
        )

    async def by_identity(self, kind: InsoleIdentityKind, value: str) -> InsoleRecord | None:
        row = await self._connection.fetchrow(
            "SELECT pair.* FROM device.insole_identities identity "
            "JOIN device.insole_pairs pair "
            "ON pair.tenant_id=identity.tenant_id AND pair.insole_id=identity.insole_id "
            "WHERE identity.identity_kind=$1 AND identity.identity_value=$2",
            kind.value,
            value,
        )
        return None if row is None else _record(row)

    async def by_number(self, institution_number: str) -> InsoleRecord | None:
        row = await self._connection.fetchrow(
            "SELECT * FROM device.insole_pairs WHERE institution_number=$1",
            institution_number,
        )
        return None if row is None else _record(row)

    async def get_for_update(self, insole_id: UUID) -> InsoleRecord | None:
        row = await self._connection.fetchrow(
            "SELECT * FROM device.insole_pairs WHERE insole_id=$1 FOR UPDATE", insole_id
        )
        return None if row is None else _record(row)

    async def next_revision(self) -> int:
        return cast(
            int,
            await self._connection.fetchval(
                "UPDATE device.insole_revision_counters SET last_revision=last_revision+1 "
                "WHERE tenant_id=$1 RETURNING last_revision",
                self._tenant_id,
            ),
        )

    async def insert(self, record: InsoleRecord) -> None:
        await self._connection.execute(
            f"INSERT INTO device.insole_pairs (tenant_id,{_COLUMNS}) VALUES ($1,{_PLACEHOLDERS})",
            self._tenant_id,
            *_values(record),
        )
        await self._connection.executemany(
            "INSERT INTO device.insole_identities "
            "(tenant_id,identity_kind,identity_value,insole_id,side) VALUES ($1,$2,$3,$4,$5)",
            [
                (
                    self._tenant_id,
                    node.identity.kind.value,
                    node.identity.value,
                    record.insole_id,
                    side,
                )
                for side, node in (("left", record.left), ("right", record.right))
            ],
        )
        await _project_insole(self._connection, self._tenant_id, record)

    async def update(self, record: InsoleRecord) -> None:
        values = _values(record)
        await self._connection.execute(
            f"UPDATE device.insole_pairs SET {_ASSIGNMENTS} WHERE tenant_id=$1 AND insole_id=$2",
            self._tenant_id,
            record.insole_id,
            *(values[position] for position, _ in _MUTABLE),
        )
        await _project_insole(self._connection, self._tenant_id, record)


class PostgresInsoleInventoryRepository:
    def __init__(self, activation_pool: Any) -> None:
        if activation_pool is None:
            raise ValueError("activation_pool is required")
        self._pool = activation_pool

    @asynccontextmanager
    async def writer(self, tenant_id: UUID) -> AsyncIterator[_PostgresWriteTransaction]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            await connection.execute(
                "INSERT INTO device.insole_revision_counters (tenant_id) VALUES ($1) "
                "ON CONFLICT (tenant_id) DO NOTHING",
                tenant_id,
            )
            await connection.execute(
                "SELECT last_revision FROM device.insole_revision_counters "
                "WHERE tenant_id=$1 FOR UPDATE",
                tenant_id,
            )
            yield _PostgresWriteTransaction(connection, tenant_id)

    async def get(self, tenant_id: UUID, insole_id: UUID) -> InsoleRecord | None:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            row = await connection.fetchrow(
                "SELECT * FROM device.insole_pairs WHERE insole_id=$1", insole_id
            )
        return None if row is None else _record(row)

    async def changes(
        self, tenant_id: UUID, *, after_revision: int, limit: int
    ) -> tuple[InsoleRecord, ...]:
        async with tenant_transaction(self._pool, tenant_id) as connection:
            rows = await connection.fetch(
                "SELECT * FROM device.insole_pairs WHERE revision>$1 ORDER BY revision LIMIT $2",
                after_revision,
                limit,
            )
        return tuple(_record(row) for row in rows)


__all__ = ["PostgresInsoleInventoryRepository"]
