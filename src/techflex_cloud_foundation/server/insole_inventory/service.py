"""Institutional insole inventory: registration, reports, retirement, download.

RAY-778 R1. Any ACTIVE terminal of the institution may register, report and
retire; the inventory is scoped by tenant and never bound to a terminal. All
merge and conflict rules live here, once, over the repository's per-tenant
write transaction.
"""

from __future__ import annotations

import base64
import binascii
from datetime import UTC, datetime, timedelta
import hashlib
from typing import Any, cast
from uuid import UUID, uuid4

from techflex_cloud_foundation.contracts.client_sync import canonical_json_bytes
from techflex_cloud_foundation.contracts.insole_inventory import (
    INSOLE_CURSOR_SCHEMA,
    INSOLE_PAGE_DEFAULT_LIMIT,
    INSOLE_PAGE_MAX_LIMIT,
    INSOLE_READING_MAX_FUTURE_SKEW_SECONDS,
    BatteryReading,
    InsoleChangesResponse,
    InsoleHolder,
    InsoleNode,
    InsoleRecord,
    InsoleRegistrationRequest,
    InsoleRegistrationResponse,
    InsoleReportApplied,
    InsoleReportRequest,
    InsoleReportResponse,
    InsoleRetireResponse,
    InsoleState,
    StoredBatteryReading,
)
from techflex_cloud_foundation.contracts.terminal_access import TerminalState
from techflex_cloud_foundation.platform_errors import (
    IdempotencyConflict,
    InsoleCursorInvalid,
    InsoleIdentityRegistered,
    InsoleNumberTaken,
    InsoleReadingInFuture,
    InsoleRetired,
    RequestContractError,
    ResourceNotFound,
    TerminalRevoked,
)
from techflex_cloud_foundation.server.access_auth import TerminalAccessContext
from techflex_cloud_foundation.server.access_control.repository import TerminalRecord

from .repository import InsoleInventoryRepository, InsoleWriteTransaction, RegistrationKeyRecord

# Revisions are PostgreSQL bigint.
_MAX_REVISION = 2**63 - 1


def encode_cursor(revision: int) -> str:
    raw = f"{INSOLE_CURSOR_SCHEMA}:{revision}".encode("ascii")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def decode_cursor(cursor: str | None) -> int:
    if cursor is None or cursor == "":
        return 0
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InsoleCursorInvalid("cursor is not a valid insole cursor") from exc
    schema, separator, value = raw.partition(":")
    if (
        schema != INSOLE_CURSOR_SCHEMA
        or not separator
        or not value.isascii()
        or not value.isdigit()
        or int(value) > _MAX_REVISION
    ):
        raise InsoleCursorInvalid("cursor is not a valid insole cursor")
    return int(value)


class InsoleInventoryService:
    _MAX_FUTURE_SKEW = timedelta(seconds=INSOLE_READING_MAX_FUTURE_SKEW_SECONDS)

    def __init__(
        self, repository: InsoleInventoryRepository, terminals: Any, *, now: Any = None
    ) -> None:
        self._repository = repository
        # Any object with ``async terminal(client_installation_id)``; the
        # access repository in production.
        self._terminals = terminals
        self._now = now or (lambda: datetime.now(UTC))

    async def _caller(self, context: TerminalAccessContext) -> TerminalRecord:
        terminal = await self._terminals.terminal(context.client_installation_id)
        if (
            terminal is None
            or terminal.tenant_id != context.tenant_id
            or terminal.account_id != context.account_id
            or terminal.status != TerminalState.ACTIVE.value
        ):
            raise TerminalRevoked("terminal was revoked")
        return cast(TerminalRecord, terminal)

    async def register(
        self,
        context: TerminalAccessContext,
        request: InsoleRegistrationRequest,
        idempotency_key: str,
    ) -> tuple[InsoleRegistrationResponse, bool]:
        """Return the response and whether a new pair was created."""

        caller = await self._caller(context)
        digest = hashlib.sha256(canonical_json_bytes(request)).digest()
        now = self._now()
        async with self._repository.writer(caller.tenant_id) as tx:
            previous = await tx.registration_key(caller.client_installation_id, idempotency_key)
            if previous is not None:
                if previous.request_sha256 != digest:
                    raise IdempotencyConflict(
                        "Idempotency-Key was used for a different registration"
                    )
                replayed = await tx.get_for_update(previous.insole_id)
                if replayed is None:  # pragma: no cover - pairs are never deleted
                    raise ResourceNotFound("insole does not exist")
                return InsoleRegistrationResponse(insole=replayed, idempotent_replay=True), False
            existing = await self._existing_pair(tx, request)
            if existing is None:
                record = InsoleRecord(
                    insole_id=uuid4(),
                    institution_number=request.institution_number,
                    size=request.size,
                    left=InsoleNode(
                        identity=request.left.identity,
                        firmware_version=request.left.firmware_version,
                    ),
                    right=InsoleNode(
                        identity=request.right.identity,
                        firmware_version=request.right.firmware_version,
                    ),
                    state=InsoleState.AVAILABLE,
                    registered_at=now,
                    registered_by_client_installation_id=caller.client_installation_id,
                    revision=await tx.next_revision(),
                    updated_at=now,
                )
                await tx.insert(record)
            else:
                record = existing
            await tx.save_registration_key(
                caller.client_installation_id,
                idempotency_key,
                RegistrationKeyRecord(request_sha256=digest, insole_id=record.insole_id),
            )
        return (
            InsoleRegistrationResponse(insole=record, idempotent_replay=existing is not None),
            existing is None,
        )

    @staticmethod
    async def _existing_pair(
        tx: InsoleWriteTransaction, request: InsoleRegistrationRequest
    ) -> InsoleRecord | None:
        """The already registered identical pair, or None; conflicts raise.

        An identity owned by a pair with another number is checked first (left,
        then right), then a number owned by a pair with other identities. A
        pair matching on number and both identities is the same pair: the
        stored size and firmware are kept and it is returned as a replay.
        """

        for node in (request.left, request.right):
            owner = await tx.by_identity(node.identity.kind, node.identity.value)
            if owner is not None and owner.institution_number != request.institution_number:
                raise InsoleIdentityRegistered(
                    "identity is registered under another institution number",
                    existing=owner.model_dump(mode="json"),
                )
        owner = await tx.by_number(request.institution_number)
        if owner is None:
            return None
        if (_device(owner.left), _device(owner.right)) != (
            _device(request.left),
            _device(request.right),
        ):
            raise InsoleNumberTaken(
                "institution number is registered to other identities",
                existing=owner.model_dump(mode="json"),
            )
        return owner

    def _not_in_future(self, moment: datetime, *, now: datetime) -> None:
        if moment > now + self._MAX_FUTURE_SKEW:
            raise InsoleReadingInFuture("device-side time is ahead of server time")

    async def report(
        self,
        context: TerminalAccessContext,
        insole_id: UUID,
        request: InsoleReportRequest,
    ) -> InsoleReportResponse:
        caller = await self._caller(context)
        now = self._now()
        for moment in (
            None if request.state is None else request.state.observed_at,
            None if request.left is None else request.left.read_at,
            None if request.right is None else request.right.read_at,
        ):
            if moment is not None:
                self._not_in_future(moment, now=now)
        async with self._repository.writer(caller.tenant_id) as tx:
            record = await tx.get_for_update(insole_id)
            if record is None:
                raise ResourceNotFound("insole does not exist")
            if record.state is InsoleState.RETIRED:
                raise InsoleRetired("insole is retired")
            changes: dict[str, object] = {}
            state_applied = request.state is not None and (
                record.state_observed_at is None
                or request.state.observed_at > record.state_observed_at
            )
            if state_applied:
                assert request.state is not None
                state = InsoleState(request.state.state.value)
                changes["state"] = state
                changes["state_observed_at"] = request.state.observed_at.astimezone(UTC)
                changes["holder"] = (
                    InsoleHolder(
                        client_installation_id=caller.client_installation_id,
                        terminal_name=caller.terminal_name,
                    )
                    if state is InsoleState.IN_USE
                    else None
                )
            left = _merge_battery(record.left, request.left, caller.client_installation_id)
            right = _merge_battery(record.right, request.right, caller.client_installation_id)
            if left is not None:
                changes["left"] = left
            if right is not None:
                changes["right"] = right
            if changes:
                changes["revision"] = await tx.next_revision()
                changes["updated_at"] = now
                record = record.model_copy(update=changes)
                await tx.update(record)
        return InsoleReportResponse(
            insole=record,
            applied=InsoleReportApplied(
                state=state_applied, left=left is not None, right=right is not None
            ),
        )

    async def retire(self, context: TerminalAccessContext, insole_id: UUID) -> InsoleRetireResponse:
        caller = await self._caller(context)
        now = self._now()
        async with self._repository.writer(caller.tenant_id) as tx:
            record = await tx.get_for_update(insole_id)
            if record is None:
                raise ResourceNotFound("insole does not exist")
            if record.state is InsoleState.RETIRED:
                return InsoleRetireResponse(insole=record, idempotent_replay=True)
            record = record.model_copy(
                update={
                    "state": InsoleState.RETIRED,
                    "holder": None,
                    "retired_at": now,
                    "retired_by_client_installation_id": caller.client_installation_id,
                    "revision": await tx.next_revision(),
                    "updated_at": now,
                }
            )
            await tx.update(record)
        return InsoleRetireResponse(insole=record, idempotent_replay=False)

    async def changes(
        self,
        context: TerminalAccessContext,
        *,
        cursor: str | None,
        limit: int | None,
    ) -> InsoleChangesResponse:
        caller = await self._caller(context)
        after = decode_cursor(cursor)
        page_size = INSOLE_PAGE_DEFAULT_LIMIT if limit is None else limit
        if not 1 <= page_size <= INSOLE_PAGE_MAX_LIMIT:
            raise RequestContractError(f"limit must be between 1 and {INSOLE_PAGE_MAX_LIMIT}")
        rows = await self._repository.changes(
            caller.tenant_id, after_revision=after, limit=page_size + 1
        )
        items = rows[:page_size]
        return InsoleChangesResponse(
            items=items,
            next_cursor=encode_cursor(items[-1].revision if items else after),
            has_more=len(rows) > page_size,
        )


def _device(node: Any) -> tuple[str, str]:
    return (node.identity.kind.value, node.identity.value)


def _merge_battery(
    node: InsoleNode, reading: BatteryReading | None, reporter: UUID
) -> InsoleNode | None:
    """The node with the newer reading, or None when the stored one stands."""

    if reading is None:
        return None
    if node.battery is not None and reading.read_at <= node.battery.read_at:
        return None
    return node.model_copy(
        update={
            "battery": StoredBatteryReading(
                millivolts=reading.millivolts,
                percent=reading.percent,
                read_at=reading.read_at.astimezone(UTC),
                reported_by_client_installation_id=reporter,
            )
        }
    )


__all__ = ["InsoleInventoryService", "decode_cursor", "encode_cursor"]
