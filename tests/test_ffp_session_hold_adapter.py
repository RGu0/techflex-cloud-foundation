from __future__ import annotations

import unittest
from uuid import uuid4

from techflex_cloud_foundation.platform_errors import RequestContractError
from techflex_cloud_foundation.server.session_hold.adapter import run_with_current_hold
from techflex_cloud_foundation.server.session_hold.service import SessionHeld


class AuthoritativeHoldAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_queued_work_rechecks_hold_at_processing_time(self) -> None:
        tenant, session = uuid4(), uuid4()
        queued_event = (str(tenant), str(session))

        class Holds:
            held = False
            reads = 0

            async def is_held(self, tenant_id, session_id):
                self.reads += 1
                self.assertions.append((tenant_id, session_id))
                return self.held

            def __init__(self):
                self.assertions = []

        holds = Holds()
        calls = []
        first = await run_with_current_hold(
            holds, *queued_event,
            lambda reader: calls.append(reader.is_held(*queued_event)),
        )
        self.assertIsNone(first)
        self.assertEqual(calls, [False])
        holds.held = True
        with self.assertRaises(SessionHeld):
            await run_with_current_hold(
                holds, *queued_event,
                lambda reader: calls.append(reader.is_held(*queued_event)),
            )
        self.assertEqual(holds.reads, 2)
        self.assertEqual(holds.assertions, [(tenant, session), (tenant, session)])
        self.assertEqual(calls, [False])

    async def test_checked_reader_rejects_cross_session_use(self) -> None:
        tenant, session = uuid4(), uuid4()

        class Holds:
            async def is_held(self, tenant_id, session_id):
                return False

        with self.assertRaises(RequestContractError):
            await run_with_current_hold(
                Holds(), tenant, session,
                lambda reader: reader.is_held(tenant, uuid4()),
            )
