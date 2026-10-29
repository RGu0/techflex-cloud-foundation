from __future__ import annotations

import unittest
from uuid import uuid4

from techflex_cloud_foundation.server.postgres import tenant_transaction


class FakeTransaction:
    def __init__(self, calls: list[tuple]) -> None:
        self.calls = calls

    async def __aenter__(self):
        self.calls.append(("transaction.enter",))
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        self.calls.append(("transaction.exit", exc_type))


class FakeConnection:
    def __init__(self, calls: list[tuple]) -> None:
        self.calls = calls

    def transaction(self) -> FakeTransaction:
        return FakeTransaction(self.calls)

    async def execute(self, query: str, *args):
        self.calls.append(("execute", " ".join(query.split()), *args))


class FakeAcquire:
    def __init__(self, connection: FakeConnection, calls: list[tuple]) -> None:
        self.connection = connection
        self.calls = calls

    async def __aenter__(self):
        self.calls.append(("acquire.enter",))
        return self.connection

    async def __aexit__(self, exc_type, exc, traceback):
        self.calls.append(("acquire.exit", exc_type))


class FakePool:
    def __init__(self) -> None:
        self.calls: list[tuple] = []
        self.connection = FakeConnection(self.calls)

    def acquire(self) -> FakeAcquire:
        return FakeAcquire(self.connection, self.calls)


class TenantTransactionTests(unittest.IsolatedAsyncioTestCase):
    async def test_sets_local_tenant_inside_transaction_before_yield(self) -> None:
        pool = FakePool()
        tenant_id = uuid4()

        async with tenant_transaction(pool, tenant_id) as connection:
            self.assertIs(connection, pool.connection)
            self.assertEqual(
                pool.calls,
                [
                    ("acquire.enter",),
                    ("transaction.enter",),
                    (
                        "execute",
                        "SELECT set_config('app.tenant_id', $1, true)",
                        str(tenant_id),
                    ),
                ],
            )

        self.assertEqual(pool.calls[-2:], [("transaction.exit", None), ("acquire.exit", None)])

    async def test_exception_rolls_back_before_connection_returns_to_pool(self) -> None:
        pool = FakePool()

        with self.assertRaisesRegex(RuntimeError, "boom"):
            async with tenant_transaction(pool, uuid4()):
                raise RuntimeError("boom")

        self.assertIs(pool.calls[-2][1], RuntimeError)
        self.assertIs(pool.calls[-1][1], RuntimeError)


if __name__ == "__main__":
    unittest.main()
