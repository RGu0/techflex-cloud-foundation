"""RAY-120 D10: the platform identity endpoint reads through the hardened reader."""

from __future__ import annotations

from contextlib import asynccontextmanager
import unittest
from unittest.mock import patch
from uuid import uuid4

from techflex_cloud_foundation.contracts.cloud import IdentityProfileInput
from techflex_cloud_foundation.platform_errors import RepositoryUnavailable
from techflex_cloud_foundation.server.identity_recovery import postgres as recovery_postgres
from techflex_cloud_foundation.server.subject_service import IdentityProtector


class _Connection:
    def __init__(self, row):
        self.row = row
        self.queries: list[str] = []

    async def fetchrow(self, query, *args):
        self.queries.append(query)
        return self.row


def _transaction(connection):
    @asynccontextmanager
    async def transaction(pool, tenant_id):
        yield connection

    return transaction


class D10IdentityReaderTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.tenant, self.subject = uuid4(), uuid4()
        self.protector = IdentityProtector(
            encryption_key=b"e" * 32, lookup_hmac_key=b"h" * 32, key_version="identity/1",
        )

    def _row(self, subject):
        protected = self.protector.protect_identity_profile(
            IdentityProfileInput(display_name="Ada Wu", contact="+86 13900001111"),
            tenant_id=str(self.tenant), subject_uuid=str(subject),
        )
        return {
            "identity_ciphertext": protected.ciphertext,
            "encryption_nonce": protected.nonce,
            "key_version": protected.key_version,
        }

    async def _read(self, row):
        connection = _Connection(row)
        reader = recovery_postgres.PostgresRecoveryIdentityReader(object(), self.protector)
        with patch.object(recovery_postgres, "tenant_transaction", _transaction(connection)):
            result = await reader.read_identity(self.tenant, self.subject)
        return result, connection

    async def test_only_active_subjects_are_read(self) -> None:
        result, connection = await self._read(None)
        self.assertEqual(result, (None, None))
        self.assertIn("s.status='ACTIVE'", connection.queries[0])

    async def test_matching_profile_decrypts_once(self) -> None:
        result, _ = await self._read(self._row(self.subject))
        self.assertEqual(result, ("Ada Wu", "+86 13900001111"))

    async def test_decrypt_failure_is_masked_without_identity_data(self) -> None:
        # A profile bound to another subject fails authentication on decrypt.
        with self.assertRaises(RepositoryUnavailable) as raised:
            await self._read(self._row(uuid4()))
        self.assertIsNone(raised.exception.__cause__)
        self.assertNotIn("Ada", str(raised.exception))
        self.assertNotIn("13900001111", str(raised.exception))
