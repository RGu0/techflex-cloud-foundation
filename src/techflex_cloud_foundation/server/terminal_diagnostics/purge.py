"""Delete the content of expired diagnostic packages, keeping tombstones.

Run on the seed host with the seed environment, e.g.
``python -m techflex_cloud_foundation.server.terminal_diagnostics.purge``. It reads the
same ``FEETFORCEPLATE_*`` settings as the seed API, uses only the platform role
pool and the configured object store, and prints the number purged. On the
seed host ``feetforceplate-diagnostics-purge.timer`` runs it daily; the OSS
``diagnostics/`` lifecycle rule (RAY-927) is the backstop, not the mechanism.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
import json
from typing import Any

from techflex_cloud_foundation.server.seed import SeedSettings, build_object_store

from .postgres import PostgresDiagnosticRepository
from .service import TerminalDiagnosticsService


async def purge_expired(
    settings: SeedSettings,
    *,
    pool_factory: Callable[..., Any] | None = None,
    object_store_factory: Callable[[SeedSettings], Any] | None = None,
) -> int:
    if pool_factory is None:
        import asyncpg  # type: ignore[import-untyped]

        pool_factory = asyncpg.create_pool
    platform_pool = await pool_factory(dsn=settings.platform_dsn, min_size=1, max_size=2)
    try:
        # The purge never inserts, so the platform pool stands in for both roles.
        service = TerminalDiagnosticsService(
            PostgresDiagnosticRepository(platform_pool, platform_pool),
            build_object_store(settings, object_store_factory),
            access=None,
        )
        return await service.purge()
    finally:
        await platform_pool.close()


def main() -> None:
    purged = asyncio.run(purge_expired(SeedSettings.from_env()))
    print(json.dumps({"purged": purged}))


if __name__ == "__main__":
    main()


__all__ = ["purge_expired"]
