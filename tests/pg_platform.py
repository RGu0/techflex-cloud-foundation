"""A shared ephemeral platform database for the ported ffp live tests.

The ffp tests read admin, tenant, activation and platform DSNs from the
environment. ``live_environment`` starts one throwaway cluster per process,
installs the schema, creates least-privilege login roles and exports those
DSNs, so the same tests run here without an operator-provided database. It
returns ``False`` where no PostgreSQL server is installed, and an operator's
own DSNs are left untouched. Set ``FFP_REQUIRE_POSTGRES=1`` to make a missing
server an error instead of a skip, so a CI image cannot pass without RLS coverage.
"""

from __future__ import annotations

import asyncio
import atexit
from contextlib import ExitStack
import os

from tests.pg_cluster import Cluster, find_postgres_bin, running_cluster
from tests.test_schema_migrations import ROLE_STEP

DB = "platform_live"
_LOGINS = {
    "TENANT": ("ffp_live_tenant", "ffp_tenant_app"),
    "ACTIVATION": ("ffp_live_activation", "ffp_activation_app"),
    "PLATFORM": ("ffp_live_platform", "ffp_platform_app"),
}
_state: dict[str, bool] = {}
_stack = ExitStack()
atexit.register(_stack.close)


def _dsn(cluster: Cluster, user: str) -> str:
    return f"postgresql://{user}@/{DB}?host={cluster.socket_dir}&port={cluster.port}"


async def _install(cluster: Cluster) -> None:
    import asyncpg

    from techflex_cloud_foundation.schema import RoleMissing, apply_migrations

    admin = await asyncpg.connect(
        host=cluster.socket_dir, port=cluster.port, user="postgres", database="postgres"
    )
    try:
        await admin.execute(f"CREATE DATABASE {DB}")
    finally:
        await admin.close()
    conn = await asyncpg.connect(
        host=cluster.socket_dir, port=cluster.port, user="postgres", database=DB
    )
    try:
        try:
            await apply_migrations(conn)
        except RoleMissing:
            await conn.execute(ROLE_STEP)
            await apply_migrations(conn)
        await conn.execute(ROLE_STEP)
        for login, role in _LOGINS.values():
            await conn.execute(
                f"CREATE ROLE {login} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT "
                f"NOBYPASSRLS; GRANT {role} TO {login}"
            )
    finally:
        await conn.close()


def live_environment() -> bool:
    """Export the ``FEETFORCEPLATE_TEST_*`` DSNs; ``False`` when no server is available."""
    if "ready" in _state:
        return _state["ready"]
    # Caller-provided databases (the live acceptance run on the host) win over a scratch cluster.
    if os.environ.get("FEETFORCEPLATE_TEST_ADMIN_DSN") or all(
        os.environ.get(f"FEETFORCEPLATE_TEST_{key}_DSN") for key in _LOGINS
    ):
        _state["ready"] = True
        return True
    binaries = find_postgres_bin()
    try:
        import asyncpg  # noqa: F401
    except ImportError:
        binaries = None
    if binaries is None:
        if os.environ.get("FFP_REQUIRE_POSTGRES") == "1":
            raise RuntimeError("FFP_REQUIRE_POSTGRES=1 but no PostgreSQL server or asyncpg found")
        _state["ready"] = False
        return False
    cluster = _stack.enter_context(running_cluster(binaries))
    asyncio.run(_install(cluster))
    os.environ["FEETFORCEPLATE_TEST_ISOLATED"] = "1"
    os.environ["FEETFORCEPLATE_TEST_ADMIN_DSN"] = _dsn(cluster, "postgres")
    for key, (login, _role) in _LOGINS.items():
        os.environ[f"FEETFORCEPLATE_TEST_{key}_DSN"] = _dsn(cluster, login)
    _state["ready"] = True
    return True
