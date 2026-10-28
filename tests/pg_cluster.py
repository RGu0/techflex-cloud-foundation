"""An ephemeral PostgreSQL cluster for tests that need a real server.

The cluster listens on a Unix socket only, lives in a temporary directory and is
removed afterwards. ``find_postgres_bin`` returns ``None`` where no server is
installed, so tests skip instead of failing on machines without one.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


@dataclass(frozen=True)
class Cluster:
    socket_dir: str
    port: int


def find_postgres_bin() -> Path | None:
    if sys.platform == "win32":
        return None
    on_path = shutil.which("initdb")
    if on_path:
        return Path(on_path).parent
    candidates = [
        *sorted(Path("/usr/lib/postgresql").glob("*/bin"), reverse=True),
        *sorted(Path("/opt/homebrew/opt").glob("postgresql@*/bin"), reverse=True),
        *sorted(Path("/usr/local/opt").glob("postgresql@*/bin"), reverse=True),
    ]
    for candidate in candidates:
        if (candidate / "initdb").exists():
            return candidate
    return None


@contextmanager
def running_cluster(bin_dir: Path) -> Iterator[Cluster]:
    root = Path(tempfile.mkdtemp(prefix="tfpg"))  # short: Unix socket paths are limited
    data = root / "data"
    sockets = root / "s"
    sockets.mkdir()
    port = 54000 + os.getpid() % 1000
    env = {**os.environ, "LC_ALL": "C"}
    try:
        subprocess.run(
            [str(bin_dir / "initdb"), "-D", str(data), "-U", "postgres", "--auth=trust",
             "-E", "UTF8", "--no-locale"],
            check=True, capture_output=True, env=env,
        )
        subprocess.run(
            [str(bin_dir / "pg_ctl"), "-D", str(data), "-w", "-l", str(root / "log"),
             "-o", f"-p {port} -k {sockets} -c listen_addresses=''", "start"],
            check=True, capture_output=True, env=env,
        )
        try:
            yield Cluster(socket_dir=str(sockets), port=port)
        finally:
            subprocess.run(
                [str(bin_dir / "pg_ctl"), "-D", str(data), "-m", "immediate", "-w", "stop"],
                capture_output=True, env=env,
            )
    finally:
        shutil.rmtree(root, ignore_errors=True)
