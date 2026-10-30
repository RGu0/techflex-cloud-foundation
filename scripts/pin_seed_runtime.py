#!/usr/bin/env python3
"""Pin the seed runtime to a published foundation release (RAY-830 release-cutover).

Run after the GitHub release for ``--version`` exists.  ``--wheel`` is the
retained release candidate; the script rewrites ``deploy/aliyun/seed/runtime``
for that version, locks it (uv downloads the published asset and records its
digest) and refuses unless that digest equals the retained wheel's.  The result
is a ``uv.lock`` that the installer's own check accepts.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import subprocess
import sys
import zipfile

RUNTIME = Path(__file__).resolve().parents[1] / "deploy" / "aliyun" / "seed" / "runtime"
VERIFIER = RUNTIME.parent / "verify_foundation_release_lock.py"
_VERSION = re.compile(r"\d+\.\d+\.\d+")


def release_url(version: str) -> str:
    return (
        "https://github.com/RGu0/techflex-cloud-foundation/releases/download/"
        f"v{version}/techflex_cloud_foundation-{version}-py3-none-any.whl"
    )


def wheel_version(wheel: Path) -> str:
    """The version recorded in the wheel's own metadata."""
    with zipfile.ZipFile(wheel) as archive:
        names = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        if len(names) != 1:
            raise ValueError("wheel must contain exactly one METADATA file")
        for line in archive.read(names[0]).decode("utf-8").splitlines():
            if line.startswith("Version: "):
                return line.removeprefix("Version: ").strip()
    raise ValueError("wheel metadata has no Version")


def rewrite_project(text: str, version: str) -> str:
    """Point the runtime project at ``version`` and its release asset."""
    if not _VERSION.fullmatch(version):
        raise ValueError("version must look like 1.2.3")
    text, count = re.subn(
        r'"techflex-cloud-foundation\[server\]==[^"]*"',
        f'"techflex-cloud-foundation[server]=={version}"',
        text,
    )
    if count != 1:
        raise ValueError("runtime project must pin the foundation server extra exactly once")
    text, count = re.subn(
        r'(techflex-cloud-foundation = \{ url = )"[^"]*"( \})',
        rf'\g<1>"{release_url(version)}"\g<2>',
        text,
    )
    if count != 1:
        raise ValueError("runtime project must name the foundation release source exactly once")
    return text


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--wheel", required=True, type=Path)
    args = parser.parse_args()

    if wheel_version(args.wheel) != args.version:
        print("wheel metadata version differs from --version", file=sys.stderr)
        return 1
    pyproject = RUNTIME / "pyproject.toml"
    pyproject.write_text(
        rewrite_project(pyproject.read_text(encoding="utf-8"), args.version), encoding="utf-8"
    )
    # A user-level uv configuration (a package mirror) would rewrite every registry
    # URL in the lock; the host's offline cache is keyed by the canonical ones.
    subprocess.run(
        ["uv", "lock", "--no-config", "--refresh-package", "techflex-cloud-foundation",
         "--project", str(RUNTIME)],
        check=True,
    )
    done = subprocess.run(
        [sys.executable, str(VERIFIER), str(pyproject), str(RUNTIME / "uv.lock")],
        check=True,
        capture_output=True,
        text=True,
    )
    url, locked_digest = done.stdout.split()
    if locked_digest != sha256(args.wheel):
        (RUNTIME / "uv.lock").unlink()
        print("published asset differs from the retained release candidate", file=sys.stderr)
        return 1
    print(f"url={url} sha256={locked_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
