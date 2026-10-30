#!/usr/bin/env python3
"""Read the public foundation wheel URL and digest from committed uv inputs."""

from __future__ import annotations

from pathlib import Path
import re
import sys
import tomllib
from urllib.parse import urlsplit


def locked_foundation_release(pyproject_path: Path, lock_path: Path) -> tuple[str, str]:
    with pyproject_path.open("rb") as source:
        project = tomllib.load(source)
    with lock_path.open("rb") as source:
        lock = tomllib.load(source)

    name = "techflex-cloud-foundation"
    packages = [item for item in lock["package"] if item.get("name") == name]
    if len(packages) != 1:
        raise RuntimeError("foundation must have exactly one locked package")
    package = packages[0]
    version = package["version"]
    pinned = re.compile(rf"{re.escape(name)}(\[[A-Za-z0-9_,.\- ]*\])?=={re.escape(version)}")
    if not any(pinned.fullmatch(item.strip()) for item in project["project"]["dependencies"]):
        raise RuntimeError("foundation dependency version differs from uv.lock")
    declared = project["tool"]["uv"]["sources"][name]["url"]
    source_url = package["source"].get("url")
    wheels = package.get("wheels", [])
    if source_url != declared or len(wheels) != 1 or wheels[0].get("url") != declared:
        raise RuntimeError("foundation release URL differs from uv.lock")
    parsed = urlsplit(declared)
    filename = f"techflex_cloud_foundation-{version}-py3-none-any.whl"
    expected_path = f"/RGu0/techflex-cloud-foundation/releases/download/v{version}/{filename}"
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.path != expected_path
        or parsed.query
        or parsed.fragment
    ):
        raise RuntimeError("foundation release URL is not the approved public asset")
    wheel_hash = wheels[0].get("hash", "")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", wheel_hash):
        raise RuntimeError("foundation wheel SHA-256 is absent from uv.lock")
    return declared, wheel_hash.removeprefix("sha256:")


def main() -> int:
    if len(sys.argv) != 3:
        raise SystemExit("usage: verify_foundation_release_lock.py PYPROJECT UV_LOCK")
    url, digest = locked_foundation_release(Path(sys.argv[1]), Path(sys.argv[2]))
    print(url, digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
