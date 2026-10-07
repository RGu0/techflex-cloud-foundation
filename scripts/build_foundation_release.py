#!/usr/bin/env python3
"""Build release artifacts and evidence; publishing remains a separate operation."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

from record_foundation_release_baseline import release_output_directory


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--uv-bin", required=True)
    arguments = parser.parse_args()
    project_root = arguments.project_root.resolve()
    try:
        with release_output_directory(
            os.environ.get("FOUNDATION_RELEASE_DIR"), project_root=project_root
        ) as output:
            subprocess.run(
                [arguments.uv_bin, "build", "--out-dir", str(output)],
                cwd=project_root,
                check=True,
            )
            subprocess.run(
                [
                    sys.executable, "scripts/record_foundation_release_baseline.py",
                    "--project-root", str(project_root), "--dist-dir", str(output),
                    "--baseline-strategy", "legacy-httpx-client/1",
                    "--output", str(output / "release-evidence.json"),
                ],
                cwd=project_root,
                check=True,
            )
    except ValueError as error:
        print(str(error), file=sys.stderr)
        return 2
    except subprocess.CalledProcessError as error:
        return error.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
