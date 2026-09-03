from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import techflex_cloud_foundation


PROJECT_ROOT = Path(__file__).parents[1]
REFERENCE = PROJECT_ROOT / "docs/api-reference.md"


def test_every_exported_symbol_is_documented() -> None:
    text = REFERENCE.read_text(encoding="utf-8")
    undocumented = [name for name in techflex_cloud_foundation.__all__ if f"`{name}" not in text]

    assert not undocumented, f"exports missing from api-reference.md: {undocumented}"


def test_api_reference_is_not_stale() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "scripts/generate_api_reference.py",
            "--project-root",
            ".",
            "--output",
            "docs/api-reference.md",
            "--check",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
