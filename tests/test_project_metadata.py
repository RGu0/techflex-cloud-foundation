from __future__ import annotations

import tomllib
from pathlib import Path


def test_root_project_is_the_foundation_distribution() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]

    assert project["name"] == "techflex-cloud-foundation"
    assert project["version"] == "0.1.1"
    assert project["requires-python"] == ">=3.11"
    assert project["optional-dependencies"]["server"] == ["asyncpg>=0.30,<1"]
