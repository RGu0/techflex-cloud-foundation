from __future__ import annotations

import ast
from pathlib import Path

FORBIDDEN_IMPORT_ROOTS = {"feetforceplate", "client", "cloud", "shared"}


def test_public_source_has_no_application_import_boundary_leak() -> None:
    source_root = Path("src/techflex_cloud_foundation")
    imports: set[str] = set()
    for source_file in source_root.rglob("*.py"):
        module = ast.parse(source_file.read_text(encoding="utf-8"))
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                imports.update(alias.name.partition(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.partition(".")[0])

    assert imports.isdisjoint(FORBIDDEN_IMPORT_ROOTS)
