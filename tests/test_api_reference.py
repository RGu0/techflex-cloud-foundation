from __future__ import annotations

import inspect
from pathlib import Path
import re
import subprocess
import sys

import techflex_cloud_foundation

PROJECT_ROOT = Path(__file__).parents[1]
REFERENCE = PROJECT_ROOT / "docs/api-reference.md"
# `### `Name(...)`` or `### `Name``; group 2 is empty when no signature is shown.
ENTRY_HEADING = re.compile(r"^### `([A-Za-z_][A-Za-z0-9_]*)(\(.*\))?`$", re.MULTILINE)


def test_every_exported_symbol_is_documented() -> None:
    text = REFERENCE.read_text(encoding="utf-8")
    undocumented = [name for name in techflex_cloud_foundation.__all__ if f"`{name}" not in text]

    assert not undocumented, f"exports missing from api-reference.md: {undocumented}"


def test_no_entry_documents_an_inherited_constructor() -> None:
    """Every printed signature must come from the symbol, not a base or metaclass.

    The staleness check below compares the file against whatever the current
    interpreter renders, so a signature the interpreter borrows from
    somewhere else makes that check assert the interpreter rather than the
    public API: the `EnumType.__call__` shape changed between CPython 3.11
    and 3.12 and moved twelve entries with it, which is how RAY-388 was
    found.  Protocols borrowed typing's placeholder `__init__` and printed
    `(*args, **kwargs)`, and a class with no constructor borrowed
    `object.__init__` and printed `()`.  Neither drifts across versions
    today, but both are the same defect and both would come back the moment
    the generator prints a signature it did not verify the owner of.
    """

    text = REFERENCE.read_text(encoding="utf-8")
    signed = {name: shown for name, shown in ENTRY_HEADING.findall(text) if shown}

    borrowed = []
    for name in techflex_cloud_foundation.__all__:
        symbol = getattr(techflex_cloud_foundation, name)
        if name not in signed or not inspect.isclass(symbol):
            continue
        if getattr(symbol, "_is_protocol", False):
            source = "typing's protocol placeholder __init__"
        elif type(symbol).__call__ is not type.__call__:
            source = f"{type(symbol).__name__}.__call__"
        elif not ("__init__" in symbol.__dict__ or "__new__" in symbol.__dict__):
            source = "object.__init__"
        else:
            continue
        borrowed.append(f"{name}{signed[name]} <- {source}")

    assert not borrowed, "api-reference.md documents inherited constructors: " + "; ".join(borrowed)


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
