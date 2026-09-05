#!/usr/bin/env python3
"""Generate docs/api-reference.md from the v1 public API (RAY-367).

The reference is derived from ``techflex_cloud_foundation.__all__`` and the
symbols' docstrings, so the committed document and the code cannot drift
silently: ``--check`` (run in tests) fails when the generated text differs
from the committed file, which is exactly what happens when a symbol is
added, renamed, removed, or re-documented.
"""

from __future__ import annotations

import argparse
import inspect
from pathlib import Path
import sys
from typing import Any

HEADER = """# API Reference

Generated from `techflex_cloud_foundation.__all__` by
`scripts/generate_api_reference.py`; do not edit by hand. Docstrings are the
single source of truth — update the code and regenerate:

```bash
uv run --locked --extra dev python scripts/generate_api_reference.py \
    --project-root . --output docs/api-reference.md
```

Every exported symbol is listed with its defining module and signature.
"""


def _defines_own_constructor(cls: type) -> bool:
    """Whether ``cls`` describes its own construction, rather than a base's.

    ``inspect.signature`` on a class answers "how is an instance of this
    made", walking the metaclass and the MRO to find out.  For a class that
    constructs nothing of its own that answer belongs to something else, and
    printing it in a reference document attributes another object's API to
    this one.  Three shapes hit this, and all three were in the committed
    document:

    * An ``Enum`` resolves to ``EnumType.__call__``, whose parameters are the
      *functional* API (``Colour("red", "GREEN BLUE")``) and not the member
      lookup every caller actually writes.  That signature is also the only
      thing here that changed between CPython 3.11 and 3.12, which is what
      made the drift check assert its own interpreter (RAY-388).
    * A ``Protocol`` resolves to the placeholder ``__init__`` that ``typing``
      installs on every protocol class, printed as ``(*args, **kwargs)``.  A
      protocol is not instantiated at all, so no signature is the honest one.
    * A plain class with no constructor resolves to ``object.__init__`` and
      prints ``()``, which reads as an invitation to instantiate a namespace
      of static methods.

    Exception subclasses already rendered bare, because ``inspect.signature``
    raises on them; this brings the other three into line with that, rather
    than making exceptions the odd case.
    """

    # ``typing`` assigns a placeholder ``__init__`` into each protocol class's
    # own ``__dict__``, so the ``__dict__`` test below cannot see through it.
    if getattr(cls, "_is_protocol", False):
        return False
    # A metaclass that overrides ``__call__`` is the thing being described --
    # ``EnumType`` is the case here.  Enum members do land a generated
    # ``__new__`` in the class's own ``__dict__``, so this test, not the one
    # below, is what excludes them.
    if type(cls).__call__ is not type.__call__:
        return False
    # ``@dataclass`` and ``NamedTuple`` generate a real ``__init__`` or
    # ``__new__`` *for this class*, and both belong in the document.
    return "__init__" in cls.__dict__ or "__new__" in cls.__dict__


def _signature(symbol: Any) -> str | None:
    if inspect.isclass(symbol) and not _defines_own_constructor(symbol):
        return None
    try:
        return str(inspect.signature(symbol))
    except (TypeError, ValueError):
        return None


def _summary(symbol: Any) -> str:
    doc = inspect.getdoc(symbol)
    if not doc:
        return "**undocumented — add a docstring**"
    return doc.split("\n\n", 1)[0].split("\n", 1)[0]


def render_reference(package: Any) -> str:
    symbols: dict[str, list[str]] = {}
    for name in package.__all__:
        symbol = getattr(package, name)
        module = getattr(symbol, "__module__", "techflex_cloud_foundation")
        symbols.setdefault(module, []).append(name)

    lines = [HEADER]
    for module in sorted(symbols):
        lines.append(f"\n## `{module}`\n")
        for name in sorted(symbols[module]):
            symbol = getattr(package, name)
            signature = _signature(symbol)
            heading = f"`{name}{signature}`" if signature else f"`{name}`"
            lines.append(f"\n### {heading}\n")
            lines.append(f"\n{_summary(symbol)}\n")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed file differs from the generated text",
    )
    args = parser.parse_args()

    sys.path.insert(0, str(args.project_root / "src"))
    import techflex_cloud_foundation

    rendered = render_reference(techflex_cloud_foundation)
    if args.check:
        committed = args.output.read_text(encoding="utf-8")
        if committed != rendered:
            print(
                "docs/api-reference.md is stale; regenerate with "
                "scripts/generate_api_reference.py",
                file=sys.stderr,
            )
            return 1
        return 0
    args.output.write_text(rendered, encoding="utf-8")
    print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
