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


def _signature(symbol: Any) -> str | None:
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
