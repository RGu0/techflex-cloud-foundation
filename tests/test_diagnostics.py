"""Diagnostics protocols, and the documented exception taxonomy.

The taxonomy in ``docs/boundaries-and-troubleshooting.md`` is the page a
consumer reads to decide what to catch.  A hand-maintained tree of class
names is exactly the kind of documentation that drifts silently, so it is
parsed and checked here against the real ``__bases__`` -- the same treatment
``docs/api-reference.md`` already gets.
"""

from __future__ import annotations

import builtins
import inspect
from pathlib import Path
import pkgutil
import re
from typing import Any

import pytest

import techflex_cloud_foundation
from techflex_cloud_foundation import AuditSink, MetricsSink

DOCS = Path(__file__).resolve().parents[1] / "docs" / "boundaries-and-troubleshooting.md"
MUTABLE_DEFAULTS = (dict, list, set, bytearray)


class TestAuditSinkHasNoSharedDefault:
    def test_fields_defaults_to_none_rather_than_an_empty_mapping(self) -> None:
        """The default was ``{}``.

        A Protocol's signature is copied into every implementation, so that
        literal became one dict shared across all calls to each implementing
        method -- while the annotation says ``Mapping``, the promise that
        stops an implementer from asking whether mutating it is safe.  An
        implementation that enriched the argument or kept it would leak
        fields from one audited event into the next, only under load.
        """

        default = inspect.signature(AuditSink.record).parameters["fields"].default

        assert default is None

    def test_an_implementation_accepting_none_satisfies_the_protocol(self) -> None:
        recorded: list[tuple[str, dict[str, int | str]]] = []

        class Recorder:
            def record(
                self,
                name: str,
                *,
                outcome: str,
                correlation_id: str,
                fields: Any = None,
            ) -> None:
                recorded.append((name, dict(fields or {})))

        sink: AuditSink = Recorder()
        sink.record("upload", outcome="ok", correlation_id="c-1")
        sink.record("upload", outcome="ok", correlation_id="c-2", fields={"parts": 3})

        assert recorded == [("upload", {}), ("upload", {"parts": 3})]

    def test_metrics_sink_still_takes_only_immutable_defaults(self) -> None:
        assert inspect.signature(MetricsSink.increment).parameters["value"].default == 1


def _public_callables() -> list[tuple[str, Any]]:
    """Every public function and method reachable from the package."""

    found: list[tuple[str, Any]] = []
    package_path = Path(techflex_cloud_foundation.__file__).parent
    for module_info in pkgutil.walk_packages([str(package_path)], "techflex_cloud_foundation."):
        module = __import__(module_info.name, fromlist=["_"])
        for name, member in vars(module).items():
            if name.startswith("_") or getattr(member, "__module__", None) != module.__name__:
                continue
            if inspect.isfunction(member):
                found.append((f"{module_info.name}.{name}", member))
            elif inspect.isclass(member):
                for method_name, method in vars(member).items():
                    if not method_name.startswith("_") and inspect.isfunction(method):
                        found.append((f"{module_info.name}.{name}.{method_name}", method))
    return found


def test_no_public_callable_carries_a_mutable_default() -> None:
    """A default is evaluated once, at definition; a mutable one is shared.

    ``AuditSink.record`` had ``fields: Mapping[str, int | str] = {}``.  The
    check is written over the whole package rather than that one signature,
    because the failure mode is invisible in review and identical everywhere
    it appears.
    """

    offenders = [
        f"{qualified_name}({parameter.name}={parameter.default!r})"
        for qualified_name, function in _public_callables()
        for parameter in inspect.signature(function).parameters.values()
        if isinstance(parameter.default, MUTABLE_DEFAULTS)
    ]

    assert offenders == []


def _documented_hierarchy() -> dict[str, str]:
    """Parse the tree in the docs into ``{class name: documented base}``."""

    text = DOCS.read_text(encoding="utf-8")
    block = re.search(r"```text\n(.*?)```", text, re.DOTALL)
    assert block is not None, "the exception hierarchy block is missing from the docs"

    hierarchy: dict[str, str] = {}
    stack: dict[int, str] = {}
    for line in block.group(1).splitlines():
        match = re.match(r"^([\s│├└─]*)([A-Za-z_][A-Za-z0-9_]*)", line)
        if match is None:
            continue
        depth = len(match.group(1)) // 4
        name = match.group(2)
        stack[depth] = name
        if depth:
            hierarchy[name] = stack[depth - 1]
    return hierarchy


def _resolve(name: str) -> type | None:
    """A documented name is either exported here or a builtin root."""

    return getattr(techflex_cloud_foundation, name, None) or getattr(builtins, name, None)


@pytest.mark.parametrize("name,documented_base", sorted(_documented_hierarchy().items()))
def test_the_documented_hierarchy_matches_the_code(name: str, documented_base: str) -> None:
    actual = _resolve(name)

    assert actual is not None, f"{name} is documented but neither exported nor a builtin"
    assert issubclass(actual, Exception)
    assert actual.__bases__[0].__name__ == documented_base


def test_every_public_exception_appears_in_the_documented_hierarchy() -> None:
    """The direction the tree cannot drift on its own: new classes."""

    exported = {
        name
        for name in techflex_cloud_foundation.__all__
        if isinstance(getattr(techflex_cloud_foundation, name), type)
        and issubclass(getattr(techflex_cloud_foundation, name), Exception)
    }
    documented = set(_documented_hierarchy())

    assert exported - documented == set()
