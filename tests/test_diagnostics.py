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
    """The direction the tree cannot drift on its own: new classes.

    This is the check that costs something.  A branch that adds a public
    exception passes its own CI and then fails here once it reaches ``main``
    alongside this file, because the tree is only complete as of the commit
    that wrote it.  That is the intended trade: the alternative is a
    taxonomy page that quietly stops being the taxonomy.  The fix is one row
    in the tree and one line in the catalogue, and the failure says so.
    """

    exported = {
        name
        for name in techflex_cloud_foundation.__all__
        if isinstance(getattr(techflex_cloud_foundation, name), type)
        and issubclass(getattr(techflex_cloud_foundation, name), Exception)
    }
    undocumented = sorted(exported - set(_documented_hierarchy()))

    assert not undocumented, (
        f"exported but missing from the exception hierarchy: {', '.join(undocumented)}. "
        f"Add each to the ```text tree in {DOCS.name} under its immediate base, and give "
        "it a row in the error catalogue for its module."
    )


# ``ValueError`` and ``RuntimeError`` also sit directly under ``Exception`` in
# the tree, but they are builtin roots this library inherits *from*, not
# families it defines.  The prose counts families, so they are excluded.
_BUILTIN_ROOTS = frozenset({"ValueError", "RuntimeError"})

_COUNT_SENTENCE = re.compile(
    r"\*\*([A-Za-z]+(?:-[A-Za-z]+)?) family bases inherit `Exception` directly\.\*\*"
)

_SMALL_NUMBERS = (
    "zero one two three four five six seven eight nine ten eleven twelve "
    "thirteen fourteen fifteen sixteen seventeen eighteen nineteen"
).split()
_TENS = {
    "twenty": 20,
    "thirty": 30,
    "forty": 40,
    "fifty": 50,
    "sixty": 60,
    "seventy": 70,
    "eighty": 80,
    "ninety": 90,
}


def _number_from_words(word: str) -> int:
    """Turn ``fourteen`` or ``twenty-one`` into an int, or fail loudly."""

    text = word.lower()
    if text in _SMALL_NUMBERS:
        return _SMALL_NUMBERS.index(text)
    tens, _, units = text.partition("-")
    if tens in _TENS:
        if not units:
            return _TENS[tens]
        if units in _SMALL_NUMBERS[1:10]:
            return _TENS[tens] + _SMALL_NUMBERS.index(units)
    raise AssertionError(
        f"cannot read {word!r} as a number; write the count as an English "
        "numeral the way the surrounding prose does"
    )


def _documented_family_count() -> tuple[str, int]:
    """The count the prose claims, as written and as a number."""

    match = _COUNT_SENTENCE.search(DOCS.read_text(encoding="utf-8"))
    assert match is not None, (
        f"the sentence stating how many family bases inherit Exception directly is "
        f"missing from {DOCS.name}, or its wording changed. It is checked here "
        "because a hand-written count is exactly what drifts."
    )
    word = match.group(1)
    return word, _number_from_words(word)


def _family_bases() -> set[str]:
    """The families the tree actually shows inheriting ``Exception``."""

    return {
        name
        for name, base in _documented_hierarchy().items()
        if base == "Exception" and name not in _BUILTIN_ROOTS
    }


def test_the_documented_family_count_matches_the_tree() -> None:
    """The one sentence on this page that a number, not a name, has to carry.

    The tree above it is already checked against ``__bases__``; this line was
    not checked against anything.  Every scope that adds a family bumps it by
    one on its own branch, so when two such branches merge git keeps one edit
    and drops the other and the number silently goes short.  It has been wrong
    at three separate merges.  Deriving it from the tree the parser already
    reads costs nothing and makes the next collision a red test.
    """

    word, claimed = _documented_family_count()
    families = _family_bases()

    assert claimed == len(families), (
        f"{DOCS.name} says {word!r} ({claimed}) family bases inherit Exception "
        f"directly, but the tree on that page holds {len(families)}: "
        f"{', '.join(sorted(families))}. Update the sentence to match the tree — "
        "the tree is the statement of record, the sentence only summarizes it."
    )
