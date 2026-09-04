"""The distribution's own metadata, checked against itself.

This file used to assert ``project["version"] == "0.1.1"``.  A literal
copied into a test says only that someone edited two files at the same time;
it has to be edited again on every release, and it never noticed that the
CHANGELOG had four ``## Unreleased`` headings and no entry for the version
`pyproject.toml` claimed.  The assertions here are relations between files
instead, so they keep holding without maintenance and fail when the files
disagree.
"""

from __future__ import annotations

from importlib import metadata
from pathlib import Path
import re
import tomllib
from urllib.parse import urlparse

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DISTRIBUTION = "techflex-cloud-foundation"
# PEP 440 release segment; this project uses plain three-part versions.
VERSION = re.compile(r"\d+\.\d+\.\d+\Z")
RELEASE_HEADING = re.compile(r"^## (\d+\.\d+\.\d+) - \d{4}-\d{2}-\d{2}$", re.MULTILINE)
LOCK_INDEX = "https://pypi.org/simple"
LOCK_HOST = "files.pythonhosted.org"


def _project() -> dict[str, object]:
    return tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]


def _changelog() -> str:
    return (PROJECT_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_root_project_is_the_foundation_distribution() -> None:
    project = _project()

    assert project["name"] == DISTRIBUTION
    assert project["requires-python"] == ">=3.11"
    assert project["optional-dependencies"]["server"] == ["asyncpg>=0.30,<1"]


def test_the_declared_version_is_the_installed_version() -> None:
    """The editable install is what the test suite actually imports.

    Bumping `pyproject.toml` without reinstalling leaves the two out of step,
    and every other assertion in this file would be checking the wrong
    number.
    """

    declared = _project()["version"]

    assert isinstance(declared, str) and VERSION.match(declared)
    assert metadata.version(DISTRIBUTION) == declared


def test_the_changelog_has_exactly_one_unreleased_section() -> None:
    """Four had accumulated, one per merged branch.

    Each is a valid heading, so nothing complained, and a reader scanning for
    what changed since the last release saw the first block and stopped.
    """

    headings = _changelog().count("\n## Unreleased\n")

    assert headings == 1, f"expected one '## Unreleased' heading, found {headings}"


def test_the_unreleased_section_comes_before_every_release() -> None:
    changelog = _changelog()
    unreleased = changelog.index("\n## Unreleased\n")
    first_release = RELEASE_HEADING.search(changelog)

    assert first_release is not None, "the changelog records no released version"
    assert unreleased < first_release.start()


def test_every_released_version_is_recorded_in_order() -> None:
    """Newest first, and no version listed twice."""

    releases = RELEASE_HEADING.findall(_changelog())

    assert releases, "the changelog records no released version"
    assert len(set(releases)) == len(releases)
    keys = [tuple(int(part) for part in release.split(".")) for release in releases]
    assert keys == sorted(keys, reverse=True)


CATEGORIES = ("Added", "Changed", "Breaking", "Fixed")


def test_the_newest_release_section_uses_the_agreed_categories() -> None:
    """A flat list of bullets does not say which entries are breaking.

    The header promises a consumer can find every breaking change by reading
    the release, and that promise is only kept if the section is sorted.  An
    empty subsection is still kept, so its absence means "not classified"
    rather than "none".
    """

    changelog = _changelog()
    first_release = RELEASE_HEADING.search(changelog)
    assert first_release is not None
    following = RELEASE_HEADING.search(changelog, first_release.end())
    section = changelog[first_release.end() : following.start() if following else len(changelog)]

    headings = re.findall(r"^### (.+)$", section, re.MULTILINE)
    assert headings == list(CATEGORIES), f"expected {CATEGORIES}, found {headings}"


def test_an_unreleased_version_is_ahead_of_the_last_release() -> None:
    """`0.2.0` is not yet a heading here; it must still be a bump.

    The declared version is what a wheel built from this tree carries, so it
    may not silently equal or trail a version already published.
    """

    declared = str(_project()["version"])
    releases = RELEASE_HEADING.findall(_changelog())
    if declared in releases:
        return  # the release has been cut; the heading is the record

    latest = max(tuple(int(part) for part in release.split(".")) for release in releases)
    assert tuple(int(part) for part in declared.split(".")) > latest


def test_the_lock_resolves_only_against_the_public_index() -> None:
    """A lock records where each package came from, not only which one.

    A mirror configured on one machine rewrites every entry; a runner without
    that configuration rewrites them all back.  Neither side is wrong and
    neither notices, and what lands is a dependency bump whose real change is
    buried under several hundred URL edits.  `./dev` sets UV_NO_CONFIG so this
    project's own commands cannot do it, but `uv lock` and `uv add` are run
    directly and bypass that; this is what catches them.
    """

    lock = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8"))
    packages = lock["package"]
    assert packages, "the lock records no package"

    registries = {
        package["source"]["registry"]
        for package in packages
        if "registry" in package.get("source", {})
    }
    assert registries == {LOCK_INDEX}, f"resolved against {sorted(registries)}"

    hosts = set()
    for package in packages:
        for artifact in (package.get("sdist", {}), *package.get("wheels", ())):
            if "url" in artifact:
                hosts.add(urlparse(artifact["url"]).netloc)

    assert hosts, "the lock names no downloadable artifact"
    assert hosts == {LOCK_HOST}, f"artifacts served from {sorted(hosts)}"
