from __future__ import annotations

from pathlib import Path
import runpy
import zipfile

import pytest

ROOT = Path(__file__).resolve().parents[1]
pin = runpy.run_path(str(ROOT / "scripts" / "pin_seed_runtime.py"))
verifier = runpy.run_path(
    str(ROOT / "deploy" / "aliyun" / "seed" / "verify_foundation_release_lock.py")
)

_PROJECT = (ROOT / "deploy" / "aliyun" / "seed" / "runtime" / "pyproject.toml").read_text(
    encoding="utf-8"
)


def _wheel(path: Path, version: str) -> Path:
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            f"techflex_cloud_foundation-{version}.dist-info/METADATA",
            f"Metadata-Version: 2.1\nName: techflex-cloud-foundation\nVersion: {version}\n",
        )
    return path


def test_rewrite_points_the_dependency_and_the_asset_at_one_version() -> None:
    rewritten = pin["rewrite_project"](_PROJECT, "0.9.1")

    assert '"techflex-cloud-foundation[server]==0.9.1"' in rewritten
    assert pin["release_url"]("0.9.1") in rewritten
    assert rewritten.count("0.9.1") >= 3
    assert pin["rewrite_project"](rewritten, "0.9.1") == rewritten


@pytest.mark.parametrize("version", ["0.9", "v0.9.1", "0.9.1; rm", ""])
def test_rewrite_refuses_a_version_that_is_not_plain(version: str) -> None:
    with pytest.raises(ValueError):
        pin["rewrite_project"](_PROJECT, version)


def test_rewrite_refuses_a_project_that_does_not_pin_the_server_extra() -> None:
    with pytest.raises(ValueError, match="server extra"):
        pin["rewrite_project"](_PROJECT.replace("[server]", ""), "0.9.1")


def test_the_version_is_read_from_the_wheel_metadata(tmp_path: Path) -> None:
    assert pin["wheel_version"](_wheel(tmp_path / "a.whl", "0.8.0")) == "0.8.0"


def test_a_wheel_without_metadata_is_refused(tmp_path: Path) -> None:
    empty = tmp_path / "e.whl"
    with zipfile.ZipFile(empty, "w") as archive:
        archive.writestr("x.txt", "x")
    with pytest.raises(ValueError, match="METADATA"):
        pin["wheel_version"](empty)


def _lock(version: str, digest: str, url: str) -> str:
    return (
        'version = 1\n\n[[package]]\nname = "techflex-cloud-foundation"\n'
        f'version = "{version}"\nsource = {{ url = "{url}" }}\n'
        f'wheels = [{{ url = "{url}", hash = "sha256:{digest}" }}]\n'
    )


def test_the_installer_verifier_accepts_the_pinned_project(tmp_path: Path) -> None:
    version = "0.8.0"
    url = pin["release_url"](version)
    project = tmp_path / "pyproject.toml"
    project.write_text(pin["rewrite_project"](_PROJECT, version), encoding="utf-8")
    lock = tmp_path / "uv.lock"
    lock.write_text(_lock(version, "a" * 64, url), encoding="utf-8")

    assert verifier["locked_foundation_release"](project, lock) == (url, "a" * 64)


def test_the_installer_verifier_refuses_a_different_asset(tmp_path: Path) -> None:
    project = tmp_path / "pyproject.toml"
    project.write_text(pin["rewrite_project"](_PROJECT, "0.8.0"), encoding="utf-8")
    lock = tmp_path / "uv.lock"
    lock.write_text(
        _lock("0.8.0", "a" * 64, "https://example.com/techflex_cloud_foundation-0.8.0.whl"),
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="release URL"):
        verifier["locked_foundation_release"](project, lock)
