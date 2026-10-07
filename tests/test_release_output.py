from pathlib import Path

import pytest

from scripts import record_foundation_release_baseline as release


def test_explicit_release_output_survives_success(tmp_path: Path) -> None:
    output = tmp_path / "release"
    with release.release_output_directory(str(output), project_root=tmp_path) as directory:
        (directory / "artifact.whl").write_bytes(b"artifact")
    assert (output / "artifact.whl").read_bytes() == b"artifact"


def test_default_release_output_is_removed(tmp_path: Path) -> None:
    with release.release_output_directory(None, project_root=tmp_path) as directory:
        (directory / "artifact.whl").write_bytes(b"artifact")
    assert not directory.exists()


def test_release_output_preserves_existing_files_on_rejection(tmp_path: Path) -> None:
    output = tmp_path / "release"
    output.mkdir()
    marker = output / "keep"
    marker.write_bytes(b"existing")
    with pytest.raises(ValueError):
        with release.release_output_directory(str(output), project_root=tmp_path):
            pytest.fail("nonempty output accepted")
    assert marker.read_bytes() == b"existing"


@pytest.mark.parametrize("destination", ["", ".", "/"])
def test_release_output_rejects_dangerous_destination(tmp_path: Path, destination: str) -> None:
    with pytest.raises(ValueError):
        with release.release_output_directory(destination, project_root=tmp_path):
            pytest.fail("dangerous output accepted")


def test_explicit_release_output_retains_failed_build_without_hiding_error(tmp_path: Path) -> None:
    output = tmp_path / "release"
    with pytest.raises(RuntimeError, match="build failed"):
        with release.release_output_directory(str(output), project_root=tmp_path) as directory:
            (directory / "partial.whl").write_bytes(b"partial")
            raise RuntimeError("build failed")
    assert (output / "partial.whl").read_bytes() == b"partial"
    assert not (output / "release-evidence.json").exists()


def test_release_output_rejects_symlink_ancestor(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "link"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation requires platform permission")
    with pytest.raises(ValueError):
        with release.release_output_directory(str(link / "release"), project_root=tmp_path):
            pytest.fail("symlink output accepted")
    assert not (target / "release").exists()
