# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path

import pytest

from setools.mcp.providers.artifact import (create_artifact_directory,
                                            remove_artifact_directory,
                                            resolve_artifact_file,
                                            validate_artifact_path,
                                            validate_artifact_tree)


def test_private_artifact_directory_is_removed(tmp_path: Path) -> None:
    """Artifact directories are private and can be removed after use."""
    directory = create_artifact_directory(tmp_path)

    assert directory.stat().st_mode & 0o777 == 0o700

    remove_artifact_directory(directory)
    assert not directory.exists()


@pytest.mark.parametrize("value", ("/policy.bin", "../policy.bin", "a/../../policy.bin"))
def test_unsafe_artifact_path_is_rejected(value: str) -> None:
    """Absolute paths and parent traversal cannot escape an artifact directory."""
    with pytest.raises(ValueError, match="safe artifact-relative path"):
        validate_artifact_path(value)


def test_artifact_tree_rejects_symbolic_links(tmp_path: Path) -> None:
    """Artifact validation rejects symbolic links even within the artifact tree."""
    target = tmp_path / "target"
    target.write_bytes(b"policy")
    (tmp_path / "link").symlink_to(target)

    with pytest.raises(ValueError, match="symbolic link"):
        validate_artifact_tree(tmp_path, 1024)


def test_artifact_tree_enforces_size_limit(tmp_path: Path) -> None:
    """Artifact contents exceeding the configured byte limit are rejected."""
    (tmp_path / "policy").write_bytes(b"policy")

    with pytest.raises(ValueError, match="size limit"):
        validate_artifact_tree(tmp_path, 3)


def test_excluded_tree_is_not_counted(tmp_path: Path) -> None:
    """Provider state excluded from validation does not consume the artifact size limit."""
    excluded = tmp_path / ".provider"
    excluded.mkdir()
    (excluded / "state").write_bytes(b"large provider state")
    (tmp_path / "policy").write_bytes(b"ok")

    validate_artifact_tree(tmp_path, 2, (excluded,))


def test_expected_artifact_file_is_resolved(tmp_path: Path) -> None:
    """An existing artifact-relative file resolves to its full path."""
    policy = tmp_path / "policy.bin"
    policy.write_bytes(b"policy")

    assert resolve_artifact_file(tmp_path, validate_artifact_path("policy.bin")) == policy


def test_missing_artifact_file_is_rejected(tmp_path: Path) -> None:
    """Resolving a missing artifact file reports an explicit error."""
    with pytest.raises(ValueError, match="is missing"):
        resolve_artifact_file(tmp_path, validate_artifact_path("policy.bin"))
