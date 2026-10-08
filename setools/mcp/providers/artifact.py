# SPDX-License-Identifier: LGPL-2.1-only

from pathlib import Path, PurePosixPath
import shutil
import tempfile
from typing import Collection


def create_artifact_directory(base_dir: Path | None = None) -> Path:
    """Create a private staging directory for one acquired artifact."""
    directory = Path(tempfile.mkdtemp(prefix="setools-policy-", dir=base_dir))
    directory.chmod(0o700)
    return directory


def remove_artifact_directory(directory: Path) -> None:
    """Remove an artifact directory and all of its contents."""
    shutil.rmtree(directory, ignore_errors=True)


def validate_artifact_path(value: str) -> PurePosixPath:
    """Validate and return one artifact-relative POSIX path."""
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or ".." in path.parts:
        raise ValueError(f"{value!r} is not a safe artifact-relative path")
    return path


def validate_artifact_tree(directory: Path,
                           max_bytes: int,
                           excluded_roots: Collection[Path] = ()) -> None:
    """Validate an artifact tree and enforce its aggregate byte limit."""
    if max_bytes < 1:
        raise ValueError("max_bytes must be at least 1")

    excluded = tuple(root.resolve() for root in excluded_roots)
    total_size = 0
    for path in directory.rglob("*"):
        resolved = path.resolve()
        if any(resolved == root or root in resolved.parents for root in excluded):
            continue
        if path.is_symlink():
            raise ValueError("Acquired artifact contains a symbolic link")
        if path.is_file():
            total_size += path.stat().st_size
            if total_size > max_bytes:
                raise ValueError("Acquired artifact exceeds the configured size limit")


def resolve_artifact_file(directory: Path, relative: PurePosixPath) -> Path:
    """Resolve and validate one expected file beneath *directory*."""
    path = directory.joinpath(*relative.parts)
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"Acquired artifact is missing {relative}")
    if directory.resolve() not in path.resolve().parents:
        raise ValueError(f"Acquired artifact path escapes its directory: {relative}")
    return path
