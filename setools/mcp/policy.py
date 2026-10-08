# SPDX-License-Identifier: LGPL-2.1-only

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Protocol


@dataclass(frozen=True)
class SessionOwner:

    """Non-sensitive identity of one MCP session owner."""

    session_id: str
    tenant_id: str | None = None
    caller_id: str | None = None


@dataclass(frozen=True)
class PolicyArtifact:

    """A policy acquired by a policy provider."""

    resolved_version: str
    policy_path: Path
    file_contexts_path: Path | None = None
    cleanup: Callable[[], None] | None = None


class PolicyProvider(Protocol):

    """Acquire SELinux policy artifacts from an implementation-defined source."""

    def acquire(self, reference: str, owner: SessionOwner) -> PolicyArtifact:
        """Acquire *reference* for *owner*."""


class SessionOwnerProvider(Protocol):

    """Resolve the owner of the active MCP request."""

    def current_owner(self) -> SessionOwner:
        """Return the active session owner."""
