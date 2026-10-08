# SPDX-License-Identifier: LGPL-2.1-only

from dataclasses import dataclass
import importlib.metadata
from pathlib import Path
from typing import Callable, Final, Iterable, Mapping, Protocol


POLICY_PROVIDER_ENTRY_POINT_GROUP: Final[str] = "setools.mcp.policy_providers"


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


class PolicyProviderFactory(Protocol):

    """Create one configured policy-provider implementation."""

    name: str

    def create(self, options: Mapping[str, str]) -> PolicyProvider:
        """Validate *options* and create the provider."""


@dataclass(frozen=True)
class PolicyProviderSelection:

    """Configured provider name and its implementation-defined options."""

    name: str
    options: Mapping[str, str]


class PolicyProviderRegistry:

    """Registry of policy-provider factories."""

    def __init__(self, factories: Iterable[PolicyProviderFactory] = ()) -> None:
        self._factories: dict[str, PolicyProviderFactory] = {}
        for factory in factories:
            self.register(factory)

    @property
    def names(self) -> tuple[str, ...]:
        """Return registered provider names."""
        return tuple(sorted(self._factories))

    def register(self, factory: PolicyProviderFactory) -> None:
        """Register *factory*, rejecting invalid or duplicate names."""
        name = factory.name
        if not name or not name.isidentifier() or name.lower() != name:
            raise ValueError(f"{name!r} is not a valid policy provider name")
        if name in self._factories:
            raise ValueError(f"Policy provider {name!r} is already registered")
        self._factories[name] = factory

    def create(self, selection: PolicyProviderSelection) -> PolicyProvider:
        """Create the selected policy provider."""
        try:
            factory = self._factories[selection.name]
        except KeyError as ex:
            available = ", ".join(self.names) or "(none)"
            raise ValueError(f"Unknown policy provider {selection.name!r}; available providers: "
                             f"{available}") from ex
        return factory.create(selection.options)

    def load_entry_points(self, group: str = POLICY_PROVIDER_ENTRY_POINT_GROUP) -> None:
        """Load installed provider factories from *group*."""
        for entry_point in importlib.metadata.entry_points(group=group):
            try:
                loaded = entry_point.load()
                factory = loaded() if isinstance(loaded, type) else loaded
                if factory.name != entry_point.name:
                    raise ValueError(f"factory name {factory.name!r} does not match entry point "
                                     f"{entry_point.name!r}")
                self.register(factory)
            except Exception as ex:
                raise RuntimeError(f"Unable to load policy provider entry point "
                                   f"{entry_point.name!r}: {ex}") from ex


class SessionOwnerProvider(Protocol):

    """Resolve the owner of the active MCP request."""

    def current_owner(self) -> SessionOwner:
        """Return the active session owner."""
