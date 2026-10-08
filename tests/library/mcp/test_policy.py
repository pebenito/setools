# SPDX-License-Identifier: GPL-2.0-only

from importlib.metadata import EntryPoint
from pathlib import Path
from typing import Mapping

import pytest

from setools.mcp.policy import (PolicyArtifact, PolicyProviderRegistry,
                                PolicyProviderSelection, SessionOwner)


class ExampleProvider:

    """Minimal externally supplied policy provider."""

    def __init__(self, options: Mapping[str, str]) -> None:
        self.options = options

    def acquire(self, reference: str, owner: SessionOwner) -> PolicyArtifact:
        del owner
        return PolicyArtifact(reference, Path(self.options["policy_path"]))


class ExampleProviderFactory:

    """Factory used to validate provider registration."""

    name = "test"

    def create(self, options: Mapping[str, str]) -> ExampleProvider:
        if set(options) != {"policy_path"}:
            raise ValueError("test provider requires policy_path")
        return ExampleProvider(options)


def test_registered_provider_is_created() -> None:
    """A registered factory receives its options and creates a usable policy provider."""
    registry = PolicyProviderRegistry((ExampleProviderFactory(),))
    provider = registry.create(PolicyProviderSelection("test", {"policy_path": "/tmp/policy"}))

    artifact = provider.acquire("1.2.3", SessionOwner("session"))

    assert registry.names == ("test",)
    assert artifact.resolved_version == "1.2.3"
    assert artifact.policy_path == Path("/tmp/policy")


@pytest.mark.parametrize("name", ("", "MixedCase", "contains-hyphen"))
def test_invalid_provider_name_is_rejected(name: str) -> None:
    """Provider registration rejects empty or noncanonical factory names."""
    factory = ExampleProviderFactory()
    factory.name = name

    with pytest.raises(ValueError, match="not a valid policy provider name"):
        PolicyProviderRegistry((factory,))


def test_duplicate_provider_is_rejected() -> None:
    """Registering a second factory under an existing name fails explicitly."""
    registry = PolicyProviderRegistry((ExampleProviderFactory(),))

    with pytest.raises(ValueError, match="already registered"):
        registry.register(ExampleProviderFactory())


def test_unknown_provider_lists_available_providers() -> None:
    """Unknown provider errors identify the registered alternatives."""
    registry = PolicyProviderRegistry((ExampleProviderFactory(),))

    with pytest.raises(ValueError, match="available providers: test"):
        registry.create(PolicyProviderSelection("missing", {}))


def test_entry_point_provider_is_loaded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Provider entry points load their factories into the registry."""
    entry_point = EntryPoint(name="test",
                             value="tests.library.mcp.test_policy:ExampleProviderFactory",
                             group="setools.mcp.policy_providers")
    monkeypatch.setattr("setools.mcp.policy.importlib.metadata.entry_points",
                        lambda **_kwargs: (entry_point,))
    registry = PolicyProviderRegistry()

    registry.load_entry_points()

    assert registry.names == ("test",)


def test_entry_point_name_must_match_factory(monkeypatch: pytest.MonkeyPatch) -> None:
    """An entry point cannot register a factory under a mismatched name."""
    entry_point = EntryPoint(name="different",
                             value="tests.library.mcp.test_policy:ExampleProviderFactory",
                             group="setools.mcp.policy_providers")
    monkeypatch.setattr("setools.mcp.policy.importlib.metadata.entry_points",
                        lambda **_kwargs: (entry_point,))

    with pytest.raises(RuntimeError, match="does not match entry point"):
        PolicyProviderRegistry().load_entry_points()
