# SPDX-License-Identifier: GPL-2.0-only

from pathlib import Path
import subprocess
from typing import Mapping, Sequence

import pytest

from setools.mcp.policy import SessionOwner
from setools.mcp.providers import (AzureDevOpsProviderFactory,
                                   AzureDevOpsUniversalPackageProvider, FeedScope,
                                   ManagedIdentityAzureCLIAuthentication)


class DownloadRunner:

    """Azure CLI runner test double that creates expected package files."""

    def __init__(self) -> None:
        self.calls: list[tuple[tuple[str, ...], Mapping[str, str], float]] = []

    def run(self, args: Sequence[str], *, env: Mapping[str, str],
            timeout: float) -> subprocess.CompletedProcess[str]:
        """Record the call and emulate a successful package download."""
        self.calls.append((tuple(args), env, timeout))
        if "download" in args:
            path = Path(args[args.index("--path") + 1])
            (path / "policy").mkdir()
            (path / "policy" / "policy.bin").write_bytes(b"policy")
            (path / "policy" / "file_contexts").write_text("/.* system_u:object_r:default_t:s0\n",
                                                           encoding="utf-8")
        return subprocess.CompletedProcess(args, 0, "", "")


def test_downloads_exact_version_with_managed_identity(tmp_path) -> None:
    """The provider authenticates, downloads, validates, and cleans a package."""
    runner = DownloadRunner()
    provider = AzureDevOpsUniversalPackageProvider(
        organization="https://dev.azure.com/example",
        project="SELinux",
        scope=FeedScope.project,
        feed="policies",
        package="compiled-policy",
        policy_file="policy/policy.bin",
        file_contexts_file="policy/file_contexts",
        authentication=ManagedIdentityAzureCLIAuthentication("client-id"),
        runner=runner,
        base_dir=tmp_path,
        timeout=30)

    artifact = provider.acquire("1.2.3", SessionOwner("session"))

    assert artifact.policy_path.read_bytes() == b"policy"
    assert artifact.file_contexts_path is not None
    assert runner.calls[0][0] == ("az", "login", "--identity", "--allow-no-subscriptions",
                                  "--client-id", "client-id")
    download = runner.calls[1][0]
    assert download[download.index("--version") + 1] == "1.2.3"
    assert download[download.index("--scope") + 1] == "project"
    assert runner.calls[1][1]["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] == "no"

    directory = artifact.policy_path.parents[1]
    assert artifact.cleanup is not None
    artifact.cleanup()
    assert not directory.exists()


@pytest.mark.parametrize("fail", (False, True))
def test_managed_identity_config_is_private_and_removed(tmp_path, fail) -> None:
    """Managed identity logins use a temporary config outside the artifact directory."""
    class Runner(DownloadRunner):
        """Runner that records the Azure CLI configuration directory."""

        def run(self, args: Sequence[str], *, env: Mapping[str, str],
                timeout: float) -> subprocess.CompletedProcess[str]:
            assert Path(env["AZURE_CONFIG_DIR"]).is_dir()
            if fail and "download" in args:
                self.calls.append((tuple(args), env, timeout))
                raise subprocess.CalledProcessError(1, args)
            return super().run(args, env=env, timeout=timeout)

    (tmp_path / "artifacts").mkdir()
    runner = Runner()
    provider = AzureDevOpsUniversalPackageProvider(
        organization="https://dev.azure.com/example",
        feed="policies",
        package="compiled-policy",
        policy_file="policy/policy.bin",
        authentication=ManagedIdentityAzureCLIAuthentication(),
        runner=runner,
        base_dir=tmp_path / "artifacts")

    if fail:
        with pytest.raises(RuntimeError, match="package download failed") as excinfo:
            provider.acquire("1.2.3", SessionOwner("session"))
        assert "dev.azure.com" not in str(excinfo.value)
        assert str(tmp_path) not in str(excinfo.value)
    else:
        provider.acquire("1.2.3", SessionOwner("session"))

    config_dirs = {call[1]["AZURE_CONFIG_DIR"] for call in runner.calls}
    assert len(config_dirs) == 1
    config_dir = Path(config_dirs.pop())
    assert not config_dir.exists()
    assert tmp_path / "artifacts" not in config_dir.parents


def test_existing_authentication_uses_process_config(tmp_path, monkeypatch) -> None:
    """Existing authentication keeps the process Azure CLI configuration."""
    monkeypatch.setenv("AZURE_CONFIG_DIR", "/home/user/.azure")
    runner = DownloadRunner()
    provider = AzureDevOpsUniversalPackageProvider(organization="https://dev.azure.com/example",
                                                   feed="policies",
                                                   package="compiled-policy",
                                                   policy_file="policy/policy.bin",
                                                   runner=runner,
                                                   base_dir=tmp_path)

    provider.acquire("1.2.3", SessionOwner("session"))

    assert len(runner.calls) == 1
    assert runner.calls[0][1]["AZURE_CONFIG_DIR"] == "/home/user/.azure"


@pytest.mark.parametrize("version", ("latest", "1.2.*", "../1.2.3", "1.2"))
def test_rejects_non_exact_versions(tmp_path, version) -> None:
    """Only immutable exact Universal Package versions are accepted."""
    provider = AzureDevOpsUniversalPackageProvider(organization="https://dev.azure.com/example",
                                                   feed="policies",
                                                   package="compiled-policy",
                                                   policy_file="policy.bin",
                                                   runner=DownloadRunner(),
                                                   base_dir=tmp_path)

    with pytest.raises(ValueError, match="exact package version"):
        provider.acquire(version, SessionOwner("session"))


@pytest.mark.parametrize("timeout", (0, -1, float("nan"), float("inf")))
def test_rejects_invalid_timeouts(timeout) -> None:
    """Non-positive and non-finite timeouts are rejected."""
    with pytest.raises(ValueError, match="timeout"):
        AzureDevOpsUniversalPackageProvider(organization="https://dev.azure.com/example",
                                            feed="policies",
                                            package="compiled-policy",
                                            policy_file="policy.bin",
                                            timeout=timeout)


def test_timeout_omits_command_details(tmp_path) -> None:
    """Subprocess timeouts do not expose CLI arguments or staging paths."""
    class TimeoutRunner:
        """Runner raising TimeoutExpired."""

        def run(self, args: Sequence[str], *, env: Mapping[str, str],
                timeout: float) -> subprocess.CompletedProcess[str]:
            del env
            raise subprocess.TimeoutExpired(args, timeout)

    provider = AzureDevOpsUniversalPackageProvider(organization="https://dev.azure.com/example",
                                                   feed="policies",
                                                   package="compiled-policy",
                                                   policy_file="policy.bin",
                                                   runner=TimeoutRunner(),
                                                   base_dir=tmp_path)

    with pytest.raises(RuntimeError, match="timed out") as excinfo:
        provider.acquire("1.2.3", SessionOwner("session"))
    assert "dev.azure.com" not in str(excinfo.value)
    assert str(tmp_path) not in str(excinfo.value)


def test_project_scope_requires_project() -> None:
    """Project-scoped feeds require an explicit project."""
    with pytest.raises(ValueError, match="project is required"):
        AzureDevOpsUniversalPackageProvider(organization="https://dev.azure.com/example",
                                            scope=FeedScope.project,
                                            feed="policies",
                                            package="compiled-policy",
                                            policy_file="policy.bin")


def test_factory_creates_provider(tmp_path) -> None:
    """The provider is constructible through the generic factory interface."""
    provider = AzureDevOpsProviderFactory(DownloadRunner()).create({
        "organization": "https://dev.azure.com/example",
        "feed": "policies",
        "package": "compiled-policy",
        "policy_file": "policy/policy.bin",
        "base_dir": str(tmp_path)})

    artifact = provider.acquire("1.2.3", SessionOwner("session"))

    assert artifact.resolved_version == "1.2.3"


def test_factory_rejects_unknown_options() -> None:
    """Provider-specific configuration rejects misspelled options."""
    with pytest.raises(ValueError, match="not a valid azure_devops"):
        AzureDevOpsProviderFactory().create({"organization": "https://dev.azure.com/example",
                                             "feed": "policies",
                                             "package": "compiled-policy",
                                             "policy_file": "policy.bin",
                                             "bogus": "value"})


@pytest.mark.parametrize("path", ("/policy.bin", "../policy.bin", "a/../../policy.bin"))
def test_rejects_unsafe_package_paths(path) -> None:
    """Configured package paths cannot escape the download directory."""
    with pytest.raises(ValueError, match="safe artifact-relative path"):
        AzureDevOpsUniversalPackageProvider(organization="https://dev.azure.com/example",
                                            feed="policies",
                                            package="compiled-policy",
                                            policy_file=path)
