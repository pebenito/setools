# SPDX-License-Identifier: LGPL-2.1-only

import enum
import logging
import math
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from typing import Mapping, Protocol, Sequence

from ..policy import PolicyArtifact, SessionOwner
from .artifact import (create_artifact_directory, remove_artifact_directory,
                       resolve_artifact_file, validate_artifact_path,
                       validate_artifact_tree)


_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:-[0-9A-Za-z.-]+)?$")


class FeedScope(enum.StrEnum):

    """Azure Artifacts feed scopes."""

    organization = enum.auto()
    project = enum.auto()


class CommandRunner(Protocol):

    """Run a command without a shell."""

    def run(self, args: Sequence[str], *, env: Mapping[str, str],
            timeout: float) -> subprocess.CompletedProcess[str]:
        """Run *args* with *env* and *timeout*."""


class SubprocessCommandRunner:

    """Run commands using :func:`subprocess.run`."""

    def run(self, args: Sequence[str], *, env: Mapping[str, str],
            timeout: float) -> subprocess.CompletedProcess[str]:
        """Run *args* without a shell and capture diagnostic output."""
        return subprocess.run(args,  # noqa: S603  # arguments are constructed and validated
                              check=True,
                              capture_output=True,
                              env=env,
                              shell=False,
                              text=True,
                              timeout=timeout)


class AzureCLIAuthentication(Protocol):

    """Prepare Azure CLI authentication for one package acquisition."""

    isolated_config: bool
    """Whether each acquisition uses a private, temporary Azure CLI configuration."""

    def prepare(self, runner: CommandRunner, env: Mapping[str, str], timeout: float) -> None:
        """Prepare authentication for a subsequent Azure CLI command."""


class ExistingAzureCLIAuthentication:

    """Use the Azure CLI identity already available to the process."""

    isolated_config = False

    def prepare(self, runner: CommandRunner, env: Mapping[str, str], timeout: float) -> None:
        """Leave the existing Azure CLI authentication unchanged."""
        del runner, env, timeout


class ManagedIdentityAzureCLIAuthentication:

    """Authenticate Azure CLI using an Azure managed identity."""

    isolated_config = True

    def __init__(self, client_id: str | None = None) -> None:
        self.client_id = client_id

    def prepare(self, runner: CommandRunner, env: Mapping[str, str], timeout: float) -> None:
        """Log Azure CLI in using the configured managed identity."""
        args = ["az", "login", "--identity", "--allow-no-subscriptions"]
        if self.client_id:
            args.extend(("--client-id", self.client_id))
        runner.run(args, env=env, timeout=timeout)


class AzureDevOpsProviderFactory:

    """Create Azure DevOps Universal Package policy providers."""

    name = "azure_devops"
    _OPTIONS = frozenset(("authentication", "base_dir", "feed", "file_contexts_file",
                          "managed_identity_client_id", "max_package_bytes", "organization",
                          "package", "policy_file", "project", "scope", "timeout_seconds"))
    _REQUIRED = ("organization", "feed", "package", "policy_file")

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner

    def create(self, options: Mapping[str, str]) -> "AzureDevOpsUniversalPackageProvider":
        """Validate *options* and create the configured provider."""
        unknown = set(options) - self._OPTIONS
        if unknown:
            raise ValueError(f"{min(unknown)} is not a valid azure_devops provider option")
        missing = tuple(name for name in self._REQUIRED if not options.get(name, "").strip())
        if missing:
            raise ValueError(
                f"azure_devops provider is missing required options: {', '.join(missing)}")

        authentication_name = options.get("authentication", "existing").strip()
        authentication: AzureCLIAuthentication
        if authentication_name == "existing":
            authentication = ExistingAzureCLIAuthentication()
        elif authentication_name == "managed_identity":
            authentication = ManagedIdentityAzureCLIAuthentication(
                options.get("managed_identity_client_id"))
        else:
            raise ValueError(f"Unknown Azure CLI authentication: {authentication_name}")

        scope_name = options.get("scope", FeedScope.organization.value).strip()
        try:
            scope = FeedScope(scope_name)
        except ValueError as ex:
            raise ValueError(f"Unknown Azure DevOps feed scope: {scope_name}") from ex

        base_dir_value = options.get("base_dir")
        return AzureDevOpsUniversalPackageProvider(
            organization=options["organization"],
            project=options.get("project"),
            scope=scope,
            feed=options["feed"],
            package=options["package"],
            policy_file=options["policy_file"],
            file_contexts_file=options.get("file_contexts_file"),
            authentication=authentication,
            runner=self.runner,
            base_dir=Path(base_dir_value) if base_dir_value else None,
            timeout=float(options.get("timeout_seconds", "120")),
            max_package_bytes=int(options.get("max_package_bytes", str(512 * 1024 * 1024))))


class AzureDevOpsUniversalPackageProvider:

    """Acquire immutable SELinux policies from an Azure Artifacts feed."""

    def __init__(self,
                 *,
                 organization: str,
                 feed: str,
                 package: str,
                 policy_file: str,
                 project: str | None = None,
                 scope: FeedScope = FeedScope.organization,
                 file_contexts_file: str | None = None,
                 authentication: AzureCLIAuthentication | None = None,
                 runner: CommandRunner | None = None,
                 base_dir: Path | None = None,
                 timeout: float = 120,
                 max_package_bytes: int = 512 * 1024 * 1024) -> None:
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a finite number greater than zero")
        if max_package_bytes < 1:
            raise ValueError("max_package_bytes must be at least 1")
        if scope is FeedScope.project and not project:
            raise ValueError("project is required for a project-scoped feed")

        self.organization = organization
        self.project = project
        self.scope = scope
        self.feed = feed
        self.package = package
        self.policy_file = validate_artifact_path(policy_file)
        self.file_contexts_file = (
            validate_artifact_path(file_contexts_file)
            if file_contexts_file is not None
            else None)
        self.authentication = authentication or ExistingAzureCLIAuthentication()
        self.runner = runner or SubprocessCommandRunner()
        self.base_dir = base_dir
        self.timeout = timeout
        self.max_package_bytes = max_package_bytes

    @staticmethod
    def _validate_version(version: str) -> None:
        """Validate an exact Universal Package version."""
        if not _VERSION_PATTERN.fullmatch(version):
            raise ValueError(f"{version!r} is not an exact package version")

    def acquire(self, reference: str, owner: SessionOwner) -> PolicyArtifact:
        """Download and validate the exact package version in *reference*."""
        del owner
        self._validate_version(reference)
        directory = create_artifact_directory(self.base_dir)
        env = dict(os.environ)
        env["AZURE_EXTENSION_USE_DYNAMIC_INSTALL"] = "no"
        config_dir: str | None = None

        try:
            if self.authentication.isolated_config:
                # Keep the login token cache out of the artifact directory and remove it
                # as soon as the download finishes.
                config_dir = tempfile.mkdtemp(prefix="setools-azure-")
                env["AZURE_CONFIG_DIR"] = config_dir
            try:
                self.authentication.prepare(self.runner, env, self.timeout)
                self.runner.run(self._download_args(reference, directory),
                                env=env, timeout=self.timeout)
            except subprocess.TimeoutExpired as ex:
                logging.getLogger(__name__).error("Azure CLI command timed out")
                raise RuntimeError("Azure DevOps package download timed out") from ex
            except subprocess.SubprocessError as ex:
                logging.getLogger(__name__).error(
                    f"Azure CLI command failed: {type(ex).__name__}")
                raise RuntimeError("Azure DevOps package download failed") from ex
            validate_artifact_tree(directory, self.max_package_bytes)
            policy_path = resolve_artifact_file(directory, self.policy_file)
            file_contexts_path = (
                resolve_artifact_file(directory, self.file_contexts_file)
                if self.file_contexts_file is not None
                else None)
        except BaseException:
            remove_artifact_directory(directory)
            raise
        finally:
            if config_dir is not None:
                shutil.rmtree(config_dir, ignore_errors=True)

        return PolicyArtifact(reference,
                              policy_path,
                              file_contexts_path,
                              cleanup=lambda: remove_artifact_directory(directory))

    def _download_args(self, version: str, directory: Path) -> list[str]:
        """Build the Azure CLI download arguments."""
        args = ["az", "artifacts", "universal", "download",
                "--organization", self.organization,
                "--scope", self.scope.value,
                "--feed", self.feed,
                "--name", self.package,
                "--version", version,
                "--path", str(directory)]
        if self.project is not None:
            args.extend(("--project", self.project))
        return args
