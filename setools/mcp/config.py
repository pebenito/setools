# SPDX-License-Identifier: LGPL-2.1-only

import configparser
from dataclasses import dataclass, field
import os
from types import MappingProxyType
from typing import ClassVar, Literal, Self, cast, get_args

from .policy import (PolicyProvider, PolicyProviderRegistry,
                     PolicyProviderSelection)


Transport = Literal["stdio", "http"]
HostOriginProtection = bool | Literal["auto"]


@dataclass(frozen=True)
class MCPConfig:

    """Validated reusable configuration for the SETools MCP server."""

    default_policy: str | None = None
    transport: Transport = "stdio"
    host: str = "127.0.0.1"
    port: int = 8000
    name: str = "setools"
    instructions: str = ("SELinux policy analysis tools built on the setools library.  "
                         "Supports querying TE/RBAC/MLS rules, enumerating policy components, "
                         "domain transition analysis, information flow analysis, policy diffing,"
                         "and file_context lookup.")
    mcp_path: str = "/mcp"
    health_path: str = "/health"
    readiness_path: str = "/ready"
    allowed_hosts: tuple[str, ...] = ()
    allowed_origins: tuple[str, ...] = ()
    host_origin_protection: HostOriginProtection = "auto"
    allow_local_paths: bool | None = None
    """Allow local filesystem paths; None allows them only for the stdio transport."""
    allow_unauthenticated: bool = False
    max_session_caches: int = 64
    max_policy_versions: int = 4
    max_session_artifacts: int = 8
    max_query_results: int = 1000
    max_analysis_depth: int = 10
    policy_provider: PolicyProviderSelection = field(
        default_factory=lambda: PolicyProviderSelection("local", {}))

    TRANSPORTS: ClassVar[tuple[str, ...]] = get_args(Transport)
    _SERVER_OPTIONS: ClassVar[frozenset[str]] = frozenset(("allowed_hosts", "allowed_origins",
                                                           "allow_local_paths",
                                                           "allow_unauthenticated",
                                                           "default_policy", "health_path",
                                                           "host", "host_origin_protection",
                                                           "instructions",
                                                           "max_analysis_depth",
                                                           "max_policy_versions",
                                                           "max_query_results",
                                                           "max_session_artifacts",
                                                           "max_session_caches", "name", "path",
                                                           "port", "readiness_path", "transport"))
    _PROVIDER_OPTIONS: ClassVar[frozenset[str]] = frozenset(("type",))

    def __post_init__(self) -> None:
        if self.transport not in self.TRANSPORTS:
            raise ValueError(f"{self.transport!r} is not a valid transport")
        if not 1 <= self.port <= 65535:
            raise ValueError(f"{self.port} is not a valid port")
        for name, path in (("mcp_path", self.mcp_path),
                           ("health_path", self.health_path),
                           ("readiness_path", self.readiness_path)):
            if not path.startswith("/") or path.startswith("//"):
                raise ValueError(f"{name} must be an absolute HTTP path")
        if len({self.mcp_path, self.health_path, self.readiness_path}) != 3:
            raise ValueError("MCP, health, and readiness paths must be distinct.")
        if self.host_origin_protection not in (True, False, "auto"):
            raise ValueError(f"{self.host_origin_protection!r} is not a valid "
                             "host_origin_protection")
        for name, value in (("max_session_caches", self.max_session_caches),
                            ("max_policy_versions", self.max_policy_versions),
                            ("max_session_artifacts", self.max_session_artifacts),
                            ("max_query_results", self.max_query_results),
                            ("max_analysis_depth", self.max_analysis_depth)):
            if value < 1:
                raise ValueError(f"{name} must be at least 1")
        if not self.policy_provider.name.strip():
            raise ValueError("[policy_provider] type must not be empty")
        object.__setattr__(self, "allowed_hosts", tuple(self.allowed_hosts))
        object.__setattr__(self, "allowed_origins", tuple(self.allowed_origins))
        options = MappingProxyType(dict(self.policy_provider.options))
        object.__setattr__(self, "policy_provider",
                           PolicyProviderSelection(self.policy_provider.name, options))

    @property
    def local_paths_allowed(self) -> bool:
        """Whether tools may read policies and file contexts from local paths."""
        if self.allow_local_paths is None:
            return self.transport == "stdio"
        return self.allow_local_paths

    @classmethod
    def from_file(cls, path: str | os.PathLike[str], *,
                  default_allow_local_paths: bool | None = None) -> Self:
        """Load and validate an MCP configuration file."""
        parser = configparser.ConfigParser()
        source = os.fspath(path)
        try:
            with open(source, "r", encoding="utf-8") as config_file:
                parser.read_file(config_file, source=source)
        except (OSError, configparser.Error) as ex:
            raise ValueError(f"Unable to parse MCP configuration {source}: {ex}") from ex

        cls._reject_unknown(parser, "server", cls._SERVER_OPTIONS)
        cls._reject_unknown(parser, "policy_provider", cls._PROVIDER_OPTIONS)

        defaults = cls()
        provider_name = parser.get("policy_provider", "type",
                                   fallback=defaults.policy_provider.name).strip()
        provider_section = f"policy_provider.{provider_name}"
        provider_options = defaults.policy_provider.options
        if provider_name != defaults.policy_provider.name:
            provider_options = {}
        if parser.has_section(provider_section):
            provider_options = dict(parser.items(provider_section))
        policy_provider = PolicyProviderSelection(provider_name, provider_options)
        return cls(default_policy=parser.get("server", "default_policy",
                                             fallback=defaults.default_policy) or None,
                   transport=cast(Transport, parser.get("server", "transport",
                                                        fallback="http").strip()),
                   host=parser.get("server", "host", fallback=defaults.host).strip(),
                   port=parser.getint("server", "port", fallback=defaults.port),
                   name=parser.get("server", "name", fallback=defaults.name),
                   instructions=parser.get("server", "instructions",
                                           fallback=defaults.instructions),
                   mcp_path=parser.get("server", "path", fallback=defaults.mcp_path).strip(),
                   health_path=parser.get("server", "health_path",
                                          fallback=defaults.health_path).strip(),
                   readiness_path=parser.get("server", "readiness_path",
                                             fallback=defaults.readiness_path).strip(),
                   allowed_hosts=cls._list(parser.get("server", "allowed_hosts", fallback=None),
                                           defaults.allowed_hosts),
                   allowed_origins=cls._list(parser.get("server", "allowed_origins", fallback=None),
                                             defaults.allowed_origins),
                   host_origin_protection=cls._host_origin_protection(
                       parser.get("server", "host_origin_protection", fallback=None),
                       defaults.host_origin_protection),
                   allow_local_paths=cast(bool | None,
                                          parser.getboolean("server", "allow_local_paths",
                                                            fallback=default_allow_local_paths)),
                   allow_unauthenticated=parser.getboolean(
                       "server", "allow_unauthenticated",
                       fallback=defaults.allow_unauthenticated),
                   max_session_caches=parser.getint("server", "max_session_caches",
                                                    fallback=defaults.max_session_caches),
                   max_policy_versions=parser.getint("server", "max_policy_versions",
                                                     fallback=defaults.max_policy_versions),
                   max_session_artifacts=parser.getint("server", "max_session_artifacts",
                                                       fallback=defaults.max_session_artifacts),
                   max_query_results=parser.getint("server", "max_query_results",
                                                   fallback=defaults.max_query_results),
                   max_analysis_depth=parser.getint("server", "max_analysis_depth",
                                                    fallback=defaults.max_analysis_depth),
                   policy_provider=policy_provider)

    @staticmethod
    def _host_origin_protection(value: str | None,
                                default: HostOriginProtection) -> HostOriginProtection:
        """Parse a boolean or "auto" Host/Origin protection setting."""
        if value is None:
            return default
        value = value.strip().lower()
        if value == "auto":
            return "auto"
        try:
            return {"true": True, "yes": True, "on": True, "1": True,
                    "false": False, "no": False, "off": False, "0": False}[value]
        except KeyError:
            raise ValueError(f"{value!r} is not a valid host_origin_protection") from None

    @staticmethod
    def _list(value: str | None, default: tuple[str, ...]) -> tuple[str, ...]:
        """Parse a comma-separated string list or use the model default."""
        if value is None:
            return default
        return tuple(item.strip() for item in value.split(",") if item.strip())

    @staticmethod
    def _reject_unknown(parser: configparser.ConfigParser, section: str,
                        allowed: frozenset[str]) -> None:
        """Reject unknown options in *section*."""
        if parser.has_section(section):
            unknown = set(parser.options(section)) - allowed
            if unknown:
                raise ValueError(f"[{section}]: {min(unknown)} is not a valid option")

    def create_policy_provider(self, registry: PolicyProviderRegistry) -> PolicyProvider:
        """Create the configured reusable policy provider."""
        return registry.create(self.policy_provider)
