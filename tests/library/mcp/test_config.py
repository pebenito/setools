# SPDX-License-Identifier: GPL-2.0-only

from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import runpy
from typing import Mapping, cast
from unittest.mock import Mock

import pytest

from setools.mcp.config import MCPConfig, Transport
from setools.mcp.policy import PolicyProviderRegistry, PolicyProviderSelection
from setools.mcp.providers import (AzureDevOpsUniversalPackageProvider,
                                   LocalPolicyProvider,
                                   default_policy_provider_registry)


@pytest.fixture
def config_file(tmp_path):
    """Return a helper that writes an MCP configuration."""
    def write(text: str):
        path = tmp_path / "mcp.ini"
        path.write_text(text, encoding="utf-8")
        return path
    return write


def test_defaults(config_file) -> None:
    """An empty configuration uses safe local defaults."""
    config = MCPConfig.from_file(config_file(""))

    assert config == MCPConfig(transport="http")
    assert config.host == "127.0.0.1"
    assert config.port == 8000
    assert config.mcp_path == "/mcp"
    assert config.host_origin_protection == "auto"
    assert not config.local_paths_allowed
    assert not config.allow_unauthenticated
    assert config.policy_provider.name == "local"
    assert isinstance(config.create_policy_provider(default_policy_provider_registry()),
                      LocalPolicyProvider)


def test_direct_configuration(config_file) -> None:
    """Direct construction and equivalent file settings produce the same configuration."""
    config = MCPConfig(transport="http", host="0.0.0.0", port=9000, mcp_path="/api/mcp",
                       max_session_caches=1, allow_local_paths=False,
                       host_origin_protection=False, allow_unauthenticated=True,
                       max_policy_versions=2, max_session_artifacts=3,
                       max_query_results=250, max_analysis_depth=6)
    loaded = MCPConfig.from_file(config_file("[server]\n"
                                             "host = 0.0.0.0\n"
                                             "port = 9000\n"
                                             "path = /api/mcp\n"
                                             "max_session_caches = 1\n"
                                             "allow_local_paths = false\n"
                                             "host_origin_protection = off\n"
                                             "allow_unauthenticated = true\n"
                                             "max_policy_versions = 2\n"
                                             "max_session_artifacts = 3\n"
                                             "max_query_results = 250\n"
                                             "max_analysis_depth = 6\n"))

    assert config == loaded
    assert isinstance(config.create_policy_provider(default_policy_provider_registry()),
                      LocalPolicyProvider)


def test_configuration_preserves_validated_values() -> None:
    """Frozen settings cannot be mutated, and replacement values are revalidated."""
    config = MCPConfig()

    with pytest.raises(FrozenInstanceError):
        setattr(config, "port", 0)
    with pytest.raises(ValueError, match="not a valid port"):
        replace(config, port=0)


def test_provider_configuration_is_immutable() -> None:
    """Provider options are copied defensively and cannot change after validation."""
    options = {"feed": "original"}
    config = MCPConfig(policy_provider=PolicyProviderSelection("external", options))
    options["feed"] = "changed"
    factory = Mock()
    factory.name = "external"

    config.create_policy_provider(PolicyProviderRegistry((factory,)))

    factory.create.assert_called_once_with({"feed": "original"})
    with pytest.raises(TypeError):
        cast(dict[str, str], config.policy_provider.options)["feed"] = "changed"


@pytest.mark.parametrize("name,values",
                         (("allowed_hosts", ["setools.example"]),
                          ("allowed_origins", ["https://setools.example"])))
def test_request_protection_lists_are_immutable(name, values) -> None:
    """Request protection settings do not retain mutable caller-owned lists."""
    config = MCPConfig(**{name: values})
    expected = tuple(values)
    values.append("untrusted.example")

    assert getattr(config, name) == expected


def test_startup_settings_from_file(config_file) -> None:
    """Configuration files load policy, transport, metadata, and multiline instructions."""
    config = MCPConfig.from_file(config_file("[server]\n"
                                             "default_policy = /srv/policy\n"
                                             "transport = stdio\n"
                                             "name = custom-setools\n"
                                             "instructions = First line.\n"
                                             "    Second line.\n"))

    assert config == MCPConfig(default_policy="/srv/policy", name="custom-setools",
                               instructions="First line.\nSecond line.")


def test_empty_default_policy(config_file) -> None:
    """An empty default policy setting leaves the server without a startup policy."""
    config = MCPConfig.from_file(config_file("[server]\ndefault_policy =\n"))

    assert config.default_policy is None


@pytest.mark.parametrize("from_file", (False, True))
@pytest.mark.parametrize("transport", ("", "sse", "HTTP"))
def test_invalid_transport(config_file, from_file, transport) -> None:
    """Direct and file configuration reject unsupported transport values."""
    with pytest.raises(ValueError, match="not a valid transport"):
        if from_file:
            MCPConfig.from_file(config_file(f"[server]\ntransport = {transport}\n"))
        else:
            MCPConfig(transport=transport)


@pytest.mark.parametrize("port", (1, 65535))
def test_valid_port_boundaries(config_file, port) -> None:
    """Direct and file configuration accept both ends of the valid port range."""
    loaded = MCPConfig.from_file(config_file(f"[server]\nport = {port}\n"))
    assert MCPConfig(transport="http", port=port) == loaded


@pytest.mark.parametrize("from_file", (False, True))
@pytest.mark.parametrize("name,value,message",
                         (("port", 0, "not a valid port"),
                          ("port", 65536, "not a valid port"),
                          ("max_session_caches", 0, "must be at least 1"),
                          ("max_session_caches", -1, "must be at least 1"),
                          ("max_policy_versions", 0, "must be at least 1"),
                          ("max_session_artifacts", 0, "must be at least 1"),
                          ("max_query_results", 0, "must be at least 1"),
                          ("max_analysis_depth", 0, "must be at least 1")))
def test_invalid_numeric_settings(config_file, from_file, name, value, message) -> None:
    """Direct and file configuration reject invalid ports and cache capacities."""
    with pytest.raises(ValueError, match=message):
        if from_file:
            MCPConfig.from_file(config_file(f"[server]\n{name} = {value}\n"))
        else:
            MCPConfig(**{name: value})


@pytest.mark.parametrize("from_file", (False, True))
@pytest.mark.parametrize("name", ("mcp_path", "health_path", "readiness_path"))
@pytest.mark.parametrize("value", ("", "relative", "//example/mcp"))
def test_invalid_route_paths(config_file, from_file, name, value) -> None:
    """HTTP routes must be nonempty absolute paths without an authority component."""
    with pytest.raises(ValueError, match=f"{name} must be an absolute HTTP path"):
        if from_file:
            option = "path" if name == "mcp_path" else name
            MCPConfig.from_file(config_file(f"[server]\n{option} = {value}\n"))
        else:
            MCPConfig(**{name: value})


@pytest.mark.parametrize("from_file", (False, True))
@pytest.mark.parametrize("name,value",
                         (("health_path", "/mcp"),
                          ("readiness_path", "/mcp"),
                          ("readiness_path", "/health")))
def test_duplicate_route_paths(config_file, from_file, name, value) -> None:
    """MCP, health, and readiness routes cannot share the same path."""
    with pytest.raises(ValueError, match="must be distinct"):
        if from_file:
            MCPConfig.from_file(config_file(f"[server]\n{name} = {value}\n"))
        else:
            MCPConfig(**{name: value})


@pytest.mark.parametrize("from_file", (False, True))
@pytest.mark.parametrize("name", ("", "   "))
def test_empty_provider_name(config_file, from_file, name) -> None:
    """Direct and file configuration reject blank provider names."""
    with pytest.raises(ValueError, match="type must not be empty"):
        if from_file:
            MCPConfig.from_file(config_file(f"[policy_provider]\ntype = {name}\n"))
        else:
            MCPConfig(policy_provider=PolicyProviderSelection(name, {}))


@pytest.mark.parametrize("text", ("not an INI section", "[server]\nport = 80\nport = 90\n"))
def test_malformed_configuration(config_file, text) -> None:
    """Malformed INI syntax and duplicate settings produce explicit parsing errors."""
    with pytest.raises(ValueError, match="Unable to parse MCP configuration"):
        MCPConfig.from_file(config_file(text))


@pytest.mark.parametrize("missing", (False, True))
def test_unreadable_configuration(tmp_path, missing) -> None:
    """Missing files and directory paths produce explicit configuration read errors."""
    path = tmp_path / "missing.ini" if missing else tmp_path
    with pytest.raises(ValueError, match="Unable to parse MCP configuration"):
        MCPConfig.from_file(path)


@pytest.mark.parametrize("default", [None, False, True])
@pytest.mark.parametrize("setting", [None, False, True])
def test_local_path_default(config_file, default, setting) -> None:
    """Explicit local-path settings override the caller's default when present."""
    text = "" if setting is None else f"[server]\nallow_local_paths = {setting}\n"
    config = MCPConfig.from_file(config_file(text), default_allow_local_paths=default)

    assert config.allow_local_paths is (default if setting is None else setting)


@pytest.mark.parametrize("transport, setting, expected",
                         [("stdio", None, True), ("http", None, False),
                          ("stdio", False, False), ("http", True, True)])
def test_local_paths_follow_transport_by_default(transport, setting, expected) -> None:
    """Local paths are allowed by default only for stdio, including after replacement."""
    config = MCPConfig(transport=transport, allow_local_paths=setting)

    assert config.local_paths_allowed is expected
    other: Transport = "http" if transport == "stdio" else "stdio"
    assert replace(config, transport=other).local_paths_allowed is (
        expected if setting is not None else not expected)


@pytest.mark.parametrize("from_file", (False, True))
def test_invalid_host_origin_protection(config_file, from_file) -> None:
    """Host/Origin protection accepts only booleans and auto."""
    with pytest.raises(ValueError, match="host_origin_protection"):
        if from_file:
            MCPConfig.from_file(config_file("[server]\nhost_origin_protection = maybe\n"))
        else:
            MCPConfig(host_origin_protection="maybe")  # type: ignore[arg-type]


@pytest.mark.parametrize("setting", [None, False, True])
def test_launcher_local_path_configuration(config_file, monkeypatch, setting) -> None:
    """The launcher preserves configured local-path access and defaults files to HTTP."""
    config = config_file("" if setting is None else f"[server]\nallow_local_paths = {setting}\n")
    server_factory = Mock()
    monkeypatch.setattr("setools.mcp.SEToolsMCPServer", server_factory)
    monkeypatch.setattr("sys.argv", ["setools-mcp", "--config", str(config)])

    runpy.run_path(str(Path(__file__).resolve().parents[3] / "setools-mcp"), run_name="__main__")

    assert server_factory.call_count == 1
    assert server_factory.call_args.args[0].local_paths_allowed is (
        False if setting is None else setting)
    assert server_factory.call_args.args[0].transport == "http"
    server_factory.return_value.run.assert_called_once_with()


@pytest.mark.parametrize("transport_args", [[], ["--transport", "stdio"]])
def test_standalone_stdio_startup_keeps_local_defaults(monkeypatch, transport_args) -> None:
    """Implicit and explicit stdio startup retain the standalone configuration defaults."""
    server_factory = Mock()
    monkeypatch.setattr("setools.mcp.SEToolsMCPServer", server_factory)
    monkeypatch.setattr("sys.argv", ["setools-mcp", *transport_args])

    runpy.run_path(str(Path(__file__).resolve().parents[3] / "setools-mcp"), run_name="__main__")

    server_factory.assert_called_once_with(MCPConfig())
    server_factory.return_value.run.assert_called_once_with()


@pytest.mark.parametrize("with_file", (False, True))
@pytest.mark.parametrize("arguments,changes",
                         (([], {}),
                          (["--policy", "command-line.policy"],
                           {"default_policy": "command-line.policy"}),
                          (["--host", "127.0.0.1"], {"host": "127.0.0.1"}),
                          (["--port", "8000"], {"port": 8000}),
                          (["--transport", "stdio"], {"transport": "stdio"}),
                          (["--transport", "http", "--host", "0.0.0.0", "--port", "9000",
                            "--policy", "cli.policy"],
                           {"transport": "http",
                            "host": "0.0.0.0",
                            "port": 9000,
                            "default_policy": "cli.policy"})))
def test_launcher_configuration_precedence(config_file, monkeypatch, with_file,
                                           arguments, changes) -> None:
    """Only explicit CLI options override file settings or standalone defaults."""
    path = config_file("[server]\n"
                       "host = 192.0.2.1\n"
                       "port = 9001\n"
                       "default_policy = configured.policy\n"
                       "name = configured-server\n"
                       "instructions = Configured instructions.\n"
                       "allow_local_paths = false\n")
    base = MCPConfig.from_file(path) if with_file else MCPConfig()
    server_factory = Mock()
    registry_factory = Mock(return_value=default_policy_provider_registry())
    monkeypatch.setattr("setools.mcp.SEToolsMCPServer", server_factory)
    monkeypatch.setattr("setools.mcp.default_policy_provider_registry", registry_factory)
    file_arguments = ["--config", str(path)] if with_file else []
    monkeypatch.setattr("sys.argv", ["setools-mcp", *file_arguments, *arguments])

    runpy.run_path(str(Path(__file__).resolve().parents[3] / "setools-mcp"), run_name="__main__")

    assert server_factory.call_count == 1
    assert server_factory.call_args.args == (replace(base, **changes),)
    if with_file:
        registry_factory.assert_called_once_with(load_entry_points=True)
        assert isinstance(server_factory.call_args.kwargs["policy_provider"], LocalPolicyProvider)
    else:
        registry_factory.assert_not_called()
        assert not server_factory.call_args.kwargs
    server_factory.return_value.run.assert_called_once_with()


def test_launcher_honors_file_transport(config_file, monkeypatch) -> None:
    """The launcher preserves a file-selected transport when no CLI override is supplied."""
    path = config_file("[server]\ntransport = stdio\n")
    server_factory = Mock()
    monkeypatch.setattr("setools.mcp.SEToolsMCPServer", server_factory)
    monkeypatch.setattr("sys.argv", ["setools-mcp", "--config", str(path)])

    runpy.run_path(str(Path(__file__).resolve().parents[3] / "setools-mcp"), run_name="__main__")

    assert server_factory.call_args.args[0].transport == "stdio"
    server_factory.return_value.run.assert_called_once_with()


@pytest.mark.parametrize("with_file", (False, True))
def test_launcher_rejects_invalid_overrides(config_file, monkeypatch, capsys, with_file) -> None:
    """Invalid CLI overrides fail before server construction with or without a file."""
    path = config_file("[server]\nport = 9000\n")
    server_factory = Mock()
    monkeypatch.setattr("setools.mcp.SEToolsMCPServer", server_factory)
    file_arguments = ["--config", str(path)] if with_file else []
    monkeypatch.setattr("sys.argv", ["setools-mcp", *file_arguments, "--port", "0"])
    launcher = str(Path(__file__).resolve().parents[3] / "setools-mcp")

    with pytest.raises(SystemExit) as error:
        runpy.run_path(launcher, run_name="__main__")

    assert error.value.code == 1
    assert "not a valid port" in capsys.readouterr().out
    server_factory.assert_not_called()


def test_launcher_overrides_do_not_hide_invalid_file(config_file, monkeypatch, capsys) -> None:
    """A valid CLI override cannot conceal an invalid setting in the configuration file."""
    path = config_file("[server]\nport = 0\n")
    server_factory = Mock()
    monkeypatch.setattr("setools.mcp.SEToolsMCPServer", server_factory)
    monkeypatch.setattr("sys.argv", ["setools-mcp", "--config", str(path), "--port", "9000"])
    launcher = str(Path(__file__).resolve().parents[3] / "setools-mcp")

    with pytest.raises(SystemExit) as error:
        runpy.run_path(launcher, run_name="__main__")

    assert error.value.code == 1
    assert "not a valid port" in capsys.readouterr().out
    server_factory.assert_not_called()


def test_azure_devops_provider(config_file, tmp_path) -> None:
    """Azure DevOps provider settings are parsed and constructed."""
    config = MCPConfig.from_file(config_file("[server]\n"
                                             "host = 0.0.0.0\n"
                                             "port = 9000\n"
                                             "path = /api/mcp\n"
                                             "allowed_hosts = setools.example, setools.internal\n"
                                             "allow_local_paths = false\n"
                                             "[policy_provider]\n"
                                             "type = azure_devops\n"
                                             "[policy_provider.azure_devops]\n"
                                             "organization = https://dev.azure.com/example\n"
                                             "project = SELinux\n"
                                             "scope = project\n"
                                             "feed = policies\n"
                                             "package = compiled-policy\n"
                                             "policy_file = policy/policy.bin\n"
                                             "authentication = managed_identity\n"
                                             "managed_identity_client_id = client-id\n"
                                             f"base_dir = {tmp_path}\n"))

    assert config.host == "0.0.0.0"
    assert config.port == 9000
    assert config.allowed_hosts == ("setools.example", "setools.internal")
    assert not config.local_paths_allowed
    assert isinstance(config.create_policy_provider(default_policy_provider_registry()),
                      AzureDevOpsUniversalPackageProvider)


def test_unknown_option_is_rejected(config_file) -> None:
    """Configuration typos fail explicitly."""
    with pytest.raises(ValueError, match="not a valid option"):
        MCPConfig.from_file(config_file("[server]\nbogus = value\n"))


def test_azure_required_options(config_file) -> None:
    """Azure provider construction reports missing required settings."""
    config = MCPConfig.from_file(config_file("[policy_provider]\n"
                                             "type = azure_devops\n"))

    with pytest.raises(ValueError, match="missing required options"):
        config.create_policy_provider(default_policy_provider_registry())


def test_unknown_provider_is_rejected(config_file) -> None:
    """Provider selection is validated by the extensible registry."""
    config = MCPConfig.from_file(config_file("[policy_provider]\n"
                                             "type = unavailable\n"))

    with pytest.raises(ValueError, match="Unknown policy provider"):
        config.create_policy_provider(default_policy_provider_registry())


def test_provider_validates_its_own_options(config_file) -> None:
    """Generic configuration delegates option validation to the provider."""
    config = MCPConfig.from_file(config_file("[policy_provider]\n"
                                             "type = local\n"
                                             "[policy_provider.local]\n"
                                             "bogus = value\n"))

    with pytest.raises(ValueError, match="not a valid local provider option"):
        config.create_policy_provider(default_policy_provider_registry())


def test_external_provider_uses_namespaced_configuration(config_file) -> None:
    """An external provider needs no configuration-parser changes."""
    class Factory:
        name = "external"
        options: Mapping[str, str] = {}

        def create(self, options: Mapping[str, str]) -> LocalPolicyProvider:
            self.options = options
            return LocalPolicyProvider()

    factory = Factory()
    config = MCPConfig.from_file(config_file("[policy_provider]\n"
                                             "type = external\n"
                                             "[policy_provider.external]\n"
                                             "bucket = policies\n"))

    provider = config.create_policy_provider(PolicyProviderRegistry((factory,)))

    assert isinstance(provider, LocalPolicyProvider)
    assert factory.options == {"bucket": "policies"}
