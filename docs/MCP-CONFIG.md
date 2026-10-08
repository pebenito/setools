# SETools MCP Server Configuration

The SETools MCP server runs over stdio by default. For HTTP, supply `--config PATH` to
configure a hosted server (or an explicit `allow_local_paths = true` / `allow_unauthenticated = true`
policy; standalone `--transport http` without `--config` is refused because HTTP disables local
paths by default and has no authentication provider):

```console
setools-mcp --config /etc/setools/mcp.ini
```

Supplying a configuration file defaults to Streamable HTTP unless its `transport` option or an
explicit `--transport` argument selects stdio. Explicit `--policy`, `--transport`, `--host`, and
`--port` arguments override file values; omitted arguments leave the file settings intact.
Configuration files must be valid even when a value would be overridden.

Authentication remains an injected `FastMCP` `AuthProvider`; the provider owns bearer-token
validation, `401` challenges, and
RFC 9728 Protected Resource Metadata. Deployment-specific subclasses can inject authentication,
session ownership, readiness checks, and audit sinks without changing SETools analysis tools.

An HTTP server with local paths disabled refuses to start without an authentication provider,
because policy artifacts are owned by the authenticated caller. The standalone launcher does not
configure authentication, so such a deployment must either be embedded by a host that injects an
`AuthProvider` or set `allow_unauthenticated = true`. Only set that option when an authenticating
reverse proxy restricts access to the server; all callers then share one identity, and artifacts
are isolated only by MCP session.

## Server settings

```ini
[server]
transport = http
name = setools
# Optional trusted startup policy and custom MCP instructions:
# default_policy = /srv/selinux/policy.bin
# instructions = Deployment-specific instructions.
host = 127.0.0.1
port = 8000
path = /mcp
health_path = /health
readiness_path = /ready
max_session_caches = 64
max_session_artifacts = 8
max_policy_versions = 4
max_query_results = 1000
max_analysis_depth = 10
# Defaults to true for stdio and false for HTTP.
# allow_local_paths = false
allow_unauthenticated = false

# Host and Origin request protection: true, false, or auto.  auto protects loopback binds;
# use true with exact allowlists for any other bind address.
host_origin_protection = true
allowed_hosts = setools.example.com
allowed_origins = https://setools.example.com
```

The liveness and readiness routes are unauthenticated operational endpoints. Readiness responses
contain only each check's name and state; check details and failures are logged by the server.
A check that raises an exception is reported as not ready.

`host_origin_protection` defaults to `auto`, which enables FastMCP DNS-rebinding protection for
loopback binds and for any configured allowlists. Set it to `true` with exact `allowed_hosts` and
`allowed_origins` for hosted deployments, or `false` only when an edge proxy enforces them.

When local paths are disabled, clients must use opaque references returned by
`setools_tool_load_policy_versions`; they cannot request arbitrary files on the server.
`allow_local_paths` defaults to `true` for stdio and `false` for HTTP, including when
`--transport` overrides the configured transport. An explicit configuration value overrides the
default. Embedded hosts can select a different default with
`MCPConfig.from_file(path, default_allow_local_paths=...)`.

`max_policy_versions` limits the versions acquired by one `setools_tool_load_policy_versions`
call, and `max_session_artifacts` limits the artifacts one session may hold. Together with
`max_session_caches`, they bound the artifacts and policies the server keeps in memory and on
disk. When local paths are disabled, `max_query_results` also bounds `max_results` and
`max_per_component` per tool call, and `max_analysis_depth` bounds `depth_limit` (disallowing
unlimited `None` searches).

When local paths are disabled, FastMCP error-detail masking is enabled (`mask_error_details=True`),
and `setools_tool_get_policy_info` omits the server-local filesystem `path` field.

`default_policy` selects a trusted server-local startup policy; omit it or leave it empty to retain
the default policy-loading behavior. The default policy is loaded once and shared read-only by
all sessions; tools select it when their policy argument is omitted or empty. `name` and `instructions` customize MCP metadata. Instructions
can span multiple lines using indented INI continuation lines.

`MCPConfig` is a frozen dataclass and the sole source of server startup settings. Load INI settings
with `MCPConfig.from_file(path)`, or construct them directly, for example
`MCPConfig(transport="http", host="0.0.0.0", allow_local_paths=False)`. Direct construction defaults to
stdio, whereas file loading defaults to HTTP. Both forms validate the transport, port range,
nonempty provider name, distinct absolute route paths, Host/Origin protection mode, and positive
session, artifact, and version limits.
Provider-specific options are validated when `create_policy_provider()` is called. Request-protection
lists and provider options are immutable snapshots rather than references to caller-owned containers.

Embedded hosts pass the configuration object directly to the server:

```python
from setools.mcp import MCPConfig, SEToolsMCPServer

config = MCPConfig.from_file("/etc/setools/mcp.ini")
server = SEToolsMCPServer(config)
server.run()
```

Server construction and `run()` do not accept separate startup settings. Authentication, provider
instances, session ownership, readiness checks, and audit sinks remain injected services. Without an
injected provider, the server creates the configured built-in provider. Hosts using custom factories
can call `config.create_policy_provider(registry)` and inject the resulting provider instance.
The configured launcher explicitly discovers installed provider factories.

To change settings, use `dataclasses.replace(config, ...)` or construct another `MCPConfig`, then
create a new server. Changes are validated during construction; hot reload or replacing the config
on an existing server is not supported.

## Local provider

The local provider preserves traditional filesystem-path behavior:

```ini
[policy_provider]
type = local
```

Local-provider acquisition requires `allow_local_paths = true`. When local paths are disabled,
`setools_tool_load_policy_versions` rejects local-provider requests before acquisition or policy
loading, including when the provider selection was omitted and defaulted to `local`. Hosted
deployments should explicitly select a non-local provider such as `azure_devops`.

## Azure DevOps Universal Packages

Azure Artifacts does not provide a direct content-download REST endpoint for Universal Packages.
The provider invokes `az artifacts universal download`, so the Azure CLI and Azure DevOps extension
must already be installed. Runtime extension installation is disabled.

```ini
[server]
host = 0.0.0.0
port = 8000
path = /mcp
allow_local_paths = false
allowed_hosts = setools.example.com

[policy_provider]
type = azure_devops

[policy_provider.azure_devops]
organization = https://dev.azure.com/example
project = SELinux
scope = project
feed = policies
package = compiled-policy
policy_file = policy/policy.bin
file_contexts_file = policy/file_contexts
authentication = managed_identity
managed_identity_client_id = 00000000-0000-0000-0000-000000000000
timeout_seconds = 120
max_package_bytes = 536870912
base_dir = /var/cache/setools-mcp
```

Supported authentication values are:

| Value              | Behavior                                                      |
| ------------------ | ------------------------------------------------------------- |
| `existing`         | Use the Azure CLI identity already available to the process.  |
| `managed_identity` | Run `az login --identity` before downloading each package.    |

With `managed_identity`, each download uses a private temporary Azure CLI configuration directory
outside the artifact directory, removed as soon as the download finishes. `existing` uses the
process's Azure CLI configuration, such as `AZURE_CONFIG_DIR` or `~/.azure`.

`max_package_bytes` is enforced after the Azure CLI download completes, so `base_dir` must have
room for the largest package the feed can serve; the limit rejects oversized packages but does not
bound transient disk use.

Only exact immutable versions such as `1.2.3` are accepted. Organization, project, feed, package,
and package-internal paths are trusted server configuration and cannot be selected by callers.

The configured Azure DevOps identity determines which packages the server can read. If it has
application-wide Feed Reader access, authorization to call this SETools deployment consequently
permits analysis of every package version exposed through the configured feed.

## External providers

Policy providers are selected by name rather than by Python module or class path. The generic
launcher registers the built-in `local` and `azure_devops` providers, then discovers installed
provider factories from the `setools.mcp.policy_providers` Python entry-point group. An installed
provider can therefore add an Amazon S3, HTTP, or other acquisition mechanism without changing
`MCPConfig` or `SEToolsMCPServer`.

For example, a distribution providing a factory named `s3` declares an entry point similar to:

```toml
[project.entry-points."setools.mcp.policy_providers"]
s3 = "example_setools_s3:S3PolicyProviderFactory"
```

Its configuration is then namespaced under the same registered name:

```ini
[policy_provider]
type = s3

[policy_provider.s3]
bucket = example-policy-bucket
key_prefix = compiled-policies
```

The entry-point name must match the factory's `name`. Duplicate or invalid provider names fail
startup. Configuration cannot load arbitrary module or class paths.

Providers that download directory trees should use the reusable artifact acquisition utilities.
They create private staging directories, reject unsafe relative paths and symbolic links, enforce
an aggregate byte limit, locate configured expected files, and clean up partial acquisitions.
Provider-specific implementations remain responsible for authentication, transport security,
immutable version semantics, and mapping their options to those safeguards.

## Session isolation

Downloaded artifacts and loaded policy handles are owned by the authenticated caller (token
issuer and subject) and the negotiated MCP session. Client-supplied session headers are not
trusted for ownership. Requests without a negotiated session are scoped to the caller alone.
References are opaque and cannot be resolved by another caller or session. Session eviction and
server shutdown invoke the provider cleanup callback and release the associated policy handles
and files.

Initial multi-replica deployments must use session affinity unless they provide a shared session
implementation. The built-in session cache is process-local.
