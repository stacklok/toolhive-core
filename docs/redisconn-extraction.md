<!-- SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc. -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Redis connection module extraction

## Design

Redis support is split into independently versioned modules:

- `github.com/stacklok/toolhive-core/redisconn`: provider-neutral standalone,
  cluster, Sentinel, TLS, static-auth, and dynamic credential callback wiring;
  production dependencies are only the Go standard library and
  `github.com/redis/go-redis/v9`.
- `github.com/stacklok/toolhive-core/redisconn/aws`: AWS ElastiCache and
  MemoryDB IAM credentials.
- `github.com/stacklok/toolhive-core/redisconn/azure`: Azure Entra ID
  credentials.
- `github.com/stacklok/toolhive-core/redisconn/gcp`: GCP Memorystore IAM
  credentials.
- The former root `redis` compatibility facade has been removed. The root
  `github.com/stacklok/toolhive-core` module no longer depends on any
  `redisconn` module.

A core `DynamicAuth` value carries a context-aware credentials callback,
`ConnMaxLifetime`, and the explicit `AllowInsecureTransport` escape hatch.
go-redis invokes the callback while each new connection is initialized, before
HELLO/AUTH. `ConnMaxLifetime` only causes an over-age pooled connection to be
retired when it is reused; it is not proactive token refresh or active
reauthentication. In Sentinel mode the callback applies only to Redis data-node
connections and is never installed on Sentinel discovery connections.

The **module dependency graph** of `redisconn` excludes every cloud SDK,
metadata client, Kubernetes module, and ToolHive application package. This is a
stronger and more useful source dependency budget than merely avoiding cloud
imports in core source. It is distinct from **binary closure**: a consumer that
imports a cloud child and core into the same executable will naturally link
reachable code from that child's SDK, while a consumer importing only core will
not acquire those child modules through core's module graph.

## Acceptance plan

- Preserve generic behavior with core tests for topology validation, timeout
  defaults, PING and close-on-PING-failure, TLS 1.2/system roots/custom CA/mTLS,
  independent Sentinel/data TLS, static authentication, callback context and
  installation timing, connection lifetime, and Sentinel credential isolation.
- Preserve provider validation, redacted errors, laziness, and cancellation in
  provider-local tests. Defaults remain 12 minutes for AWS and 45 minutes for
  Azure and GCP.
- Run each module standalone with `GOWORK=off`: tidy/verify, tests (including
  race where supported), vulnerability scanning where the tool is available,
  and a checked-in module-graph budget gate. CI must exercise all modules rather
  than relying on root `./...`, which does not cross nested module boundaries.
- Use no global provider registration or blank imports.

## Migration from the removed `redis` package

The deprecated `github.com/stacklok/toolhive-core/redis` facade was kept from
root `v0.0.44` through `v0.0.55` and removed in a later root release.
Consumers still importing it should import `redisconn` and, when needed,
exactly one typed provider child, migrate `Config` connection fields to
`redisconn.Config`, and build `redisconn.DynamicAuth` with the selected child's
constructor.

## Development and release ordering

`go.work` joins the root and four nested modules for repository development.
Each module also works with `GOWORK=off`; local `replace` directives are used
only where an untagged sibling module is required. These checked-in replacements
are development-only: Go ignores a dependency module's `replace` directives in
downstream builds.

The root module does not require any `redisconn` module, so a root `vX.Y.Z`
tag never needs sibling tags first. Release ordering only applies within the
`redisconn` modules: when a provider needs a new `redisconn` version, tag
`redisconn/vX.Y.Z` first, then pin that version in the provider manifests and
tag `redisconn/aws/vX.Y.Z`, `redisconn/azure/vX.Y.Z`, and
`redisconn/gcp/vX.Y.Z` as needed. Do not fabricate versions.

Release automation and maintainers must use module-prefixed tags for nested
modules.
