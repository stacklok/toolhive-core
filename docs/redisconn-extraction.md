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
- The root `redis` package remains a deprecated, source-compatible facade and
  translates legacy configuration to the extracted modules.

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
- Test the deprecated facade's validation selection, mutual exclusion, error
  behavior, and translation paths without duplicating connection security code.
- Run each module standalone with `GOWORK=off`: tidy/verify, tests (including
  race where supported), vulnerability scanning where the tool is available,
  and a checked-in module-graph budget gate. CI must exercise all modules rather
  than relying on root `./...`, which does not cross nested module boundaries.
- Use no global provider registration or blank imports.

## Compatibility window and migration

The proposed compatibility window, based on the current root tag `v0.0.43`, is
to retain deprecated `github.com/stacklok/toolhive-core/redis` for at least root
`v0.0.44` and `v0.0.45`. Removal may occur only in a later, explicitly
announced breaking root release. This is an **owner/release decision requiring
maintainer confirmation**, not a release commitment made by this extraction.

New consumers should import `redisconn` and, when needed, exactly one typed
provider child. Existing consumers can continue using `redis` during the
window, then migrate `Config` connection fields to `redisconn.Config` and build
`redisconn.DynamicAuth` with the selected child's constructor.

## Development and release ordering

`go.work` joins the root and four nested modules for repository development.
Each module also works with `GOWORK=off`; local `replace` directives are used
only where an untagged sibling module is required. These checked-in replacements
are development-only: Go ignores a dependency module's `replace` directives in
downstream builds.

Do not fabricate versions. For a coordinated release, tag in dependency order,
updating each dependent module's `require` before its tag:

1. tag `redisconn/vX.Y.Z`;
2. update the three provider modules from the development-only `redisconn
   v0.0.0` requirement to that released core version, then tag
   `redisconn/aws/vX.Y.Z`;
3. tag `redisconn/azure/vX.Y.Z`;
4. tag `redisconn/gcp/vX.Y.Z`;
5. update or remove the root module's local replacements and replace its
   `v0.0.0` requirements with the released child versions, then publish a
   subsequent root tag.

Release automation and maintainers must use module-prefixed tags for nested
modules. No external release is part of this change.
