# toolhive-core

[![Release][release-img]][release] [![Build Status][ci-img]][ci]
[![Coverage Status][coveralls-img]][coveralls]
[![License: Apache 2.0][license-img]][license]
[![Star on GitHub][stars-img]][stars]

The ToolHive Platform common libraries and specifications.

`toolhive-core` provides stable, well-tested Go utilities with explicit API guarantees for the ToolHive ecosystem. Projects like [toolhive](https://github.com/stacklok/toolhive), [dockyard](https://github.com/stacklok/dockyard), [toolhive-registry](https://github.com/stacklok/toolhive-registry), and [toolhive-registry-server](https://github.com/stacklok/toolhive-registry-server) depend on this library for shared functionality.

## Why toolhive-core?

The ToolHive ecosystem spans multiple Go repositories, and several of these projects need to share common utilities. Rather than having projects import internal packages from `toolhive` (which have no stability guarantees), `toolhive-core` provides:

- **Stability guarantees**: Packages follow semantic versioning with explicit API commitments
- **Clear maturity levels**: Each package is marked as Stable, Beta, or Alpha
- **Tested and documented**: All packages meet minimum quality standards before inclusion
- **Independent versioning**: Evolves on its own release cadence, decoupled from `toolhive` releases

## Available Packages

| Package | Stability | Description |
|---------|-----------|-------------|
| `cel` | Alpha | Generic CEL expression compilation and evaluation |
| `env` | Stable | Environment variable abstraction with `Reader` interface |
| `httperr` | Stable | Wrap errors with HTTP status codes |
| `logging` | Alpha | Pre-configured `*slog.Logger` factory with consistent ToolHive defaults |
| `telemetry/metrics` | Alpha | Shared OTel histogram bucket presets, label-key constants, and emitter-ownership vocabulary |
| `telemetry/reconcile` | Alpha | Unified operator reconcile metric emitter |
| `oci/skills` | Alpha | OCI artifact types, media types, and registry operations for skills |
| `oci/plugins` | Alpha | OCI artifact types, media types, and registry operations for plugins |
| `authn` | Alpha | Inbound OIDC/JWT bearer-token validation for resource servers |
| `networking` | Alpha | Outbound HTTP client construction with SSRF egress policy: private-IP/link-local dial blocking, redirect policy, body-capped JSON fetch, endpoint/issuer URL + private-IP validation helpers, and port allocation/validation utilities |
| `postgres` | Alpha | PostgreSQL connection pool with optional cloud IAM dynamic auth |
| `redisconn` | Alpha | Lean Redis/Valkey client construction for standalone, cluster, and Sentinel deployments |
| `redisconn/aws` | Alpha | AWS ElastiCache/MemoryDB IAM credentials for `redisconn` |
| `redisconn/azure` | Alpha | Azure Entra ID credentials for `redisconn` |
| `redisconn/gcp` | Alpha | GCP Memorystore IAM credentials for `redisconn` |
| `redis` | Deprecated | Source-compatible facade; migrate to `redisconn` and a provider child module |
| `recovery` | Beta | HTTP panic recovery middleware |
| `validation/http` | Stable | RFC 7230/8707 compliant HTTP header and URI validation |
| `validation/group` | Stable | Group name validation |

## Registry JSON validation

`registry/types.ValidateServerJSON(data, validateExtensions)` always validates the
**original bytes** against the embedded MCP **2025-12-11** server schema. The
submitted `$schema` URI does not select a schema and is never fetched. Missing
required fields, wrong types, schema constraint violations, and `packages: null`
are rejected; omission of `packages` is permitted.

The embedded schema is the published
[2025-12-11 schema](https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json)
(SHA-256 `3fba09590c99f61735d234822279f4223fab9e300c0a81e81c91ab62a4114de0`),
with one local semantic patch: `package.version` has `maxLength: 255`. That
constraint comes from the [registry v1.8.1 draft schema](https://raw.githubusercontent.com/modelcontextprotocol/registry/v1.8.1/docs/reference/server-json/draft/server.schema.json)
(SHA-256 `e81b689767ce00722800b2c838ff7e93f6fb1d7bb6d7b2249250f66e4dc4d8c8`).
The draft is not the released dated schema, so its other changes are excluded:
its `$id`, Cargo/crates.io documentation, and URL patterns that allow a leading
template variable. `pkg/api/v0` is the registry Go API import path; module
`v1.8.1` is its module release; neither selects the dated embedded schema.

All public raw validators in `registry/types` require one complete JSON value and
reject malformed/trailing input, duplicate decoded member names at any depth
(including escape-equivalent names), invalid UTF-8, and unpaired Unicode escapes
before decoding to maps or structs. Member names are case-sensitive: `name` and
`Name` are distinct, and only `name` satisfies the required MCP property. These
checks use Go 1.27's standard `encoding/json/jsontext`, without an experiment flag.
Validate raw input **before** unmarshaling it: typed `Validate` methods and
`registry/converters` cannot recover information already lost during decoding.

The extension flag controls only additional ToolHive policy on original
`_meta["io.modelcontextprotocol.registry/publisher-provided"]` metadata:

- `false`: only the MCP schema applies; namespace values may be scalars, arrays,
  or objects where the MCP schema permits them.
- `true`: namespace values must be objects. Arbitrary custom namespace objects
  are accepted; `io.github.stacklok` must also satisfy ToolHive's extension schema.
- `ValidateUpstreamRegistryBytes` always enables this additional policy.

Dynamic validation and converter extension decodes use `json.Number`, retaining
numeric spelling and precision through JSON serialization, including
`9007199254740993`, `18446744073709551615`,
`0.12345678901234567890123456789`, and `1e400` in unconstrained metadata and
nested MCP tool definitions. This includes dynamic tool `_meta` fields and JSON
Schema maps (`$defs`, `properties`, `additionalProperties`, and unmodeled
keywords) in input and output schemas. The current embedded schemas constrain
numbers only through integer/range checks for ports and a non-negative range for
`metadata.stars`; `gojsonschema` evaluates those checks with `big.Rat`, so a
fractional value near an integer port is rejected. Consumers of dynamic converter
maps and MCP tool fields must handle `json.Number`, not assume `float64`; callers
decoding server or registry bytes themselves should use `json.Decoder.UseNumber`
as well.

This is not a claim of arbitrary-number-exact schema evaluation. In
`gojsonschema` v1.2.0, `enum`, `const`, and `uniqueItems` equality re-marshals
numbers through `float64`. The current embedded schemas use those keywords only
for strings or bounded integer arrays, never arbitrary numeric metadata, but a
future schema using numeric equality constraints would have that precision
limitation. Explicitly typed numeric fields retain their Go range/precision
limits, and converting a `json.Number` to a native numeric type can fail or lose
precision. Validation does not canonicalize JSON, mutate caller bytes, or impose
an application-level input byte limit; callers should bound untrusted input size.

Validation errors report schema-defined property names and failure kinds, not
submitted values, arbitrary namespace/image keys, or server names. Exact error
text is not an API contract.

## Package Stability Levels

Each package is marked with a stability level:

| Level | Meaning | API Guarantees |
|-------|---------|----------------|
| **Stable** | Production-ready, fully supported | No breaking changes without major version bump |
| **Beta** | Feature-complete, may have minor changes | Breaking changes possible with deprecation notice |
| **Alpha** | Experimental, subject to significant changes | No stability guarantees |

## Graduation Criteria

Packages in `toolhive-core` must meet formal criteria before inclusion. This ensures that shared packages are genuinely reusable, well-tested, and not tied to the internal workings of any specific project.

### Guiding Principle

Packages must provide genuinely reusable value and be designed as reusable from the start. A package that requires knowledge of toolhive internals to use correctly is not a good candidate for graduation.

### Fast Track (Simple Packages)

For small, focused packages with minimal dependencies (e.g., `env`, `errors`, `validation`):

| Criterion | Requirement |
|-----------|-------------|
| **Production usage** | Deployed in production for ≥1 month |
| **No internal dependencies** | Cannot depend on non-graduated internal packages |
| **No global state** | No singletons, global variables for state, or `init()` side effects |
| **Test coverage** | ≥70% line coverage |
| **Documentation** | Package-level godoc |
| **Approval** | GitHub issue approved by one maintainer |

### Standard Track (Complex Packages)

For packages with external dependencies, multiple types, or broader API surface:

| Criterion | Requirement |
|-----------|-------------|
| **Production usage** | Deployed in production for ≥2 months without breaking changes |
| **API stability** | No breaking changes in the last 2 minor releases |
| **Interface design** | Uses Go interfaces for dependency injection and testability |
| **Error handling** | Returns typed errors; no panics except for programming bugs |
| **No global state** | No singletons, global variables for state, or `init()` side effects |
| **Test coverage** | ≥70% line coverage with meaningful assertions |
| **Documentation** | Package-level godoc with usage examples |
| **Linting** | Passes `golangci-lint` with project configuration |
| **Minimal dependencies** | Only essential external dependencies |
| **No circular imports** | Must not create import cycles when extracted |
| **No internal dependencies** | Cannot depend on non-graduated internal packages |
| **Stable external deps** | External dependencies must be v1.0+ or widely adopted |
| **Sponsorship** | At least one maintainer sponsors the graduation |
| **Approval** | RFC or detailed GitHub issue reviewed and approved |

### Graduation Process

1. **Proposal**: Open a GitHub issue identifying the graduation candidate and proposed track (fast/standard)
2. **Track determination**: Maintainers confirm which track applies based on package complexity
3. **Evaluation**: Assess against the relevant track's criteria
4. **Approval**: Fast track requires one maintainer approval; standard track requires RFC or detailed issue review
5. **Extraction**: Move package to `toolhive-core` with necessary adaptations
6. **Release**: Tag a new semver release of `toolhive-core`
7. **Migration**: Update consuming projects to import from `toolhive-core`

## Versioning

`toolhive-core` follows [Semantic Versioning 2.0.0](https://semver.org/):

- **Major (vX.0.0)**: Breaking API changes
- **Minor (v0.X.0)**: New features, backward-compatible
- **Patch (v0.0.X)**: Bug fixes, backward-compatible

### Release preflight

Before creating or pushing a release tag, check out the exact commit to be tagged and run:

```bash
./scripts/validate-release.sh <intended-tag>
```

The intended tag must use the module's tag prefix (for example, `v1.2.3`, `redisconn/v1.2.3`, or `redisconn/aws/v1.2.3`). Every required sibling module version must already have an exact module-prefixed release tag available in the local clone; fetch the required previous tags before running the check. The script only inspects local Git state and makes no network calls.

For an auditable preflight result, manually dispatch the **Release** workflow with the same intended tag and the full 40-character lowercase commit SHA that will receive it. The workflow rejects branch names, tag names, abbreviated SHAs, and uppercase SHAs, verifies that the input resolves to a commit, and checks out that exact commit. Create and push the tag only after the local check and, when used, the manual preflight pass against that SHA.

The tag-triggered Release workflow repeats validation after a tag is pushed. This post-tag check is defense in depth; it detects an invalid release but is not the pre-tag control.

### Unresolved release risks

Repository workflows cannot prevent an authorized user from directly pushing a tag without performing the preflight. Access controls and release-operator procedure must enforce the required pre-tag check; the post-tag workflow can only report failure after the tag exists.

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.

<!-- Badge links -->
<!-- prettier-ignore-start -->
[release]: https://github.com/stacklok/toolhive-core/releases/latest
[release-img]: https://img.shields.io/github/v/release/stacklok/toolhive-core
[ci]: https://github.com/stacklok/toolhive-core/actions/workflows/ci.yml
[ci-img]: https://github.com/stacklok/toolhive-core/actions/workflows/ci.yml/badge.svg
[coveralls]: https://coveralls.io/github/stacklok/toolhive-core
[coveralls-img]: https://coveralls.io/repos/github/stacklok/toolhive-core/badge.svg
[license]: https://opensource.org/licenses/Apache-2.0
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue.svg
[stars]: https://github.com/stacklok/toolhive-core/stargazers
[stars-img]: https://img.shields.io/github/stars/stacklok/toolhive-core?style=social
<!-- prettier-ignore-end -->

<!-- markdownlint-disable-file first-line-heading no-inline-html no-emphasis-as-heading -->
