# toolhive-core

The ToolHive Platform common libraries and specifications.

`toolhive-core` provides stable, well-tested Go utilities with explicit API guarantees for the ToolHive ecosystem. Projects like [toolhive](https://github.com/stacklok/toolhive), [dockyard](https://github.com/stacklok/dockyard), [toolhive-registry](https://github.com/stacklok/toolhive-registry), and [toolhive-registry-server](https://github.com/stacklok/toolhive-registry-server) depend on this library for shared functionality.

## Why toolhive-core?

The ToolHive ecosystem spans multiple Go repositories, and several of these projects need to share common utilities. Rather than having projects import internal packages from `toolhive` (which have no stability guarantees), `toolhive-core` provides:

- **Stability guarantees**: Packages follow semantic versioning with explicit API commitments
- **Clear maturity levels**: Each package is marked as Stable, Beta, or Alpha
- **Tested and documented**: All packages meet minimum quality standards before inclusion
- **Independent versioning**: Evolves on its own release cadence, decoupled from `toolhive` releases

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

## License

Apache-2.0 - See [LICENSE](LICENSE) for details.
