# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

toolhive-core is a shared Go library providing stable, well-tested utilities for the ToolHive ecosystem. It serves as a common dependency for toolhive, dockyard, toolhive-registry, and toolhive-registry-server projects.

## Build and Development Commands

This project uses [Task](https://taskfile.dev/) for automation:

```bash
task              # Run all checks (lint + test)
task lint         # Run golangci-lint and go vet
task test         # Run tests with race detection
```

Run a single test:
```bash
go test -race -run TestFunctionName ./path/to/package
```

Other commands:
```bash
task lint-fix      # Auto-fix linting issues
task test-coverage # Run tests with coverage report
task gen           # Generate mocks using mockgen
task tidy          # go mod tidy && go mod verify
task license-check # Verify SPDX license headers
task license-fix   # Add missing license headers
```

## Development Workflow

1. Implement changes with tests (≥70% coverage)
2. Run `task` to verify lint + tests pass
3. If adding mocks: add `//go:generate` directive, run `task gen`
4. Run `task license-check` before committing

## Boundaries

### Never
- Remove or skip existing tests
- Change exported interface signatures without discussion
- Modify `go.mod` dependencies without being asked

### Ask First
- Adding new packages (need to consider stability track)
- Adding new dependencies
- Changes to error codes in `httperr`

### Always
- Run `task` before considering work complete
- Include table-driven tests for new functions
- Use interface-based design for new packages (see `env.Reader` pattern)

## Architecture

### Package Design Principles

1. **Interface-based design** - Public APIs expose interfaces for testability and mock generation
2. **Dependency injection** - Enables mocking (see `env.Reader` interface pattern)
3. **Error wrapping** - Uses Go 1.13+ error wrapping compatible with `errors.Is()` and `errors.As()`
4. **Security-first validation** - All validators check for injection attacks (CRLF, control chars) and enforce length limits

### Current Packages

| Package | Purpose |
|---------|---------|
| `cel` | Generic CEL expression compilation and evaluation (Alpha) |
| `env` | Environment variable abstraction with `Reader` interface for testable code |
| `httperr` | Wrap errors with HTTP status codes; use `WithCode()`, `Code()`, `New()` |
| `logging` | Pre-configured `*slog.Logger` factory with consistent ToolHive defaults (Alpha) |
| `oci/skills` | OCI artifact types, media types, and registry operations for ToolHive skills (Alpha) |
| `recovery` | HTTP panic recovery middleware (Beta) |
| `validation/http` | RFC 7230/8707 compliant HTTP header and URI validation |
| `validation/group` | Group name validation (lowercase alphanumeric, underscore, dash, space) |

### Mock Generation

Mocks are generated using `go.uber.org/mock`. Add `//go:generate` directives in source files, then run `task gen`.

## Code Quality Notes

- **Test coverage**: ≥70% required for package graduation
- **License headers**: Run `task license-check` before committing to verify SPDX headers

## Stability Guarantees

Packages follow graduation tracks:
- **Stable**: Production-ready, semantic versioning applies
- **Beta**: API may change with deprecation notices
- **Alpha**: Experimental, breaking changes possible
