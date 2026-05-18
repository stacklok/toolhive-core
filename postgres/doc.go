// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package postgres provides a shared PostgreSQL connection layer for the
ToolHive ecosystem. It wraps github.com/jackc/pgx/v5/pgxpool with a single
Config type, a NewPool factory, and a dynamic-authentication dispatcher.
Schema management — migrations, queries, and per-application type codecs —
remains the caller's responsibility.

# Quick Start

	cfg := &postgres.Config{
	    Host:     "db.example.com",
	    Port:     5432,
	    User:     "appuser",
	    Password: "s3cret",
	    Database: "appdb",
	}

	pool, err := postgres.NewPool(ctx, cfg)
	if err != nil {
	    return err
	}
	defer pool.Close()

# Dynamic Authentication

Setting Config.DynamicAuth causes NewPool to install a BeforeConnect hook
that resolves a fresh credential before every connection attempt.

Currently supported backends:

  - AWS RDS IAM — short-lived tokens signed with the workload's ambient
    AWS credentials (env vars, EC2 instance profile, EKS web identity, …).
    Region "detect" auto-discovers the region via IMDS.

Example:

	cfg.DynamicAuth = &postgres.DynamicAuthConfig{
	    AWSRDSIAM: &postgres.DynamicAuthAWSRDSIAM{Region: "us-east-1"},
	}

For short-lived connections that cannot use a pool hook (for example
golang-migrate's one-shot migration connection), call NewAuthToken to
materialize a single token, then embed it via BuildConnectionStringWithAuth:

	token, _ := postgres.NewAuthToken(ctx, cfg, cfg.GetMigrationUser())
	connStr := cfg.BuildConnectionStringWithAuth(cfg.GetMigrationUser(), token)

# Hooks

WithAfterConnect installs an AfterConnect callback — the canonical place to
register application-specific type codecs (for example, codecs for
PostgreSQL enum array types defined in the caller's schema):

	pool, err := postgres.NewPool(ctx, cfg,
	    postgres.WithAfterConnect(func(ctx context.Context, conn *pgx.Conn) error {
	        return registerMyEnumCodecs(ctx, conn)
	    }),
	)

WithBeforeConnect overrides the auto-installed dynamic-auth hook. Callers
that need to layer additional logic on top should call NewDynamicAuthFunc
explicitly and compose the result.

# Logging

NewPool emits a single info-level message on success, redacting password
fields via Config's slog.LogValuer implementation. StartPoolStatsLogger is
an opt-in helper that periodically logs connection-pool statistics at debug
level until its context is cancelled.

# Secrets Handling

This package treats Password and MigrationPassword as already-resolved
strings. File-based secret loading, environment-variable overrides, and
pgpass fallback all live in the caller's configuration layer. Config
implements slog.LogValuer to redact credentials when logged.
*/
package postgres
