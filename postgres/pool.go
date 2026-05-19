// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultPoolStatsInterval is the cadence at which StartPoolStatsLogger
// emits a connection-pool snapshot when no other interval is configured.
const DefaultPoolStatsInterval = 60 * time.Second

// Option customizes NewPool. See WithBeforeConnect, WithAfterConnect, and
// WithLogger.
type Option func(*options)

type options struct {
	beforeConnect BeforeConnectFn
	afterConnect  func(ctx context.Context, conn *pgx.Conn) error
	logger        *slog.Logger
}

// WithBeforeConnect installs a hook that runs immediately before pgx dials.
//
// NewPool rejects a combination of WithBeforeConnect and cfg.DynamicAuth — a
// silently-replaced auth hook would leave production tokens to expire 15
// minutes after deploy. Callers that need both must call NewDynamicAuthFunc
// explicitly, compose the two hooks themselves in the order they want, and
// pass the composed result via WithBeforeConnect (with cfg.DynamicAuth left
// nil so this package does not also try to install an auth hook).
func WithBeforeConnect(fn BeforeConnectFn) Option {
	return func(o *options) { o.beforeConnect = fn }
}

// WithAfterConnect installs a hook that runs immediately after a new
// connection has been established. The typical use case is registering
// custom type codecs (for example, application-defined enum array codecs).
func WithAfterConnect(fn func(ctx context.Context, conn *pgx.Conn) error) Option {
	return func(o *options) { o.afterConnect = fn }
}

// WithLogger sets the slog.Logger used for pool-creation messages and (when
// invoked) StartPoolStatsLogger output. When unset, slog.Default() is used.
func WithLogger(logger *slog.Logger) Option {
	return func(o *options) { o.logger = logger }
}

// NewPool creates a *pgxpool.Pool from cfg. When cfg.DynamicAuth is set,
// NewPool installs the appropriate dynamic-auth hook on BeforeConnect.
//
// Passing both cfg.DynamicAuth and WithBeforeConnect is an error — the
// failure mode of a silently-replaced auth hook (tokens expiring 15 min
// after deploy) is severe enough to refuse the ambiguity. Callers that
// genuinely want to layer logic on top of dynamic auth should call
// NewDynamicAuthFunc, compose the hooks themselves, and pass the
// composition via WithBeforeConnect with cfg.DynamicAuth left nil.
//
// cfg is validated; cfg is not mutated.
func NewPool(ctx context.Context, cfg *Config, opts ...Option) (*pgxpool.Pool, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	o := &options{}
	for _, opt := range opts {
		opt(o)
	}
	logger := o.logger
	if logger == nil {
		logger = slog.Default()
	}

	if cfg.DynamicAuth != nil && o.beforeConnect != nil {
		return nil, errors.New("cfg.DynamicAuth and WithBeforeConnect are mutually exclusive; " +
			"to layer hooks, call NewDynamicAuthFunc, compose with your hook, " +
			"and pass the composition via WithBeforeConnect with cfg.DynamicAuth = nil")
	}

	poolConfig, err := buildPoolConfig(cfg)
	if err != nil {
		return nil, err
	}

	applyPoolTuning(poolConfig, cfg)

	beforeConnect := o.beforeConnect
	if cfg.DynamicAuth != nil {
		beforeConnect, err = NewDynamicAuthFunc(ctx, cfg, cfg.User)
		if err != nil {
			return nil, err
		}
	}
	if beforeConnect != nil {
		poolConfig.BeforeConnect = beforeConnect
	}
	if o.afterConnect != nil {
		poolConfig.AfterConnect = o.afterConnect
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection pool: %w", err)
	}

	logger.LogAttrs(ctx, slog.LevelInfo, "postgres connection pool created", slog.Any("config", cfg))
	return pool, nil
}

// buildPoolConfig assembles a *pgxpool.Config without exposing
// caller-controlled fields to URL parsing. SSL configuration is bootstrapped
// from a minimal DSN — sslmode is the one field that pgx must translate into
// a *tls.Config — and the connection target is then assigned structurally.
// This eliminates the DSN-injection paths that would otherwise let a `@` in
// Host or a `?` in Database shift the authority or query section of the URL.
func buildPoolConfig(cfg *Config) (*pgxpool.Config, error) {
	sslMode := cfg.SSLMode
	if sslMode == "" {
		sslMode = DefaultSSLMode
	}

	// SSLMode values are constrained by pgx (disable/allow/prefer/require/
	// verify-ca/verify-full); url.QueryEscape is belt-and-suspenders.
	bootDSN := "postgres://localhost?sslmode=" + url.QueryEscape(sslMode)
	pc, err := pgxpool.ParseConfig(bootDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize pool config: %w", err)
	}

	pc.ConnConfig.Host = cfg.Host
	pc.ConnConfig.Port = uint16(cfg.Port) //nolint:gosec // G115: Port is bounded by Validate (1..65535).
	pc.ConnConfig.User = cfg.User
	pc.ConnConfig.Password = cfg.Password
	pc.ConnConfig.Database = cfg.Database

	return pc, nil
}

// applyPoolTuning copies pool-sizing knobs from cfg onto poolConfig, leaving
// pgxpool's defaults in place where cfg has zero values.
func applyPoolTuning(poolConfig *pgxpool.Config, cfg *Config) {
	if cfg.MaxOpenConns > 0 {
		poolConfig.MaxConns = cfg.MaxOpenConns
	}
	if cfg.MinConns > 0 {
		poolConfig.MinConns = cfg.MinConns
	}
	if cfg.ConnMaxLifetime > 0 {
		poolConfig.MaxConnLifetime = cfg.ConnMaxLifetime
	}
}

// StartPoolStatsLogger emits a connection-pool snapshot at DEBUG every
// interval until ctx is cancelled. When interval is zero, the default
// cadence is used. When logger is nil, slog.Default() is used.
//
// This is an opt-in helper; consumers that want pool metrics through a
// different sink (OpenTelemetry, Prometheus) should read pool.Stat()
// themselves.
func StartPoolStatsLogger(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, interval time.Duration) {
	if pool == nil {
		return
	}
	if interval == 0 {
		interval = DefaultPoolStatsInterval
	}
	if logger == nil {
		logger = slog.Default()
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				stat := pool.Stat()
				logger.LogAttrs(ctx, slog.LevelDebug, "postgres pool stats",
					slog.Int64("total_conns", int64(stat.TotalConns())),
					slog.Int64("acquired_conns", int64(stat.AcquiredConns())),
					slog.Int64("idle_conns", int64(stat.IdleConns())),
					slog.Int64("max_conns", int64(stat.MaxConns())),
					slog.Int64("acquire_count", stat.AcquireCount()),
					slog.Int64("acquire_duration_ms", stat.AcquireDuration().Milliseconds()),
					slog.Int64("canceled_acquire_count", stat.CanceledAcquireCount()),
					slog.Int64("empty_acquire_count", stat.EmptyAcquireCount()),
				)
			}
		}
	}()
}
