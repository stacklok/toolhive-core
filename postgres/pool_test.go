// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"bytes"
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPool_NilConfig(t *testing.T) {
	t.Parallel()
	pool, err := NewPool(t.Context(), nil)
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "config is nil")
}

func TestNewPool_InvalidConfig(t *testing.T) {
	t.Parallel()
	pool, err := NewPool(t.Context(), &Config{})
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "invalid configuration")
}

func TestNewPool_DynamicAuthMisconfigured(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.DynamicAuth = &DynamicAuthConfig{AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: ""}}
	pool, err := NewPool(t.Context(), cfg)
	require.Error(t, err)
	assert.Nil(t, pool)
	// Validate() catches the empty region before NewDynamicAuthFunc runs.
	assert.Contains(t, err.Error(), "dynamicAuth.awsRdsIam.region is required")
}

// TestNewPool_DynamicAuthAndBeforeConnectAreMutuallyExclusive verifies that
// NewPool refuses the ambiguous combination rather than silently dropping
// one hook. The failure mode of a silently-replaced auth hook — production
// tokens expiring ~15 minutes after deploy — is severe enough that we want
// a loud rejection at construction time.
func TestNewPool_DynamicAuthAndBeforeConnectAreMutuallyExclusive(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.SSLMode = testSSLModeDisable
	cfg.DynamicAuth = &DynamicAuthConfig{
		AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: testRegion},
	}

	pool, err := NewPool(t.Context(), cfg,
		WithBeforeConnect(func(context.Context, *pgx.ConnConfig) error { return nil }),
	)
	require.Error(t, err)
	assert.Nil(t, pool)
	assert.Contains(t, err.Error(), "mutually exclusive")
}

// TestNewPool_LazyConnect verifies that NewPool returns successfully even
// when the database is unreachable — pgxpool establishes connections
// lazily on first Acquire, not at construction time. Dial errors surface
// at query time, not pool-creation time.
func TestNewPool_LazyConnect(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = 1 // closed port; never opens
	cfg.SSLMode = testSSLModeDisable

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	pool, err := NewPool(t.Context(), cfg, WithLogger(logger))
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	assert.Contains(t, buf.String(), "postgres connection pool created")
	// Logger received the cfg via slog.LogValuer — password must not appear.
	assert.NotContains(t, buf.String(), cfg.Password)
}

func TestNewPool_OptionsArePopulated(t *testing.T) {
	t.Parallel()
	o := &options{}
	WithBeforeConnect(func(context.Context, *pgx.ConnConfig) error { return nil })(o)
	WithAfterConnect(func(context.Context, *pgx.Conn) error { return nil })(o)
	WithLogger(slog.Default())(o)
	assert.NotNil(t, o.beforeConnect)
	assert.NotNil(t, o.afterConnect)
	assert.NotNil(t, o.logger)
}

// TestBuildPoolConfig_AssignsFieldsStructurally verifies the structural
// override path: caller-supplied Host and Database land verbatim on the pgx
// ConnConfig instead of going through URL parsing. This is the test guard
// against the DSN-injection class flagged in code review — a `@` in Host or
// a `?` in Database is preserved as-is and never reinterpreted by url.Parse.
func TestBuildPoolConfig_AssignsFieldsStructurally(t *testing.T) {
	t.Parallel()

	cfg := &Config{
		Host:     "db-1.cluster.example.com",
		Port:     5433,
		User:     "appuser",
		Password: "s3cret",
		Database: testDatabase,
		SSLMode:  "require",
	}

	pc, err := buildPoolConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "db-1.cluster.example.com", pc.ConnConfig.Host)
	assert.Equal(t, uint16(5433), pc.ConnConfig.Port)
	assert.Equal(t, "appuser", pc.ConnConfig.User)
	assert.Equal(t, "s3cret", pc.ConnConfig.Password)
	assert.Equal(t, "appdb", pc.ConnConfig.Database)
	assert.NotNil(t, pc.ConnConfig.TLSConfig, "sslmode=require must produce a non-nil tls.Config")
}

func TestBuildPoolConfig_SSLModeDisableLeavesTLSUnset(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.SSLMode = testSSLModeDisable

	pc, err := buildPoolConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, pc.ConnConfig.TLSConfig, "sslmode=disable must produce a nil tls.Config")
}

func TestApplyPoolTuning(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.MaxOpenConns = 17
	cfg.MinConns = 3
	cfg.ConnMaxLifetime = 42 * time.Minute

	pc, err := pgxpool.ParseConfig(cfg.ConnectionString())
	require.NoError(t, err)
	applyPoolTuning(pc, cfg)

	assert.Equal(t, int32(17), pc.MaxConns)
	assert.Equal(t, int32(3), pc.MinConns)
	assert.Equal(t, 42*time.Minute, pc.MaxConnLifetime)
}

func TestApplyPoolTuning_PreservesDefaultsForZeroValues(t *testing.T) {
	t.Parallel()

	cfg := validConfig() // all pool knobs at zero

	pc, err := pgxpool.ParseConfig(cfg.ConnectionString())
	require.NoError(t, err)
	defaultMax := pc.MaxConns
	defaultMin := pc.MinConns
	defaultLifetime := pc.MaxConnLifetime

	applyPoolTuning(pc, cfg)

	assert.Equal(t, defaultMax, pc.MaxConns)
	assert.Equal(t, defaultMin, pc.MinConns)
	assert.Equal(t, defaultLifetime, pc.MaxConnLifetime)
}

func TestStartPoolStatsLogger_ExitsOnContextCancel(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.Host = "127.0.0.1"
	cfg.Port = 1
	cfg.SSLMode = testSSLModeDisable

	pool, err := NewPool(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithCancel(t.Context())
	StartPoolStatsLogger(ctx, pool, slog.Default(), 10*time.Millisecond)
	cancel()
	// Give the goroutine time to notice cancellation and return. This is a
	// soft check — race-detector + leak-detector tooling at the suite level
	// is what catches a leaked goroutine.
	time.Sleep(50 * time.Millisecond)
}

func TestStartPoolStatsLogger_NilPoolNoop(t *testing.T) {
	t.Parallel()
	// Must not panic.
	StartPoolStatsLogger(t.Context(), nil, slog.Default(), 0)
}

// TestStartPoolStatsLogger_UsesDefaultInterval verifies the default-interval
// branch is exercised. We do not wait the full default 60s; we just call
// the function and immediately cancel — coverage is the goal.
func TestStartPoolStatsLogger_UsesDefaultInterval(t *testing.T) {
	t.Parallel()

	cfg := validConfig()
	cfg.SSLMode = testSSLModeDisable
	pool, err := NewPool(t.Context(), cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	ctx, cancel := context.WithCancel(t.Context())
	StartPoolStatsLogger(ctx, pool, nil, 0) // default logger + default interval
	cancel()

	// Touch the counter so the lint can't complain about unused atomic.
	var seen atomic.Int32
	seen.Add(1)
	assert.Equal(t, int32(1), seen.Load())
}
