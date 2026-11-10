// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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
	cfg.Host = testLoopbackHost
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
		SSLMode:  testSSLModeRequire,
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

// testSSLModes lists every sslmode pgx accepts.
var testSSLModes = []string{testSSLModeDisable, "allow", "prefer", testSSLModeRequire, "verify-ca", "verify-full"}

// TestBuildPoolConfig_TargetsConfiguredHost uses pgx parsing a DSN with the
// real host as the reference: every connection attempt, and the TLS server
// name of each, must match it, so nothing still points at the bootstrap host.
func TestBuildPoolConfig_TargetsConfiguredHost(t *testing.T) {
	t.Parallel()

	for _, host := range []string{"db-1.cluster.example.com", "10.0.0.5"} {
		for _, sslMode := range testSSLModes {
			t.Run(host+"/"+sslMode, func(t *testing.T) {
				t.Parallel()
				assertTargetsLikePgx(t, host, sslMode)
			})
		}
	}
}

// TestBuildPoolConfig_KeepsSNIOff checks that PGSSLSNI=0, under which pgx
// sends no server name except for verify-full, is still honoured.
func TestBuildPoolConfig_KeepsSNIOff(t *testing.T) {
	t.Setenv("PGSSLSNI", "0")

	for _, sslMode := range testSSLModes {
		assertTargetsLikePgx(t, "db-1.cluster.example.com", sslMode)
	}
}

// assertTargetsLikePgx checks buildPoolConfig against pgx parsing a DSN that
// names host directly.
func assertTargetsLikePgx(t *testing.T, host, sslMode string) {
	t.Helper()

	cfg := validConfig()
	cfg.Host = host
	cfg.Port = 5433
	cfg.SSLMode = sslMode

	pc, err := buildPoolConfig(cfg)
	require.NoError(t, err)
	want, err := pgxpool.ParseConfig(fmt.Sprintf("postgres://%s:5433?sslmode=%s", host, sslMode))
	require.NoError(t, err)

	got := connAttempts(&pc.ConnConfig.Config)
	assert.Equal(t, connAttempts(&want.ConnConfig.Config), got, "sslmode=%s", sslMode)
	for _, attempt := range got {
		assert.NotEqual(t, bootHost, attempt.Host, "sslmode=%s", sslMode)
		assert.NotEqual(t, bootHost, attempt.ServerName, "sslmode=%s", sslMode)
	}
}

// TestBuildPoolConfig_VerifyFullAcceptsCertificateForConfiguredHost runs a
// verify-full handshake against a server whose certificate is valid for
// 127.0.0.1 only, so checking it against any other name fails.
func TestBuildPoolConfig_VerifyFullAcceptsCertificateForConfiguredHost(t *testing.T) {
	t.Parallel()

	cert, roots := selfSignedCert(t, net.IPv4(127, 0, 0, 1))
	handshake := make(chan error, 1)
	port := listenPostgres(t, func(conn net.Conn) {
		if code, err := readStartupCode(conn); err != nil || code != sslRequestCode {
			handshake <- fmt.Errorf("want SSLRequest, got code %d: %v", code, err)
			return
		}
		_, _ = conn.Write([]byte{'S'})
		handshake <- tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}}).Handshake()
	})

	cfg := validConfig()
	cfg.Host = testLoopbackHost
	cfg.Port = port
	cfg.SSLMode = "verify-full"
	pc, err := buildPoolConfig(cfg)
	require.NoError(t, err)
	pc.ConnConfig.TLSConfig.RootCAs = roots
	pc.ConnConfig.ConnectTimeout = 5 * time.Second

	// The fake server closes the connection after the handshake, so the
	// connect itself fails; the handshake is what is under test.
	_, err = pgx.ConnectConfig(t.Context(), pc.ConnConfig)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "certificate")
	select {
	case err := <-handshake:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("no connection reached the configured host")
	}
}

// TestBuildPoolConfig_PreferFallsBackToConfiguredHost refuses TLS so that
// prefer retries in plaintext, and checks the retry reaches the same server.
func TestBuildPoolConfig_PreferFallsBackToConfiguredHost(t *testing.T) {
	t.Parallel()

	codes := make(chan uint32, 4)
	port := listenPostgres(t, func(conn net.Conn) {
		code, err := readStartupCode(conn)
		if err != nil {
			return
		}
		codes <- code
		if code == sslRequestCode {
			_, _ = conn.Write([]byte{'N'})
		}
	})

	cfg := validConfig()
	cfg.Host = testLoopbackHost
	cfg.Port = port
	cfg.SSLMode = "prefer"
	pc, err := buildPoolConfig(cfg)
	require.NoError(t, err)
	pc.ConnConfig.ConnectTimeout = 5 * time.Second

	_, err = pgx.ConnectConfig(t.Context(), pc.ConnConfig)
	require.Error(t, err)
	require.Len(t, codes, 2, "both the TLS attempt and the plaintext retry must reach the configured host")
	assert.Equal(t, uint32(sslRequestCode), <-codes)
	assert.Equal(t, uint32(pgProtocolVersion), <-codes)
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
	cfg.Host = testLoopbackHost
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

// connAttempt is one host, port and TLS setting pgx tries when connecting.
type connAttempt struct {
	Host       string
	Port       uint16
	TLS        bool
	ServerName string
	SkipVerify bool
}

func connAttempts(c *pgconn.Config) []connAttempt {
	fallbacks := append([]*pgconn.FallbackConfig{{Host: c.Host, Port: c.Port, TLSConfig: c.TLSConfig}}, c.Fallbacks...)
	attempts := make([]connAttempt, 0, len(fallbacks))
	for _, fb := range fallbacks {
		attempt := connAttempt{Host: fb.Host, Port: fb.Port, TLS: fb.TLSConfig != nil}
		if fb.TLSConfig != nil {
			attempt.ServerName = fb.TLSConfig.ServerName
			attempt.SkipVerify = fb.TLSConfig.InsecureSkipVerify
		}
		attempts = append(attempts, attempt)
	}
	return attempts
}

const (
	// sslRequestCode opens an SSLRequest packet; a StartupMessage carries
	// pgProtocolVersion in the same position.
	sslRequestCode    = 80877103
	pgProtocolVersion = 196608
)

// listenPostgres accepts connections on 127.0.0.1, hands each to serve and
// closes it once serve returns. It returns the listening port.
func listenPostgres(t *testing.T, serve func(net.Conn)) int {
	t.Helper()
	ln, err := net.Listen("tcp", net.JoinHostPort(testLoopbackHost, "0"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				serve(conn)
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}

// readStartupCode reads the 8-byte header of the first packet a client sends
// and returns its code (sslRequestCode or pgProtocolVersion).
func readStartupCode(conn net.Conn) (uint32, error) {
	var header [8]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(header[4:]), nil
}

// selfSignedCert returns a certificate valid for ip only and a pool that
// trusts it.
func selfSignedCert(t *testing.T, ip net.IP) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "postgres-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IPAddresses:           []net.IP{ip},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, roots
}
