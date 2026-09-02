// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"slices"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// NewClient constructs a Redis client according to cfg. The returned client
// is a goredis.UniversalClient so callers can remain mode-agnostic. NewClient
// applies timeout defaults, validates connection-mode topology, builds the
// appropriate underlying client (standalone, cluster, or sentinel), and
// verifies connectivity with a Ping before returning. On Ping failure the
// underlying client is closed and the error is returned.
//
// cfg is copied internally before defaults are applied; the caller's Config
// is not mutated.
func NewClient(ctx context.Context, cfg *Config) (goredis.UniversalClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis: config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("redis: invalid configuration: %w", err)
	}

	local := *cfg
	local.applyDefaults()

	client, err := buildClient(ctx, &local)
	if err != nil {
		return nil, err
	}

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: failed to connect: %w", err)
	}
	return client, nil
}

// BuildTLSConfig converts a TLSConfig into a *tls.Config suitable for
// dialing a Redis endpoint. Returns (nil, nil) when cfg is nil, signalling
// "no TLS". Returns an error when the CA certificate or client certificate
// and key cannot be parsed, or when only one of ClientCert and ClientKey is
// set.
//
// The returned *tls.Config sets MinVersion to TLS 1.2 and uses the system
// root CAs unless CACert is supplied. When ClientCert and ClientKey are set,
// it presents them to the server for mutual TLS.
func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := validateTLSConfig(cfg); err != nil {
		return nil, fmt.Errorf("redis: invalid TLS configuration: %w", err)
	}
	tc := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // G402: configurable per-deployment
	}
	if len(cfg.CACert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACert) {
			return nil, fmt.Errorf("redis: failed to parse CA certificate PEM data")
		}
		tc.RootCAs = pool
	}
	if len(cfg.ClientCert) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("redis: failed to parse client certificate and key: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return tc, nil
}

// buildClient constructs the underlying goredis client. cfg has already been
// validated and had defaults applied.
func buildClient(ctx context.Context, cfg *Config) (goredis.UniversalClient, error) {
	switch {
	case cfg.SentinelConfig != nil:
		return buildSentinelClient(ctx, cfg)
	case cfg.ClusterMode:
		return buildClusterClient(ctx, cfg)
	default:
		return buildStandaloneClient(ctx, cfg)
	}
}

// dynamicAuthOptions resolves cfg.DynamicAuth (when set) into the
// goredis.Options fields that authenticate connections with fresh
// credentials: a CredentialsProviderContext hook that go-redis calls during
// its HELLO/AUTH handshake (before RESP3 negotiation and DB selection — see
// CredentialsFunc's doc comment for why this must not be an OnConnect hook),
// and a ConnMaxLifetime that forces go-redis to periodically retire and
// redial connections — re-running that hook — before the previous token
// would be rejected. Returns zero values, unmodified from cfg, when
// cfg.DynamicAuth is nil.
func dynamicAuthOptions(
	ctx context.Context, cfg *Config,
) (credentialsProviderContext func(context.Context) (string, string, error), connMaxLifetime time.Duration, err error) {
	if cfg.DynamicAuth == nil {
		return nil, cfg.ConnMaxLifetime, nil
	}
	credFn, err := newDynamicAuthCredentialsFunc(ctx, cfg)
	if err != nil {
		return nil, 0, err
	}
	connMaxLifetime = cfg.ConnMaxLifetime
	if connMaxLifetime == 0 {
		connMaxLifetime = dynamicAuthConnMaxLifetime(cfg.DynamicAuth)
	}
	return credFn, connMaxLifetime, nil
}

func buildStandaloneClient(ctx context.Context, cfg *Config) (goredis.UniversalClient, error) {
	tlsCfg, err := BuildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("redis: standalone TLS config: %w", err)
	}
	credFn, connMaxLifetime, err := dynamicAuthOptions(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return goredis.NewClient(&goredis.Options{
		Addr:                       cfg.Addr,
		Username:                   cfg.Username,
		Password:                   cfg.Password,
		DB:                         cfg.DB,
		DialTimeout:                cfg.DialTimeout,
		ReadTimeout:                cfg.ReadTimeout,
		WriteTimeout:               cfg.WriteTimeout,
		TLSConfig:                  tlsCfg,
		CredentialsProviderContext: credFn,
		ConnMaxLifetime:            connMaxLifetime,
	}), nil
}

func buildClusterClient(ctx context.Context, cfg *Config) (goredis.UniversalClient, error) {
	tlsCfg, err := BuildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("redis: cluster TLS config: %w", err)
	}
	credFn, connMaxLifetime, err := dynamicAuthOptions(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return goredis.NewClusterClient(&goredis.ClusterOptions{
		Addrs:                      []string{cfg.Addr},
		Username:                   cfg.Username,
		Password:                   cfg.Password,
		DialTimeout:                cfg.DialTimeout,
		ReadTimeout:                cfg.ReadTimeout,
		WriteTimeout:               cfg.WriteTimeout,
		TLSConfig:                  tlsCfg,
		CredentialsProviderContext: credFn,
		ConnMaxLifetime:            connMaxLifetime,
	}), nil
}

// buildSentinelClient wires CredentialsProviderContext for the data-node
// (master/replica) connections only. go-redis's FailoverOptions.sentinelOptions
// deliberately does not propagate CredentialsProviderContext (or
// CredentialsProvider/Password) to the internal sentinel-daemon connections
// it builds — those use SentinelUsername/SentinelPassword instead — so
// dynamic-auth credentials for the cloud data-node identity never reach the
// Sentinel discovery connections. (This is unlike OnConnect, which
// FailoverOptions.sentinelOptions does copy onto sentinel connections —
// using it here would have leaked data-node IAM credentials to the Sentinel
// daemons.)
func buildSentinelClient(ctx context.Context, cfg *Config) (goredis.UniversalClient, error) {
	credFn, connMaxLifetime, err := dynamicAuthOptions(ctx, cfg)
	if err != nil {
		return nil, err
	}
	opts := &goredis.FailoverOptions{
		MasterName:                 cfg.SentinelConfig.MasterName,
		SentinelAddrs:              cfg.SentinelConfig.SentinelAddrs,
		Username:                   cfg.Username,
		Password:                   cfg.Password,
		DB:                         cfg.DB,
		DialTimeout:                cfg.DialTimeout,
		ReadTimeout:                cfg.ReadTimeout,
		WriteTimeout:               cfg.WriteTimeout,
		CredentialsProviderContext: credFn,
		ConnMaxLifetime:            connMaxLifetime,
	}

	// When both master and sentinel TLS are nil, leave Dialer/TLSConfig
	// unset and let go-redis use plaintext. When only master TLS is set,
	// go-redis would apply that single TLSConfig to all connections
	// (including sentinels). Whenever we need asymmetric handling, install
	// a custom dialer that selects the right config per target address.
	if cfg.TLS != nil || cfg.SentinelTLS != nil {
		if err := configureTLSDialer(opts, cfg.TLS, cfg.SentinelTLS); err != nil {
			return nil, err
		}
	}
	return goredis.NewFailoverClient(opts), nil
}

// configureTLSDialer installs a per-address TLS dialer onto opts so that
// master and sentinel connections can use different TLS configurations.
func configureTLSDialer(opts *goredis.FailoverOptions, masterCfg, sentinelCfg *TLSConfig) error {
	masterTLS, err := BuildTLSConfig(masterCfg)
	if err != nil {
		return fmt.Errorf("redis: master TLS config: %w", err)
	}
	sentinelTLS, err := BuildTLSConfig(sentinelCfg)
	if err != nil {
		return fmt.Errorf("redis: sentinel TLS config: %w", err)
	}
	opts.Dialer = newTLSDialer(masterTLS, sentinelTLS, opts.SentinelAddrs, opts.DialTimeout)
	return nil
}

// newTLSDialer returns a dialer that picks masterTLS or sentinelTLS based on
// whether the target address matches one of the configured sentinel
// addresses. A nil tls.Config means "plaintext for this target".
func newTLSDialer(
	masterTLS, sentinelTLS *tls.Config,
	sentinelAddrs []string,
	timeout time.Duration,
) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(_ context.Context, network, addr string) (net.Conn, error) {
		d := &net.Dialer{Timeout: timeout}
		tlsCfg := masterTLS
		if slices.Contains(sentinelAddrs, addr) {
			tlsCfg = sentinelTLS
		}
		if tlsCfg == nil {
			return d.Dial(network, addr)
		}
		return tls.DialWithDialer(d, network, addr, tlsCfg)
	}
}
