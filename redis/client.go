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

	client, err := buildClient(&local)
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
// "no TLS". Returns an error when CACert is present but cannot be parsed.
//
// The returned *tls.Config sets MinVersion to TLS 1.2 and uses the system
// root CAs unless CACert is supplied.
func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
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
	return tc, nil
}

// buildClient constructs the underlying goredis client. cfg has already been
// validated and had defaults applied.
func buildClient(cfg *Config) (goredis.UniversalClient, error) {
	switch {
	case cfg.SentinelConfig != nil:
		return buildSentinelClient(cfg)
	case cfg.ClusterMode:
		return buildClusterClient(cfg)
	default:
		return buildStandaloneClient(cfg)
	}
}

func buildStandaloneClient(cfg *Config) (goredis.UniversalClient, error) {
	tlsCfg, err := BuildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("redis: standalone TLS config: %w", err)
	}
	return goredis.NewClient(&goredis.Options{
		Addr:         cfg.Addr,
		Username:     cfg.Username,
		Password:     cfg.Password,
		DB:           cfg.DB,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		TLSConfig:    tlsCfg,
	}), nil
}

func buildClusterClient(cfg *Config) (goredis.UniversalClient, error) {
	tlsCfg, err := BuildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("redis: cluster TLS config: %w", err)
	}
	return goredis.NewClusterClient(&goredis.ClusterOptions{
		Addrs:        []string{cfg.Addr},
		Username:     cfg.Username,
		Password:     cfg.Password,
		DialTimeout:  cfg.DialTimeout,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
		TLSConfig:    tlsCfg,
	}), nil
}

func buildSentinelClient(cfg *Config) (goredis.UniversalClient, error) {
	opts := &goredis.FailoverOptions{
		MasterName:    cfg.SentinelConfig.MasterName,
		SentinelAddrs: cfg.SentinelConfig.SentinelAddrs,
		Username:      cfg.Username,
		Password:      cfg.Password,
		DB:            cfg.DB,
		DialTimeout:   cfg.DialTimeout,
		ReadTimeout:   cfg.ReadTimeout,
		WriteTimeout:  cfg.WriteTimeout,
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
