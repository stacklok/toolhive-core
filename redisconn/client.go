// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redisconn

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"slices"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// NewClient constructs and verifies a Redis client. The caller's configuration
// is not mutated. A client that fails its initial PING is closed.
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

// BuildTLSConfig builds a TLS 1.2-or-newer configuration. A nil input means
// plaintext; a nil CA bundle uses system roots.
func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	if cfg == nil {
		return nil, nil
	}
	if err := validateTLSConfig(cfg); err != nil {
		return nil, fmt.Errorf("redis: invalid TLS configuration: %w", err)
	}
	tlsCfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // explicitly configurable
	}
	if len(cfg.CACert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(cfg.CACert) {
			return nil, errors.New("redis: failed to parse CA certificate PEM data")
		}
		tlsCfg.RootCAs = pool
	}
	if len(cfg.ClientCert) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("redis: failed to parse client certificate and key: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}
	return tlsCfg, nil
}

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

func dynamicAuthOptions(cfg *Config) (CredentialsProvider, time.Duration) {
	if cfg.DynamicAuth == nil {
		return nil, cfg.ConnMaxLifetime
	}
	lifetime := cfg.ConnMaxLifetime
	if lifetime == 0 {
		lifetime = cfg.DynamicAuth.ConnMaxLifetime
	}
	return cfg.DynamicAuth.CredentialsProviderContext, lifetime
}

func buildStandaloneClient(cfg *Config) (goredis.UniversalClient, error) {
	tlsCfg, err := BuildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("redis: standalone TLS config: %w", err)
	}
	provider, lifetime := dynamicAuthOptions(cfg)
	return goredis.NewClient(&goredis.Options{
		Addr: cfg.Addr, Username: cfg.Username, Password: cfg.Password, DB: cfg.DB,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
		TLSConfig: tlsCfg, CredentialsProviderContext: provider, ConnMaxLifetime: lifetime,
	}), nil
}

func buildClusterClient(cfg *Config) (goredis.UniversalClient, error) {
	tlsCfg, err := BuildTLSConfig(cfg.TLS)
	if err != nil {
		return nil, fmt.Errorf("redis: cluster TLS config: %w", err)
	}
	provider, lifetime := dynamicAuthOptions(cfg)
	return goredis.NewClusterClient(&goredis.ClusterOptions{
		Addrs: []string{cfg.Addr}, Username: cfg.Username, Password: cfg.Password,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
		TLSConfig: tlsCfg, CredentialsProviderContext: provider, ConnMaxLifetime: lifetime,
	}), nil
}

// FailoverOptions intentionally applies dynamic credentials only to data-node
// connections. go-redis does not copy CredentialsProviderContext into its
// internal Sentinel options, unlike OnConnect.
func buildSentinelClient(cfg *Config) (goredis.UniversalClient, error) {
	opts, err := buildSentinelOptions(cfg)
	if err != nil {
		return nil, err
	}
	return goredis.NewFailoverClient(opts), nil
}

func buildSentinelOptions(cfg *Config) (*goredis.FailoverOptions, error) {
	provider, lifetime := dynamicAuthOptions(cfg)
	opts := &goredis.FailoverOptions{
		MasterName: cfg.SentinelConfig.MasterName, SentinelAddrs: cfg.SentinelConfig.SentinelAddrs,
		Username: cfg.Username, Password: cfg.Password, DB: cfg.DB,
		DialTimeout: cfg.DialTimeout, ReadTimeout: cfg.ReadTimeout, WriteTimeout: cfg.WriteTimeout,
		CredentialsProviderContext: provider, ConnMaxLifetime: lifetime,
	}
	if cfg.TLS != nil || cfg.SentinelTLS != nil {
		if err := configureTLSDialer(opts, cfg.TLS, cfg.SentinelTLS); err != nil {
			return nil, err
		}
	}
	return opts, nil
}

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

func newTLSDialer(
	masterTLS, sentinelTLS *tls.Config,
	sentinelAddrs []string,
	timeout time.Duration,
) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		tlsCfg := masterTLS
		if slices.Contains(sentinelAddrs, addr) {
			tlsCfg = sentinelTLS
		}
		dialer := &net.Dialer{Timeout: timeout}
		if tlsCfg == nil {
			return dialer.DialContext(ctx, network, addr)
		}
		return (&tls.Dialer{NetDialer: dialer, Config: tlsCfg}).DialContext(ctx, network, addr)
	}
}
