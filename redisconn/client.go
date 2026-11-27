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
	"os"
	"slices"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

const (
	initialConnectRetryDelay = 100 * time.Millisecond
	maxConnectRetryDelay     = 2 * time.Second
)

// NewClient constructs and verifies a Redis client. The caller's configuration
// is not mutated. A client that fails its initial PING, after retrying for up
// to ConnectRetryTimeout, is closed.
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
	if err := pingWithRetry(ctx, client, local.ConnectRetryTimeout); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis: failed to connect: %w", err)
	}
	return client, nil
}

// pingWithRetry bounds every attempt, including the first, by timeout, and stops
// early on errors a retry cannot fix. When its own deadline expires it returns
// the last PING error rather than the deadline error, so callers see why Redis
// was unreachable; when the caller's context ends, that error is joined in.
func pingWithRetry(parent context.Context, client goredis.UniversalClient, timeout time.Duration) error {
	if timeout <= 0 {
		return client.Ping(parent).Err()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	err := client.Ping(ctx).Err()
	delay := initialConnectRetryDelay
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		if err == nil || isPermanentConnectError(err) {
			return err
		}
		select {
		case <-ctx.Done():
			return retryStopError(parent, err)
		case <-timer.C:
		}
		pingErr := client.Ping(ctx).Err()
		if pingErr != nil && ctx.Err() != nil {
			return retryStopError(parent, err)
		}
		err = pingErr
		delay = min(delay*2, maxConnectRetryDelay)
		timer.Reset(delay)
	}
}

func isPermanentConnectError(err error) bool {
	var certErr *tls.CertificateVerificationError
	return goredis.IsAuthError(err) || goredis.IsPermissionError(err) || errors.As(err, &certErr)
}

func retryStopError(parent context.Context, lastErr error) error {
	if parent.Err() != nil {
		return errors.Join(parent.Err(), lastErr)
	}
	return lastErr
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
	caCert, err := loadCACert(cfg)
	if err != nil {
		return nil, err
	}
	if len(caCert) > 0 {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caCert) {
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

// loadCACert returns the configured CA bundle: CACertFile's contents when set,
// otherwise CACert. An unreadable or empty CACertFile is an error so a
// misconfigured path cannot silently select system roots.
func loadCACert(cfg *TLSConfig) ([]byte, error) {
	if cfg.CACertFile == "" {
		return cfg.CACert, nil
	}
	data, err := os.ReadFile(cfg.CACertFile) // #nosec G304 -- path comes from trusted configuration
	if err != nil {
		return nil, fmt.Errorf("redis: failed to read CA certificate file %q: %w", cfg.CACertFile, err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("redis: CA certificate file %q is empty", cfg.CACertFile)
	}
	return data, nil
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
		PoolSize: cfg.PoolSize, MaxActiveConns: cfg.MaxActiveConns,
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
		PoolSize: cfg.PoolSize, MaxActiveConns: cfg.MaxActiveConns,
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
		PoolSize: cfg.PoolSize, MaxActiveConns: cfg.MaxActiveConns,
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
