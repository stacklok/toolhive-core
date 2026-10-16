// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redisconn

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Default client timeouts applied when the corresponding Config field is zero.
const (
	DefaultDialTimeout  = 5 * time.Second
	DefaultReadTimeout  = 3 * time.Second
	DefaultWriteTimeout = 3 * time.Second
)

// CredentialsProvider resolves credentials for a new Redis connection.
type CredentialsProvider func(context.Context) (username, password string, err error)

// DynamicAuth configures credentials that are resolved while each new
// connection is initialized. ConnMaxLifetime retires over-age connections
// lazily on reuse; it does not proactively refresh or reauthenticate them.
type DynamicAuth struct {
	// CredentialsProviderContext returns credentials for each new connection.
	CredentialsProviderContext CredentialsProvider
	// ConnMaxLifetime is the provider-recommended maximum connection age. A
	// non-zero Config.ConnMaxLifetime overrides it.
	ConnMaxLifetime time.Duration
	// AllowInsecureTransport permits dynamic credentials without verified TLS.
	// Use only when a trusted local tunnel supplies transport security.
	AllowInsecureTransport bool
}

// Config configures a Redis client. Exactly one of Addr or SentinelConfig must
// be set. ClusterMode upgrades an Addr-based config to Redis Cluster.
type Config struct {
	// Addr is the host:port for standalone or cluster mode.
	Addr string
	// ClusterMode enables Redis Cluster and requires Addr.
	ClusterMode bool
	// SentinelConfig selects Sentinel mode and is mutually exclusive with Addr.
	SentinelConfig *SentinelConfig
	// Username and Password are static Redis credentials. Password is mutually
	// exclusive with DynamicAuth.
	Username    string
	Password    string //nolint:gosec // field name, not a hardcoded credential
	DynamicAuth *DynamicAuth
	// DB is ignored in cluster mode.
	DB int
	// Zero timeouts use the package defaults.
	DialTimeout  time.Duration
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	// PoolSize is the base number of socket connections in each pool. In
	// cluster mode, it applies per node. Zero uses the go-redis default.
	PoolSize int
	// MaxActiveConns is the maximum number of connections allocated by each
	// pool. In cluster mode, it applies per node. Zero allows the pool to
	// allocate connections without a hard limit.
	MaxActiveConns int
	// TLS secures Redis data-node connections; SentinelTLS independently secures
	// Sentinel discovery connections.
	TLS         *TLSConfig
	SentinelTLS *TLSConfig
	// ConnMaxLifetime overrides DynamicAuth.ConnMaxLifetime when non-zero.
	ConnMaxLifetime time.Duration
}

// SentinelConfig identifies a Sentinel-managed Redis master.
type SentinelConfig struct {
	// MasterName is the monitored Redis master name.
	MasterName string
	// SentinelAddrs lists Sentinel host:port endpoints.
	SentinelAddrs []string
}

// TLSConfig configures server verification, custom roots, and mutual TLS.
type TLSConfig struct {
	// InsecureSkipVerify disables server certificate verification.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty"`
	// CACert is an optional PEM CA bundle; empty uses system roots.
	// It is mutually exclusive with CACertFile.
	CACert []byte
	// CACertFile is an optional path to a PEM CA bundle, read when the TLS
	// configuration is built. When set, the bundle replaces the system roots.
	// A missing, empty, or malformed file is an error; it never falls back to
	// system roots or plaintext. The file is read once, so changes require a
	// new client. It is mutually exclusive with CACert.
	CACertFile string `json:"caCertFile,omitempty" yaml:"caCertFile,omitempty"`
	// ClientCert and ClientKey are a PEM mTLS certificate pair.
	ClientCert []byte
	ClientKey  []byte
}

// Validate checks connection topology, TLS, and dynamic-auth safety.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	if c.PoolSize < 0 {
		return errors.New("pool size must not be negative")
	}
	if c.MaxActiveConns < 0 {
		return errors.New("max active connections must not be negative")
	}
	if c.ClusterMode && c.SentinelConfig != nil {
		return errors.New("cluster mode cannot be used with sentinel configuration")
	}
	if c.Addr != "" && c.SentinelConfig != nil {
		return errors.New("addr and sentinel configuration are mutually exclusive; set exactly one")
	}
	if c.Addr == "" && c.SentinelConfig == nil {
		return errors.New("one of addr (standalone or cluster) or sentinel configuration is required")
	}
	if c.ClusterMode && c.Addr == "" {
		return errors.New("cluster mode requires addr to be set")
	}
	if c.SentinelConfig != nil {
		if c.SentinelConfig.MasterName == "" {
			return errors.New("sentinel master name is required")
		}
		if len(c.SentinelConfig.SentinelAddrs) == 0 {
			return errors.New("at least one sentinel address is required")
		}
	}
	if err := validateTLSConfig(c.TLS); err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}
	if err := validateTLSConfig(c.SentinelTLS); err != nil {
		return fmt.Errorf("sentinel TLS config: %w", err)
	}
	return validateDynamicAuth(c)
}

func validateDynamicAuth(c *Config) error {
	if c.DynamicAuth == nil {
		return nil
	}
	if c.DynamicAuth.CredentialsProviderContext == nil {
		return errors.New("dynamicAuth credentials provider is required")
	}
	if c.Password != "" {
		return errors.New("password must not be set when dynamicAuth is configured")
	}
	if c.DynamicAuth.AllowInsecureTransport {
		return nil
	}
	if c.TLS == nil {
		return errors.New("TLS is required when dynamicAuth is configured " +
			"(set Config.TLS, or DynamicAuth.AllowInsecureTransport to opt out for trusted local tunneling)")
	}
	if c.TLS.InsecureSkipVerify {
		return errors.New("TLS must verify the server certificate when dynamicAuth is configured " +
			"(InsecureSkipVerify defeats the purpose of a signed token; " +
			"set DynamicAuth.AllowInsecureTransport to opt out)")
	}
	return nil
}

// validateTLSConfig checks the configuration without touching the filesystem;
// CACertFile is read and checked by BuildTLSConfig.
func validateTLSConfig(cfg *TLSConfig) error {
	if cfg == nil {
		return nil
	}
	if (len(cfg.ClientCert) == 0) != (len(cfg.ClientKey) == 0) {
		return errors.New("client certificate and key must be provided together")
	}
	if len(cfg.CACert) > 0 && cfg.CACertFile != "" {
		return errors.New("CACert and CACertFile are mutually exclusive")
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.DialTimeout == 0 {
		c.DialTimeout = DefaultDialTimeout
	}
	if c.ReadTimeout == 0 {
		c.ReadTimeout = DefaultReadTimeout
	}
	if c.WriteTimeout == 0 {
		c.WriteTimeout = DefaultWriteTimeout
	}
}
