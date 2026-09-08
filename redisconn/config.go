// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redisconn

import (
	"context"
	"errors"
	"fmt"
	"time"
)

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
	CredentialsProviderContext CredentialsProvider
	ConnMaxLifetime            time.Duration
	AllowInsecureTransport     bool
}

// Config configures a Redis client. Exactly one of Addr or SentinelConfig must
// be set. ClusterMode upgrades an Addr-based config to Redis Cluster.
type Config struct {
	Addr            string
	ClusterMode     bool
	SentinelConfig  *SentinelConfig
	Username        string
	Password        string //nolint:gosec // field name, not a hardcoded credential
	DynamicAuth     *DynamicAuth
	DB              int
	DialTimeout     time.Duration
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	TLS             *TLSConfig
	SentinelTLS     *TLSConfig
	ConnMaxLifetime time.Duration
}

type SentinelConfig struct {
	MasterName    string
	SentinelAddrs []string
}

type TLSConfig struct {
	InsecureSkipVerify bool
	CACert             []byte
	ClientCert         []byte
	ClientKey          []byte
}

// Validate checks connection topology, TLS, and dynamic-auth safety.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
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
		return errors.New("TLS is required when dynamicAuth is configured (set Config.TLS, or DynamicAuth.AllowInsecureTransport to opt out for trusted local tunneling)")
	}
	if c.TLS.InsecureSkipVerify {
		return errors.New("TLS must verify the server certificate when dynamicAuth is configured (InsecureSkipVerify defeats the purpose of a signed token; set DynamicAuth.AllowInsecureTransport to opt out)")
	}
	return nil
}

func validateTLSConfig(cfg *TLSConfig) error {
	if cfg != nil && (len(cfg.ClientCert) == 0) != (len(cfg.ClientKey) == 0) {
		return errors.New("client certificate and key must be provided together")
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
