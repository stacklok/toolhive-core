// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"errors"
	"time"
)

// Default timeouts applied by NewClient when the corresponding Config field
// is zero.
const (
	DefaultDialTimeout  = 5 * time.Second
	DefaultReadTimeout  = 3 * time.Second
	DefaultWriteTimeout = 3 * time.Second
)

// Config configures a Redis client. Exactly one of Addr or SentinelConfig
// must be set. ClusterMode upgrades an Addr-based config to the Redis
// Cluster protocol.
type Config struct {
	// Addr is the Redis server address (host:port) for standalone or cluster
	// modes. Mutually exclusive with SentinelConfig.
	Addr string

	// ClusterMode enables the Redis Cluster protocol. Requires Addr. Cluster
	// mode ignores DB because Redis Cluster only supports database 0.
	ClusterMode bool

	// SentinelConfig activates Sentinel failover mode. Mutually exclusive
	// with Addr.
	SentinelConfig *SentinelConfig

	// Username is the optional ACL username (Redis 6.0+). When empty, auth
	// falls back to legacy AUTH using only Password.
	Username string

	// Password is the AUTH/ACL password. May be empty when the server does
	// not require authentication.
	Password string //nolint:gosec // G101: field name, not a hardcoded credential

	// DB is the Redis database index. Applies to standalone and sentinel
	// modes; ignored in cluster mode.
	DB int

	// DialTimeout is the timeout for establishing a connection. When zero,
	// DefaultDialTimeout is used.
	DialTimeout time.Duration

	// ReadTimeout is the timeout for socket reads. When zero,
	// DefaultReadTimeout is used.
	ReadTimeout time.Duration

	// WriteTimeout is the timeout for socket writes. When zero,
	// DefaultWriteTimeout is used.
	WriteTimeout time.Duration

	// TLS configures TLS for master/cluster connections. When nil, those
	// connections are plaintext.
	TLS *TLSConfig

	// SentinelTLS configures TLS for sentinel daemon connections. Only
	// applies when SentinelConfig is set. When nil, sentinel connections are
	// plaintext (independent of TLS).
	SentinelTLS *TLSConfig
}

// SentinelConfig describes a Redis Sentinel deployment used to discover the
// current master.
type SentinelConfig struct {
	// MasterName is the logical name of the monitored master, as configured
	// on the sentinel daemons.
	MasterName string

	// SentinelAddrs is the list of sentinel daemon addresses (host:port).
	SentinelAddrs []string
}

// TLSConfig describes how to verify a TLS-enabled Redis (or sentinel)
// endpoint. The mere presence of a TLSConfig enables TLS; the zero value
// means "verify against system CAs with hostname verification".
type TLSConfig struct {
	// InsecureSkipVerify disables certificate verification. Intended for
	// self-signed development setups; never use in production.
	InsecureSkipVerify bool

	// CACert is the PEM-encoded CA bundle used to verify the server. When
	// nil, system root CAs are used.
	CACert []byte
}

// Validate checks Config for connection-mode topology errors and returns
// the first violation encountered. It does not verify caller-specific
// invariants such as key-prefix conventions or ACL requirements.
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
	return nil
}

// applyDefaults writes DefaultDialTimeout/ReadTimeout/WriteTimeout into c
// for any zero-valued timeout field.
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
