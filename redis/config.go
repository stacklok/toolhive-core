// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"errors"
	"fmt"
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
	//
	// When DynamicAuth is set, Username is required: it is the IAM/ACL
	// identity (AWS IAM user, Azure principal object ID, or GCP service
	// account email) that dynamic-auth tokens authenticate as.
	Username string

	// Password is the AUTH/ACL password. May be empty when the server does
	// not require authentication. Mutually exclusive with DynamicAuth.
	Password string //nolint:gosec // G101: field name, not a hardcoded credential

	// DynamicAuth, when non-nil, mints short-lived AUTH passwords from a
	// cloud IAM backend instead of using a static Password. NewClient
	// installs an Options.OnConnect hook that authenticates each connection
	// with a freshly minted token, and sets ConnMaxLifetime (when Config's
	// own ConnMaxLifetime is zero) to a value inside the backend's token TTL
	// so pooled connections are periodically retired and redialed with a
	// current token.
	DynamicAuth *DynamicAuthConfig

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

	// ConnMaxLifetime is the maximum amount of time a connection may be
	// reused before go-redis retires and redials it. When zero and
	// DynamicAuth is set, a backend-specific default inside the token's TTL
	// is used instead of go-redis's own default. Ignored (left at go-redis's
	// default) when DynamicAuth is nil and this is zero.
	ConnMaxLifetime time.Duration
}

// DynamicAuthConfig selects a dynamic-authentication backend. Exactly one
// backend field must be non-nil when DynamicAuthConfig itself is non-nil.
type DynamicAuthConfig struct {
	// AWSElastiCacheIAM enables AWS ElastiCache/MemoryDB IAM authentication
	// tokens.
	AWSElastiCacheIAM *DynamicAuthAWSElastiCacheIAM

	// AzureAD enables Azure Entra ID (formerly Azure AD) authentication
	// tokens for Azure Cache for Redis.
	AzureAD *DynamicAuthAzureAD

	// GCPMemorystoreIAM enables GCP Memorystore for Redis Cluster IAM
	// authentication tokens.
	GCPMemorystoreIAM *DynamicAuthGCPMemorystoreIAM
}

// DynamicAuthAWSElastiCacheIAM configures AWS ElastiCache/MemoryDB IAM
// dynamic authentication.
type DynamicAuthAWSElastiCacheIAM struct {
	// Region is the AWS region used to sign IAM tokens. Use "detect" to
	// auto-discover the region from the EC2 instance metadata service (IMDS).
	Region string

	// ClusterName is the ElastiCache replication group ID / cache name, or
	// the MemoryDB cluster name, that the presigned token is scoped to.
	ClusterName string

	// ServiceName is the SigV4 signing service name: "elasticache" (the
	// default, used when empty) or "memorydb".
	ServiceName string
}

// DynamicAuthAzureAD configures Azure Entra ID (formerly Azure AD)
// authentication for Azure Cache for Redis. It has no fields: the token is
// minted from DefaultAzureCredential's normal resolution order (environment
// variables — including AZURE_CLIENT_ID to select a user-assigned managed
// identity — workload identity, system-assigned managed identity, Azure
// CLI, ...).
type DynamicAuthAzureAD struct{}

// DynamicAuthGCPMemorystoreIAM configures GCP Memorystore for Redis Cluster
// IAM authentication. It has no fields: the token is minted from ambient
// Application Default Credentials, scoped for Memorystore IAM auth.
type DynamicAuthGCPMemorystoreIAM struct{}

// countDynamicAuthBackends returns how many backend fields on da are set.
func countDynamicAuthBackends(da *DynamicAuthConfig) int {
	n := 0
	if da.AWSElastiCacheIAM != nil {
		n++
	}
	if da.AzureAD != nil {
		n++
	}
	if da.GCPMemorystoreIAM != nil {
		n++
	}
	return n
}

// singleDynamicAuthBackend rejects a DynamicAuthConfig with zero or more
// than one backend configured.
func singleDynamicAuthBackend(da *DynamicAuthConfig) error {
	switch n := countDynamicAuthBackends(da); {
	case n == 0:
		return errors.New("dynamicAuth is set but no supported auth method " +
			"(e.g., awsElastiCacheIam, azureAd, gcpMemorystoreIam) is configured")
	case n > 1:
		return errors.New("dynamicAuth must configure exactly one auth method, but more than one is set")
	default:
		return nil
	}
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

	// ClientCert and ClientKey are a PEM-encoded client certificate/key pair
	// presented to the server for mutual TLS. Both fields must be set together.
	ClientCert []byte
	ClientKey  []byte
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
	if err := validateTLSConfig(c.TLS); err != nil {
		return fmt.Errorf("TLS config: %w", err)
	}
	if err := validateTLSConfig(c.SentinelTLS); err != nil {
		return fmt.Errorf("sentinel TLS config: %w", err)
	}
	return validateDynamicAuth(c)
}

// validateDynamicAuth checks c.DynamicAuth for backend-selection and
// required-field errors. Split out of Validate to keep both functions under
// the project's cyclomatic-complexity budget.
func validateDynamicAuth(c *Config) error {
	if c.DynamicAuth == nil {
		return nil
	}
	if err := singleDynamicAuthBackend(c.DynamicAuth); err != nil {
		return err
	}
	if c.Password != "" {
		return errors.New("password must not be set when dynamicAuth is configured")
	}
	if c.Username == "" {
		return errors.New("username is required when dynamicAuth is configured")
	}
	if c.DynamicAuth.AWSElastiCacheIAM != nil {
		if c.DynamicAuth.AWSElastiCacheIAM.Region == "" {
			return errors.New("dynamicAuth.awsElastiCacheIam.region is required")
		}
		if c.DynamicAuth.AWSElastiCacheIAM.ClusterName == "" {
			return errors.New("dynamicAuth.awsElastiCacheIam.clusterName is required")
		}
	}
	return nil
}

func validateTLSConfig(cfg *TLSConfig) error {
	if cfg != nil && (len(cfg.ClientCert) == 0) != (len(cfg.ClientKey) == 0) {
		return errors.New("client certificate and key must be provided together")
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
