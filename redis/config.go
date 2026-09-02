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
	// When DynamicAuth is set, whether Username is required depends on the
	// backend: AWS ElastiCache/MemoryDB IAM and Azure Entra ID require it (the
	// IAM user / principal object ID that minted tokens authenticate as); GCP
	// Memorystore IAM authentication is token-only and rejects a username, so
	// Username must be left empty for that backend.
	Username string

	// Password is the AUTH/ACL password. May be empty when the server does
	// not require authentication. Mutually exclusive with DynamicAuth.
	Password string //nolint:gosec // G101: field name, not a hardcoded credential

	// DynamicAuth, when non-nil, mints short-lived AUTH credentials from a
	// cloud IAM backend instead of using a static Password. NewClient
	// installs an Options.CredentialsProviderContext hook that resolves
	// fresh credentials for each connection attempt — during go-redis's
	// handshake, before RESP3 negotiation and DB selection — and sets
	// ConnMaxLifetime (when Config's own ConnMaxLifetime is zero) to a value
	// inside the backend's token TTL so pooled connections are periodically
	// retired and redialed with current credentials.
	//
	// Dynamic authentication requires a verified TLS connection (Config.TLS
	// set, with InsecureSkipVerify false): cloud IAM tokens are bearer
	// credentials, and sending them over an unverified or plaintext
	// connection lets a network attacker capture and replay them. Set
	// DynamicAuthConfig.AllowInsecureTransport to opt out for trusted local
	// tunneling (for example, a sidecar-terminated mTLS tunnel where this
	// package's own TLS handshake would be redundant).
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

	// AllowInsecureTransport opts out of the requirement that Config.TLS be
	// set (with verification enabled) when DynamicAuth is configured. Leave
	// false unless a trusted local tunnel already provides transport
	// security outside this package's own TLS handling.
	AllowInsecureTransport bool
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

	// ServiceName is the SigV4 signing service name. Must be empty (the
	// default, treated as "elasticache") or "memorydb".
	ServiceName string

	// ResourceType selects the AWS-required resource-type query parameter
	// for serverless caches. Must be empty (the default, for provisioned
	// ElastiCache/MemoryDB clusters) or "ServerlessCache" (for ElastiCache
	// Serverless / MemoryDB Serverless).
	ResourceType string
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
// Authentication is token-only (AUTH <token>) — Config.Username must be
// empty for this backend; Memorystore does not accept a username alongside
// the token.
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

// validateDynamicAuth checks c.DynamicAuth for backend-selection,
// transport-security, and required-field errors. Split into per-backend
// helpers to keep every function under the project's cyclomatic-complexity
// budget.
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
	if err := validateDynamicAuthTLS(c.TLS, c.DynamicAuth); err != nil {
		return err
	}
	switch {
	case c.DynamicAuth.AWSElastiCacheIAM != nil:
		return validateAWSElastiCacheIAM(c.Username, c.DynamicAuth.AWSElastiCacheIAM)
	case c.DynamicAuth.AzureAD != nil:
		return validateUsernameRequired(c.Username, "azureAd")
	case c.DynamicAuth.GCPMemorystoreIAM != nil:
		return validateUsernameForbidden(c.Username, "gcpMemorystoreIam", "GCP Memorystore IAM authentication is token-only")
	default:
		return nil
	}
}

// validateDynamicAuthTLS requires a verified TLS connection for dynamic
// authentication, unless the caller explicitly opted out via
// AllowInsecureTransport. Cloud IAM tokens are bearer credentials; sending
// them over an unverified or plaintext connection lets a network attacker
// capture and replay them.
func validateDynamicAuthTLS(tls *TLSConfig, da *DynamicAuthConfig) error {
	if da.AllowInsecureTransport {
		return nil
	}
	if tls == nil {
		return errors.New("TLS is required when dynamicAuth is configured " +
			"(set Config.TLS, or DynamicAuthConfig.AllowInsecureTransport to opt out for trusted local tunneling)")
	}
	if tls.InsecureSkipVerify {
		return errors.New("TLS must verify the server certificate when dynamicAuth is configured " +
			"(InsecureSkipVerify defeats the purpose of a signed token; " +
			"set DynamicAuthConfig.AllowInsecureTransport to opt out)")
	}
	return nil
}

// validateUsernameRequired returns an error when username is empty, for
// backends (AWS, Azure) whose AUTH command needs an explicit identity.
func validateUsernameRequired(username, backend string) error {
	if username == "" {
		return fmt.Errorf("username is required when dynamicAuth.%s is configured", backend)
	}
	return nil
}

// validateUsernameForbidden returns an error when username is set, for
// backends (GCP) whose AUTH command is token-only.
func validateUsernameForbidden(username, backend, reason string) error {
	if username != "" {
		return fmt.Errorf("username must not be set when dynamicAuth.%s is configured (%s)", backend, reason)
	}
	return nil
}

// validateAWSElastiCacheIAM checks required fields and enum-constrained
// fields on a DynamicAuthAWSElastiCacheIAM.
func validateAWSElastiCacheIAM(username string, iam *DynamicAuthAWSElastiCacheIAM) error {
	if err := validateUsernameRequired(username, "awsElastiCacheIam"); err != nil {
		return err
	}
	if iam.Region == "" {
		return errors.New("dynamicAuth.awsElastiCacheIam.region is required")
	}
	if iam.ClusterName == "" {
		return errors.New("dynamicAuth.awsElastiCacheIam.clusterName is required")
	}
	switch iam.ServiceName {
	case "", awsElastiCacheDefaultServiceName, awsElastiCacheMemoryDBServiceName:
	default:
		return fmt.Errorf("dynamicAuth.awsElastiCacheIam.serviceName must be empty, %q, or %q, got %q",
			awsElastiCacheDefaultServiceName, awsElastiCacheMemoryDBServiceName, iam.ServiceName)
	}
	switch iam.ResourceType {
	case "", awsElastiCacheServerlessResourceType:
	default:
		return fmt.Errorf("dynamicAuth.awsElastiCacheIam.resourceType must be empty or %q, got %q",
			awsElastiCacheServerlessResourceType, iam.ResourceType)
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
