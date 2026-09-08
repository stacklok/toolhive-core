// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/stacklok/toolhive-core/redisconn"
)

// Default timeouts applied by NewClient when the corresponding Config field
// is zero.
const (
	DefaultDialTimeout  = redisconn.DefaultDialTimeout
	DefaultReadTimeout  = redisconn.DefaultReadTimeout
	DefaultWriteTimeout = redisconn.DefaultWriteTimeout
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
	// inside the backend's token TTL. go-redis retires an over-age pooled
	// connection lazily when it is reused; this does not proactively refresh
	// or reauthenticate an open connection.
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

// SentinelConfig is kept for source compatibility.
// Deprecated: use redisconn.SentinelConfig.
type SentinelConfig = redisconn.SentinelConfig

// TLSConfig is kept for source compatibility.
// Deprecated: use redisconn.TLSConfig.
type TLSConfig = redisconn.TLSConfig

// Validate checks Config for connection and provider configuration errors.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("config is nil")
	}
	base := c.redisconnConfig(nil)
	if err := base.Validate(); err != nil {
		return err
	}
	if c.DynamicAuth == nil {
		return nil
	}
	if err := singleDynamicAuthBackend(c.DynamicAuth); err != nil {
		return err
	}
	base.DynamicAuth = &redisconn.DynamicAuth{
		CredentialsProviderContext: func(context.Context) (string, string, error) { return "", "", nil },
		AllowInsecureTransport:     c.DynamicAuth.AllowInsecureTransport,
	}
	if err := base.Validate(); err != nil {
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

func (c *Config) redisconnConfig(dynamicAuth *redisconn.DynamicAuth) *redisconn.Config {
	return &redisconn.Config{
		Addr: c.Addr, ClusterMode: c.ClusterMode, SentinelConfig: c.SentinelConfig,
		Username: c.Username, Password: c.Password, DynamicAuth: dynamicAuth, DB: c.DB,
		DialTimeout: c.DialTimeout, ReadTimeout: c.ReadTimeout, WriteTimeout: c.WriteTimeout,
		TLS: c.TLS, SentinelTLS: c.SentinelTLS, ConnMaxLifetime: c.ConnMaxLifetime,
	}
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
