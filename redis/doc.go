// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package redis provides a shared Redis client connection layer used by
toolhive components and stacklok-llm-gateway services.

The package wraps github.com/redis/go-redis/v9 with a single Config type and
NewClient factory that supports three connection modes:

  - Standalone — a single endpoint (Addr).
  - Cluster    — Redis Cluster protocol against a single seed Addr.
  - Sentinel   — high-availability failover via SentinelConfig.

The returned client is a goredis.UniversalClient so callers can write
mode-agnostic code.

# Connection Modes

Standalone:

	cli, err := redis.NewClient(ctx, &redis.Config{
	    Addr:     "redis.example.com:6379",
	    Password: "...",
	    DB:       0,
	})

Cluster:

	cli, err := redis.NewClient(ctx, &redis.Config{
	    Addr:        "cluster.example.com:6379",
	    ClusterMode: true,
	    Username:    "app",
	    Password:    "...",
	})

Sentinel:

	cli, err := redis.NewClient(ctx, &redis.Config{
	    SentinelConfig: &redis.SentinelConfig{
	        MasterName:    "mymaster",
	        SentinelAddrs: []string{"sentinel-0:26379", "sentinel-1:26379"},
	    },
	    Password: "...",
	})

# TLS

TLS is opt-in per connection target. When TLS is set, master/cluster
connections use it. SentinelTLS, when set, applies to sentinel daemon
connections independently — useful when the master and sentinels present
different certificate chains. Both fields accept either system CAs (CACert
nil) or a custom CA bundle. To use mTLS, set ClientCert and ClientKey to a
PEM-encoded client certificate/key pair; the master and sentinel connections
can use different pairs.

# Defaults and Validation

NewClient applies DefaultDialTimeout, DefaultReadTimeout, and
DefaultWriteTimeout when the corresponding Config fields are zero, then
validates connection-mode topology (Addr XOR SentinelConfig, ClusterMode
requires Addr, Sentinel requires MasterName plus at least one address). It
verifies the connection with a Ping before returning. Caller-specific
validation (key-prefix requirements, ACL enforcement) remains the caller's
responsibility.

# Dynamic Authentication

Config.DynamicAuth mints short-lived AUTH credentials from a cloud IAM
backend instead of using a static Password:

  - AWSElastiCacheIAM — ElastiCache/MemoryDB IAM authentication tokens,
    hand-signed with SigV4 (there is no RDS-style auth.BuildAuthToken helper
    for these services). Supports ElastiCache/MemoryCache Serverless via
    ResourceType.
  - AzureAD — Entra ID (formerly Azure AD) access tokens for Azure Cache for
    Redis.
  - GCPMemorystoreIAM — GCP OAuth2 access tokens for Memorystore for Redis
    Cluster IAM authentication. This backend authenticates token-only
    (AUTH <token>, no username) — Config.Username must be left empty.

Dynamic authentication requires a verified TLS connection (Config.TLS set,
with InsecureSkipVerify false): these are bearer credentials, and sending
them over an unverified or plaintext connection lets a network attacker
capture and replay them. Set DynamicAuthConfig.AllowInsecureTransport to opt
out for trusted local tunneling.

Unlike pgx's BeforeConnect hook, go-redis has no per-dial hook that runs
before its own HELLO/AUTH handshake, and pooled connections are long-lived
rather than reconnecting per operation. NewClient works around the first
problem by wiring Options.CredentialsProviderContext, which go-redis
resolves during that handshake — before RESP3 negotiation and DB selection
— rather than OnConnect, which only fires afterward (breaking non-zero DB
selection and silently downgrading otherwise RESP3-capable connections to
RESP2). It works around the second by setting ConnMaxLifetime (defaulted
per backend, inside the token's TTL, when Config.ConnMaxLifetime is zero)
so go-redis periodically retires and redials pooled connections — re-running
CredentialsProviderContext and picking up current credentials before the
previous token would be rejected.

For Sentinel, CredentialsProviderContext is wired only onto the data-node
(master/replica) connections: go-redis's FailoverOptions deliberately does
not propagate it to the internal Sentinel-daemon connections it builds (those
authenticate with SentinelUsername/SentinelPassword instead), so the cloud
data-node identity never reaches the Sentinel daemons.

	cli, err := redis.NewClient(ctx, &redis.Config{
	    Addr:     "my-cluster.abcdef.ng.0001.use1.cache.amazonaws.com:6379",
	    Username: "app-iam-user",
	    TLS:      &redis.TLSConfig{},
	    DynamicAuth: &redis.DynamicAuthConfig{
	        AWSElastiCacheIAM: &redis.DynamicAuthAWSElastiCacheIAM{
	            Region:      "us-east-1",
	            ClusterName: "my-cluster",
	        },
	    },
	})

Whether Config.Username is required depends on the backend: AWS ElastiCache/
MemoryDB IAM and Azure Entra ID require it (the IAM user / principal object
ID that minted tokens authenticate as); GCP Memorystore IAM authentication
rejects a username. Config.Password must always be empty when DynamicAuth is
set.
*/
package redis
