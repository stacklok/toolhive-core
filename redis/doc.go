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
nil) or a custom CA bundle.

# Defaults and Validation

NewClient applies DefaultDialTimeout, DefaultReadTimeout, and
DefaultWriteTimeout when the corresponding Config fields are zero, then
validates connection-mode topology (Addr XOR SentinelConfig, ClusterMode
requires Addr, Sentinel requires MasterName plus at least one address). It
verifies the connection with a Ping before returning. Caller-specific
validation (key-prefix requirements, ACL enforcement) remains the caller's
responsibility.
*/
package redis
