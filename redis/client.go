// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"crypto/tls"
	"fmt"

	goredis "github.com/redis/go-redis/v9"
	"github.com/stacklok/toolhive-core/redisconn"
)

// NewClient constructs and verifies a Redis client.
//
// Deprecated: use redisconn.NewClient.
func NewClient(ctx context.Context, cfg *Config) (goredis.UniversalClient, error) {
	if cfg == nil {
		return nil, fmt.Errorf("redis: config is nil")
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("redis: invalid configuration: %w", err)
	}
	var dynamicAuth *redisconn.DynamicAuth
	if cfg.DynamicAuth != nil {
		provider, err := newDynamicAuthCredentialsFunc(ctx, cfg)
		if err != nil {
			return nil, err
		}
		dynamicAuth = &redisconn.DynamicAuth{
			CredentialsProviderContext: redisconn.CredentialsProvider(provider),
			ConnMaxLifetime:            dynamicAuthConnMaxLifetime(cfg.DynamicAuth),
			AllowInsecureTransport:     cfg.DynamicAuth.AllowInsecureTransport,
		}
	}
	return redisconn.NewClient(ctx, cfg.redisconnConfig(dynamicAuth))
}

// BuildTLSConfig converts a legacy TLSConfig to crypto/tls configuration.
//
// Deprecated: use redisconn.BuildTLSConfig.
func BuildTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	return redisconn.BuildTLSConfig(cfg)
}
