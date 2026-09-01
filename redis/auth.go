// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// TokenFunc mints a fresh short-lived password for a dynamic-auth backend.
// client.go calls it from an Options.OnConnect hook so every newly dialed
// (or redialed) connection authenticates with a current token.
type TokenFunc func(ctx context.Context) (string, error)

// NewAuthToken returns a short-lived password minted by the dynamic-auth
// backend configured in cfg.DynamicAuth, using cfg.Username as the ACL/IAM
// identity. When DynamicAuth is nil, the empty string is returned and no
// error is raised — this lets callers fall back to a static Password.
//
// This entry point is for callers that mint a token outside NewClient (for
// example, a standalone health-check tool). NewClient does not call it;
// NewClient resolves a TokenFunc once and re-invokes it on every OnConnect so
// the token used stays current across reconnects.
func NewAuthToken(ctx context.Context, cfg *Config) (string, error) {
	if cfg == nil {
		return "", errors.New("config is nil")
	}
	if cfg.DynamicAuth == nil {
		return "", nil
	}
	fn, err := newDynamicAuthTokenFunc(ctx, cfg)
	if err != nil {
		return "", err
	}
	return fn(ctx)
}

// newDynamicAuthTokenFunc resolves cfg.DynamicAuth to a TokenFunc. Backend
// construction (region/credential resolution) happens once here; the
// returned TokenFunc mints a fresh token on every call.
func newDynamicAuthTokenFunc(ctx context.Context, cfg *Config) (TokenFunc, error) {
	if err := singleDynamicAuthBackend(cfg.DynamicAuth); err != nil {
		return nil, err
	}
	switch {
	case cfg.DynamicAuth.AWSElastiCacheIAM != nil:
		return awsElastiCacheIAMTokenFunc(ctx, cfg)
	case cfg.DynamicAuth.AzureAD != nil:
		return azureADTokenFunc()
	case cfg.DynamicAuth.GCPMemorystoreIAM != nil:
		return gcpMemorystoreIAMTokenFunc(ctx)
	default:
		return nil, errors.New("unreachable: singleDynamicAuthBackend guarantees exactly one backend is set")
	}
}

// dynamicAuthConnMaxLifetime returns the ConnMaxLifetime NewClient installs
// for a dynamic-auth-enabled client when cfg.ConnMaxLifetime is unset: a
// value comfortably inside the backend's token TTL so go-redis retires and
// redials pooled connections — re-running OnConnect and picking up a fresh
// token — well before the previous token would be rejected.
func dynamicAuthConnMaxLifetime(da *DynamicAuthConfig) time.Duration {
	switch {
	case da.AWSElastiCacheIAM != nil:
		return DefaultAWSElastiCacheIAMTokenTTL
	case da.AzureAD != nil:
		return DefaultAzureADTokenTTL
	case da.GCPMemorystoreIAM != nil:
		return DefaultGCPMemorystoreIAMTokenTTL
	default:
		return 0
	}
}

// wrapAuthError prefixes dynamic-auth errors with a consistent label so they
// are easy to spot in client-construction logs.
func wrapAuthError(backend string, err error) error {
	return fmt.Errorf("dynamic auth (%s): %w", backend, err)
}
