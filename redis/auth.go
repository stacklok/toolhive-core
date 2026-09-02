// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// CredentialsFunc resolves the username/password to authenticate a
// dynamic-auth-enabled connection with. It is wired into go-redis's
// Options.CredentialsProviderContext, which go-redis calls during the
// HELLO/AUTH handshake inside initConn — before RESP3 negotiation and DB
// selection happen. An OnConnect hook is unsuitable for this: go-redis only
// invokes OnConnect after HELLO/AUTH and any SELECT have already completed,
// which would silently downgrade otherwise RESP3-capable servers to RESP2
// and break selection of a non-zero database when Password is left empty
// for the hook to fill in later.
type CredentialsFunc func(ctx context.Context) (username, password string, err error)

// NewAuthToken returns the username and short-lived password minted by the
// dynamic-auth backend configured in cfg.DynamicAuth. When DynamicAuth is
// nil, both return values are empty and no error is raised — this lets
// callers fall back to a static Username/Password.
//
// This entry point is for callers that mint credentials outside NewClient
// (for example, a standalone health-check tool). NewClient does not call it;
// NewClient resolves a CredentialsFunc once and re-invokes it on every
// connection attempt so the credentials used stay current across reconnects.
func NewAuthToken(ctx context.Context, cfg *Config) (username, password string, err error) {
	if cfg == nil {
		return "", "", errors.New("config is nil")
	}
	if cfg.DynamicAuth == nil {
		return "", "", nil
	}
	fn, err := newDynamicAuthCredentialsFunc(ctx, cfg)
	if err != nil {
		return "", "", err
	}
	return fn(ctx)
}

// newDynamicAuthCredentialsFunc resolves cfg.DynamicAuth to a
// CredentialsFunc. Backend construction (region/credential resolution)
// happens once here; the returned CredentialsFunc mints fresh credentials on
// every call.
func newDynamicAuthCredentialsFunc(ctx context.Context, cfg *Config) (CredentialsFunc, error) {
	if err := singleDynamicAuthBackend(cfg.DynamicAuth); err != nil {
		return nil, err
	}
	switch {
	case cfg.DynamicAuth.AWSElastiCacheIAM != nil:
		return awsElastiCacheIAMCredentialsFunc(ctx, cfg)
	case cfg.DynamicAuth.AzureAD != nil:
		return azureADCredentialsFunc(cfg)
	case cfg.DynamicAuth.GCPMemorystoreIAM != nil:
		return gcpMemorystoreIAMCredentialsFunc()
	default:
		return nil, errors.New("unreachable: singleDynamicAuthBackend guarantees exactly one backend is set")
	}
}

// dynamicAuthConnMaxLifetime returns the ConnMaxLifetime NewClient installs
// for a dynamic-auth-enabled client when cfg.ConnMaxLifetime is unset: a
// value comfortably inside the backend's token TTL so go-redis retires and
// redials pooled connections — re-running the CredentialsProviderContext
// hook and picking up fresh credentials — well before the previous token
// would be rejected.
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
