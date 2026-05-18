// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// BeforeConnectFn rewrites a connection config (typically by replacing the
// password) immediately before pgx dials. It is the contract used by
// pgxpool.Config.BeforeConnect and by this package's dynamic-auth backends.
type BeforeConnectFn func(ctx context.Context, conn *pgx.ConnConfig) error

// NewAuthToken returns a short-lived password for user produced by the
// dynamic-authentication backend configured in cfg.DynamicAuth. When
// DynamicAuth is nil, the empty string is returned and no error is raised —
// this lets callers fall back to a static Password or PGPASSFILE.
//
// This entry point is intended for short-lived connections (for example,
// running migrations) where pgxpool's BeforeConnect hook is not available.
// For pooled connections, prefer NewDynamicAuthFunc.
func NewAuthToken(ctx context.Context, cfg *Config, user string) (string, error) {
	if cfg == nil {
		return "", errors.New("config is nil")
	}
	if cfg.DynamicAuth == nil {
		return "", nil
	}
	if cfg.DynamicAuth.AWSRDSIAM != nil {
		return awsRDSIAMToken(ctx, cfg, user)
	}
	return "", errors.New("dynamicAuth is set but no supported auth method (e.g., awsRdsIam) is configured")
}

// NewDynamicAuthFunc returns a BeforeConnect hook that resolves a fresh
// dynamic-auth credential on every connection attempt. The returned hook
// writes the resolved token into connConfig.Password.
//
// Returns an error when cfg.DynamicAuth is nil — callers that may or may
// not be configured for dynamic auth should branch on cfg.DynamicAuth
// before calling this constructor, or use NewPool which handles both
// shapes transparently.
func NewDynamicAuthFunc(ctx context.Context, cfg *Config, user string) (BeforeConnectFn, error) {
	if cfg == nil {
		return nil, errors.New("config is nil")
	}
	if cfg.DynamicAuth == nil {
		return nil, errors.New("dynamic authentication is not configured")
	}
	if cfg.DynamicAuth.AWSRDSIAM != nil {
		return awsRDSIAMBeforeConnect(ctx, cfg, user)
	}
	return nil, errors.New("dynamicAuth is set but no supported auth method (e.g., awsRdsIam) is configured")
}

// wrapAuthError prefixes dynamic-auth errors with a consistent label so they
// are easy to spot in pool startup logs.
func wrapAuthError(backend string, err error) error {
	return fmt.Errorf("dynamic auth (%s): %w", backend, err)
}
