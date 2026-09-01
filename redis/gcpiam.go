// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// gcpMemorystoreIAMScope is the OAuth2 scope required for Memorystore for
// Redis Cluster IAM authentication.
const gcpMemorystoreIAMScope = "https://www.googleapis.com/auth/cloud-platform"

// DefaultGCPMemorystoreIAMTokenTTL bounds go-redis's ConnMaxLifetime for GCP
// Memorystore IAM auth. GCP OAuth2 access tokens are typically valid ~60
// minutes; pooled connections are retired well inside that window.
const DefaultGCPMemorystoreIAMTokenTTL = 45 * time.Minute

// gcpMemorystoreIAMTokenFunc returns a TokenFunc that acquires a fresh GCP
// OAuth2 access token on every call, usable as a Redis AUTH password for
// Memorystore for Redis Cluster IAM authentication. cfg.Username must be
// the authenticating service account's email address.
//
// Unlike the AWS and Azure backends, this call is NOT credential-free:
// google.DefaultTokenSource resolves Application Default Credentials
// eagerly and returns an error immediately when none are found, rather than
// deferring resolution to the first Token() call.
func gcpMemorystoreIAMTokenFunc(ctx context.Context) (TokenFunc, error) {
	ts, err := newGCPTokenSource(ctx)
	if err != nil {
		return nil, wrapAuthError("gcpMemorystoreIam", err)
	}
	return func(context.Context) (string, error) {
		token, err := ts.Token()
		if err != nil {
			return "", wrapAuthError("gcpMemorystoreIam", fmt.Errorf("failed to acquire GCP access token: %w", err))
		}
		return token.AccessToken, nil
	}, nil
}

// newGCPTokenSource builds the token source used to acquire GCP access
// tokens, scoped for Memorystore IAM authentication.
func newGCPTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	ts, err := google.DefaultTokenSource(ctx, gcpMemorystoreIAMScope)
	if err != nil {
		return nil, fmt.Errorf("failed to load GCP default credentials: %w", err)
	}
	return ts, nil
}
