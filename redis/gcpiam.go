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

// gcpMemorystoreIAMCredentialsFunc returns a CredentialsFunc that acquires a
// fresh GCP OAuth2 access token on every call, usable as a Redis AUTH
// password for Memorystore for Redis Cluster IAM authentication.
//
// Memorystore for Redis Cluster IAM authentication is token-only: the
// server authenticates AUTH <token>, and explicitly does not accept a
// username (for example, a service account email) alongside it — the
// returned CredentialsFunc always reports an empty username.
//
// Unlike the AWS and Azure backends, this call is NOT credential-free:
// google.DefaultTokenSource resolves Application Default Credentials
// eagerly and returns an error immediately when none are found, rather than
// deferring resolution to the first Token() call.
func gcpMemorystoreIAMCredentialsFunc() (CredentialsFunc, error) {
	// Deliberately context.Background(), not the ctx passed through
	// NewClient: DefaultTokenSource captures whatever context it's given
	// for the lifetime of the returned TokenSource (it's used to build the
	// source's internal token-refresh HTTP client). NewClient's ctx is
	// often request- or deploy-scoped and may be canceled shortly after
	// NewClient returns (e.g. a deferred cancel from a construction
	// timeout); that would poison every later token refresh through this
	// source. The token source's actual lifetime matches the client's, not
	// the call that constructed it, so it needs a context that outlives
	// construction.
	ts, err := newGCPTokenSource(context.Background())
	if err != nil {
		return nil, wrapAuthError("gcpMemorystoreIam", err)
	}
	return func(context.Context) (string, string, error) {
		token, err := ts.Token()
		if err != nil {
			return "", "", wrapAuthError("gcpMemorystoreIam", fmt.Errorf("failed to acquire GCP access token: %w", err))
		}
		return "", token.AccessToken, nil
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
