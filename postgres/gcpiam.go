// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

// gcpCloudSQLIAMScope is the OAuth2 scope required for GCP Cloud SQL IAM
// database authentication — distinct from the broader sqlservice.admin scope
// used to manage Cloud SQL instances themselves.
const gcpCloudSQLIAMScope = "https://www.googleapis.com/auth/sqlservice.login"

// gcpCloudSQLIAMToken returns a single GCP OAuth2 access token usable as a
// PostgreSQL password for Cloud SQL IAM database authentication. This is the
// direct-TCP token-swap path, not the Cloud SQL Go connector (cloudsqlconn):
// it requires the instance to have a reachable IP and does not get Cloud
// SQL's automatic mTLS tunnel — see DynamicAuthGCPCloudSQLIAM's doc comment.
func gcpCloudSQLIAMToken(ctx context.Context) (string, error) {
	ts, err := newGCPTokenSource(ctx)
	if err != nil {
		return "", wrapAuthError("gcpCloudSqlIam", err)
	}
	token, err := tokenWithContext(ctx, ts)
	if err != nil {
		return "", wrapAuthError("gcpCloudSqlIam", fmt.Errorf("failed to acquire GCP access token: %w", err))
	}
	return token.AccessToken, nil
}

// gcpCloudSQLIAMBeforeConnect returns a BeforeConnect hook that generates a
// fresh GCP access token before each connection attempt. The token source is
// constructed once, at hook-construction time, using context.Background()
// rather than the ctx passed in here: google.DefaultTokenSource captures
// whatever context it's given for the lifetime of the returned TokenSource
// (used to build its internal token-refresh HTTP client), and this
// constructor's ctx is often request- or pool-construction-scoped and may be
// canceled shortly after NewPool returns — which would poison every later
// token refresh through this source. oauth2.TokenSource caches and refreshes
// the underlying token internally.
func gcpCloudSQLIAMBeforeConnect() (BeforeConnectFn, error) {
	ts, err := newGCPTokenSource(context.Background())
	if err != nil {
		return nil, wrapAuthError("gcpCloudSqlIam", err)
	}
	return func(ctx context.Context, conn *pgx.ConnConfig) error {
		token, err := tokenWithContext(ctx, ts)
		if err != nil {
			return wrapAuthError("gcpCloudSqlIam", fmt.Errorf("failed to acquire GCP access token: %w", err))
		}
		conn.Password = token.AccessToken
		return nil
	}, nil
}

// tokenWithContext calls ts.Token(), honoring ctx for cancellation even
// though oauth2.TokenSource's Token method takes no context of its own.
// This returns as soon as ctx is done, but — since the underlying call
// cannot itself be aborted through this interface — the goroutine calling
// Token() keeps running in the background until it completes on its own.
func tokenWithContext(ctx context.Context, ts oauth2.TokenSource) (*oauth2.Token, error) {
	type result struct {
		token *oauth2.Token
		err   error
	}
	ch := make(chan result, 1)
	go func() {
		token, err := ts.Token()
		ch <- result{token, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.token, r.err
	}
}

// newGCPTokenSource builds the token source used to acquire GCP access
// tokens. Unlike the AWS and Azure backends, this call is NOT
// credential-free: google.DefaultTokenSource resolves Application Default
// Credentials eagerly and returns an error immediately when none are found,
// rather than deferring resolution to the first Token() call. That makes its
// outcome environment-dependent in a way the other two backends'
// constructors are not, which is why this package has no equivalent to
// TestAwsRDSIAMBeforeConnect_ReturnsHookForStaticRegion /
// TestAzureADBeforeConnect_ReturnsHookWithoutContactingAzure for this
// backend — see the explanatory comment at the bottom of azuread_test.go.
func newGCPTokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	ts, err := google.DefaultTokenSource(ctx, gcpCloudSQLIAMScope)
	if err != nil {
		return nil, fmt.Errorf("failed to load GCP default credentials: %w", err)
	}
	return ts, nil
}
