// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package gcp

import (
	"context"
	"errors"
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/stacklok/toolhive-core/redisconn"
)

// GCP Memorystore scope and default connection lifetime.
const (
	Scope                  = "https://www.googleapis.com/auth/cloud-platform"
	DefaultConnMaxLifetime = 45 * time.Minute
)

// Config explicitly selects token-only Memorystore IAM authentication.
type Config struct {
	// MemorystoreIAM must be true to explicitly select token-only IAM auth.
	MemorystoreIAM bool
}

// Validate requires explicit selection of Memorystore IAM authentication.
func (c Config) Validate() error {
	if !c.MemorystoreIAM {
		return errors.New("memorystore IAM marker must be enabled")
	}
	return nil
}

// NewDynamicAuth resolves Application Default Credentials eagerly and retains
// their token source for the client lifetime. A canceled connection context
// makes the callback return promptly, but oauth2.TokenSource has no context-aware
// Token method, so cancellation cannot interrupt an in-progress Token call.
func NewDynamicAuth(cfg Config) (*redisconn.DynamicAuth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, wrapError(err)
	}
	tokenSource, err := google.DefaultTokenSource(context.Background(), Scope)
	if err != nil {
		return nil, wrapError(fmt.Errorf("failed to load GCP default credentials: %w", err))
	}
	return dynamicAuth(tokenSource), nil
}

func dynamicAuth(tokenSource oauth2.TokenSource) *redisconn.DynamicAuth {
	return &redisconn.DynamicAuth{
		ConnMaxLifetime: DefaultConnMaxLifetime,
		CredentialsProviderContext: func(ctx context.Context) (string, string, error) {
			token, err := tokenWithContext(ctx, tokenSource)
			if err != nil {
				return "", "", wrapError(fmt.Errorf("failed to acquire GCP access token: %w", err))
			}
			return "", token.AccessToken, nil
		},
	}
}

func tokenWithContext(ctx context.Context, tokenSource oauth2.TokenSource) (*oauth2.Token, error) {
	type result struct {
		token *oauth2.Token
		err   error
	}
	resultCh := make(chan result, 1)
	go func() {
		token, err := tokenSource.Token()
		resultCh <- result{token: token, err: err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case got := <-resultCh:
		return got.token, got.err
	}
}

func wrapError(err error) error {
	return fmt.Errorf("dynamic auth (gcpMemorystoreIam): %w", err)
}
