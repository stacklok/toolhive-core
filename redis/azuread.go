// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// azureADScope is the OAuth2 scope Azure Cache for Redis requires for
// Entra ID (formerly Azure AD) token-based authentication.
const azureADScope = "acca5fbb-b7e4-4009-81f1-37e38fd66d78/.default"

// DefaultAzureADTokenTTL bounds go-redis's ConnMaxLifetime for Azure Entra
// ID auth. Entra ID access tokens are typically valid ~60-90 minutes;
// pooled connections are retired well inside that window.
const DefaultAzureADTokenTTL = 45 * time.Minute

// azureADTokenFunc returns a TokenFunc that acquires a fresh Entra ID access
// token on every call, usable as a Redis AUTH password. The credential is
// constructed once, at hook-construction time; azidentity caches and
// refreshes the underlying token internally, so per-call cost is usually a
// cache hit rather than a network round trip.
func azureADTokenFunc() (TokenFunc, error) {
	cred, err := newAzureCredential()
	if err != nil {
		return nil, wrapAuthError("azureAd", err)
	}
	return func(ctx context.Context) (string, error) {
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureADScope}})
		if err != nil {
			return "", wrapAuthError("azureAd", fmt.Errorf("failed to acquire Entra ID token: %w", err))
		}
		return token.Token, nil
	}, nil
}

// newAzureCredential builds the credential used to acquire Entra ID tokens.
// Construction never contacts Azure — DefaultAzureCredential resolves
// lazily, on the first GetToken call, following its normal chain
// (environment variables — including AZURE_CLIENT_ID to select a
// user-assigned managed identity — workload identity, managed identity,
// Azure CLI, ...).
func newAzureCredential() (*azidentity.DefaultAzureCredential, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to construct Azure credential: %w", err)
	}
	return cred, nil
}
