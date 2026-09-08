// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/jackc/pgx/v5"
)

// azureADScope is the OAuth2 scope Azure Database for PostgreSQL Flexible
// Server (and Single Server) requires for Entra ID (formerly Azure AD)
// token-based authentication.
const azureADScope = "https://ossrdbms-aad.database.windows.net/.default"

// azureADToken returns a single Entra ID access token usable as a PostgreSQL
// password for Azure Database for PostgreSQL.
func azureADToken(ctx context.Context) (string, error) {
	cred, err := newAzureCredential()
	if err != nil {
		return "", wrapAuthError("azureAd", err)
	}
	token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureADScope}})
	if err != nil {
		return "", wrapAuthError("azureAd", fmt.Errorf("failed to acquire Entra ID token: %w", err))
	}
	return token.Token, nil
}

// azureADBeforeConnect returns a BeforeConnect hook that generates a fresh
// Entra ID token before each connection attempt. The credential is
// constructed once, at hook-construction time; azidentity caches and
// refreshes the underlying token internally, so per-connection cost is a
// single (usually cached) token acquisition.
func azureADBeforeConnect() (BeforeConnectFn, error) {
	cred, err := newAzureCredential()
	if err != nil {
		return nil, wrapAuthError("azureAd", err)
	}
	return func(ctx context.Context, conn *pgx.ConnConfig) error {
		token, err := cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{azureADScope}})
		if err != nil {
			return wrapAuthError("azureAd", fmt.Errorf("failed to acquire Entra ID token: %w", err))
		}
		conn.Password = token.Token
		return nil
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
