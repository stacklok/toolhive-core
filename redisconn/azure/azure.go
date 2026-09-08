// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package azure

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"

	"github.com/stacklok/toolhive-core/redisconn"
)

// Azure Entra ID scope and default connection lifetime.
const (
	Scope                  = "acca5fbb-b7e4-4009-81f1-37e38fd66d78/.default"
	DefaultConnMaxLifetime = 45 * time.Minute
)

// Config configures Azure Cache for Redis Entra ID authentication.
type Config struct {
	Username string
}

// Validate requires the principal object ID used as the Redis username.
func (c Config) Validate() error {
	if c.Username == "" {
		return errors.New("username is required")
	}
	return nil
}

// NewDynamicAuth constructs DefaultAzureCredential without contacting Azure;
// credential resolution remains lazy until a connection requests a token.
func NewDynamicAuth(cfg Config) (*redisconn.DynamicAuth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, wrapError(err)
	}
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, wrapError(fmt.Errorf("failed to construct Azure credential: %w", err))
	}
	return dynamicAuth(cfg.Username, credential), nil
}

func dynamicAuth(username string, credential azcore.TokenCredential) *redisconn.DynamicAuth {
	return &redisconn.DynamicAuth{
		ConnMaxLifetime: DefaultConnMaxLifetime,
		CredentialsProviderContext: func(ctx context.Context) (string, string, error) {
			token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{Scope}})
			if err != nil {
				return "", "", wrapError(fmt.Errorf("failed to acquire Entra ID token: %w", err))
			}
			return username, token.Token, nil
		},
	}
}

func wrapError(err error) error {
	return fmt.Errorf("dynamic auth (azureAd): %w", err)
}
