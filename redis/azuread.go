// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import redisconnazure "github.com/stacklok/toolhive-core/redisconn/azure"

// DefaultAzureADTokenTTL is retained for source compatibility.
// Deprecated: use redisconnazure.DefaultConnMaxLifetime.
const DefaultAzureADTokenTTL = redisconnazure.DefaultConnMaxLifetime

func azureADCredentialsFunc(cfg *Config) (CredentialsFunc, error) {
	auth, err := redisconnazure.NewDynamicAuth(redisconnazure.Config{Username: cfg.Username})
	if err != nil {
		return nil, err
	}
	return CredentialsFunc(auth.CredentialsProviderContext), nil
}
