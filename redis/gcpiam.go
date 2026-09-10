// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import redisconngcp "github.com/stacklok/toolhive-core/redisconn/gcp"

// DefaultGCPMemorystoreIAMTokenTTL is retained for source compatibility.
// Deprecated: use redisconngcp.DefaultConnMaxLifetime.
const DefaultGCPMemorystoreIAMTokenTTL = redisconngcp.DefaultConnMaxLifetime

func gcpMemorystoreIAMCredentialsFunc() (CredentialsFunc, error) {
	auth, err := redisconngcp.NewDynamicAuth(redisconngcp.Config{MemorystoreIAM: true})
	if err != nil {
		return nil, err
	}
	return CredentialsFunc(auth.CredentialsProviderContext), nil
}
