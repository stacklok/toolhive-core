// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redisconn_test

import (
	"context"

	"github.com/stacklok/toolhive-core/redisconn"
)

func ExampleNewClient_staticCredentials() {
	client, err := redisconn.NewClient(context.Background(), &redisconn.Config{
		Addr:     "redis.example.com:6379",
		Username: "application",
		Password: "secret",
		TLS:      &redisconn.TLSConfig{}, // system roots and server verification
	})
	if err != nil {
		return
	}
	defer client.Close()
}
