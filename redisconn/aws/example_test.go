// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package aws_test

import (
	"context"

	"github.com/stacklok/toolhive-core/redisconn"
	redisconnaws "github.com/stacklok/toolhive-core/redisconn/aws"
)

func ExampleNewDynamicAuth() {
	auth, err := redisconnaws.NewDynamicAuth(context.Background(), redisconnaws.Config{
		Username:    "redis-iam-user",
		Region:      "us-east-1",
		ClusterName: "orders-cache",
	})
	if err != nil {
		return
	}
	client, err := redisconn.NewClient(context.Background(), &redisconn.Config{
		Addr:        "orders-cache.example.cache.amazonaws.com:6379",
		TLS:         &redisconn.TLSConfig{},
		DynamicAuth: auth,
	})
	if err != nil {
		return
	}
	defer client.Close()
}
