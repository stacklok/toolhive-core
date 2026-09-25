// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

const closeNotificationHelperEnv = "TOOLHIVE_CLOSE_NOTIFICATION_HELPER"

// TestClientClose_DoesNotHoldMutexWhileNotificationHandlerDrains exercises the
// real go-sdk connection drain. The child-process boundary turns the former
// deadlock into a bounded test failure instead of wedging the package test run.
func TestClientClose_DoesNotHoldMutexWhileNotificationHandlerDrains(t *testing.T) {
	t.Parallel()

	if os.Getenv(closeNotificationHelperEnv) == "1" {
		testClientCloseNotificationHandlerDrains(t)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestClientClose_DoesNotHoldMutexWhileNotificationHandlerDrains$")
	cmd.Env = append(os.Environ(), closeNotificationHelperEnv+"=1")
	output, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "shutdown deadlocked or helper failed:\n%s", output)
}

func testClientCloseNotificationHandlerDrains(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	closeStarted := make(chan struct{})
	server := gosdk.NewServer(&gosdk.Implementation{Name: "test-server", Version: "1.0.0"}, nil)
	server.AddReceivingMiddleware(func(next gosdk.MethodHandler) gosdk.MethodHandler {
		return func(ctx context.Context, method string, req gosdk.Request) (gosdk.Result, error) {
			if method == "notifications/cancelled" {
				close(closeStarted)
			}
			return next(ctx, method, req)
		}
	})
	server.AddResource(&gosdk.Resource{Name: "first", URI: "file:///first"}, nil)
	clientTransport, serverTransport := gosdk.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = serverSession.Close() })

	compat := &Client{}
	callbackEntered := make(chan struct{})
	allowReentry := make(chan struct{})
	callbackDone := make(chan struct{})
	compat.OnNotification(func(mcp.JSONRPCNotification) {
		close(callbackEntered)
		<-allowReentry
		_, _ = compat.ListPrompts(ctx, mcp.ListPromptsRequest{})
		close(callbackDone)
	})

	opts := &gosdk.ClientOptions{}
	compat.installNotificationHandlers(opts)
	subscribed := make(chan struct{})
	client := gosdk.NewClient(&gosdk.Implementation{Name: "test-client", Version: "1.0.0"}, opts)
	client.AddReceivingMiddleware(func(next gosdk.MethodHandler) gosdk.MethodHandler {
		return func(ctx context.Context, method string, req gosdk.Request) (gosdk.Result, error) {
			if method == "notifications/subscriptions/acknowledged" {
				close(subscribed)
			}
			return next(ctx, method, req)
		}
	})
	session, err := client.Connect(ctx, clientTransport, nil)
	require.NoError(t, err)
	compat.client = client
	compat.session = session

	select {
	case <-subscribed:
	case <-time.After(time.Second):
		t.Fatal("resource-list subscription was not acknowledged")
	}
	server.AddResource(&gosdk.Resource{Name: "second", URI: "file:///second"}, nil)
	select {
	case <-callbackEntered:
	case <-time.After(time.Second):
		t.Fatal("resource-list notification did not reach the compatibility callback")
	}

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- compat.Close()
	}()
	select {
	case <-closeStarted:
	case <-time.After(time.Second):
		t.Fatal("Close did not begin draining the SDK session")
	}

	concurrentCloseDone := make(chan error, 1)
	go func() {
		concurrentCloseDone <- compat.Close()
	}()
	select {
	case err := <-concurrentCloseDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("concurrent Close did not return while shutdown drained")
	}

	close(allowReentry)

	select {
	case <-callbackDone:
	case <-time.After(time.Second):
		t.Fatal("notification callback could not re-enter the compatibility client")
	}
	select {
	case err := <-closeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Close did not finish after the notification callback returned")
	}
}
