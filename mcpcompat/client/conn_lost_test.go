// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestOnConnectionLost_FiresOnClose verifies the handler registered via
// OnConnectionLost is invoked once the session ends (here, via Close, which
// causes the underlying go-sdk ClientSession.Wait to return).
func TestOnConnectionLost_FiresOnClose(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newTestServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))

	lost := make(chan error, 1)
	// Register before Initialize: the watch must start once connected.
	c.OnConnectionLost(func(err error) { lost <- err })

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "c", Version: "1"},
		},
	})
	require.NoError(t, err)

	require.NoError(t, c.Close())

	select {
	case <-lost:
		// handler fired as expected (error value is transport-dependent).
	case <-time.After(5 * time.Second):
		t.Fatal("OnConnectionLost handler was not invoked after Close")
	}
}

// TestOnConnectionLost_RegisterAfterInitialize verifies registration works even
// when the client is already connected.
func TestOnConnectionLost_RegisterAfterInitialize(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newTestServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "c", Version: "1"},
		},
	})
	require.NoError(t, err)

	lost := make(chan error, 1)
	c.OnConnectionLost(func(err error) { lost <- err })

	require.NoError(t, c.Close())

	select {
	case <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("OnConnectionLost handler was not invoked after Close")
	}
}

// TestOnConnectionLost_NoHandlerNoWatch verifies registering no handler is safe
// and Close still works.
func TestOnConnectionLost_NoHandlerNoWatch(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newTestServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "c", Version: "1"},
		},
	})
	require.NoError(t, err)
	assert.NoError(t, c.Close())
}
