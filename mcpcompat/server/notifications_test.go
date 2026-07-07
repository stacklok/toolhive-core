// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// TestSendNotificationToAllClients_NoSessions verifies the broadcast is a safe
// no-op when there are no connected clients.
func TestSendNotificationToAllClients_NoSessions(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("notify-server", "1.0.0")
	assert.NotPanics(t, func() {
		srv.SendNotificationToAllClients("notifications/message", map[string]any{"data": "hi"})
	})
}

// TestSendNotificationToAllClients_Broadcast connects a live client and then
// broadcasts several notification methods, exercising the real per-session
// dispatch path (progress/message/list-changed/unknown) without panicking.
func TestSendNotificationToAllClients_Broadcast(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("notify-server", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithLogging(),
	)
	srv.AddTool(
		mcp.NewTool("noop", mcp.WithDescription("noop")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

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
	t.Cleanup(func() { _ = c.Close() })

	// Each of these maps onto a different branch of the dispatcher; none should
	// panic even though some are dropped (list-changed, unknown).
	assert.NotPanics(t, func() {
		srv.SendNotificationToAllClients("notifications/progress",
			map[string]any{"progressToken": "t", "progress": 0.5})
		srv.SendNotificationToAllClients("notifications/message",
			map[string]any{"level": "info", "data": "hello"})
		srv.SendNotificationToAllClients("notifications/tools/list_changed", nil)
		srv.SendNotificationToAllClients("some/unknown/method", map[string]any{"x": 1})
	})
}

// TestSSEHandlers verifies SSEServer exposes non-nil SSE and message handlers.
func TestSSEHandlers(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("sse-server", "1.0.0")
	sse := server.NewSSEServer(srv)
	assert.NotNil(t, sse.SSEHandler())
	assert.NotNil(t, sse.MessageHandler())
}
