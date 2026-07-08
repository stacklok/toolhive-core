// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
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
// dispatch path (progress/message/list-changed/unknown). It registers an
// OnNotification handler and asserts that the progress and message
// notifications actually arrive with their expected params, so that a silent
// regression in sendOneNotification's jsonConvert or the go-sdk's
// NotifyProgress/Log is caught rather than masked by a NotPanics check.
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

	// WithContinuousListening opens the standalone SSE stream so
	// server-initiated notifications (which arrive outside any in-flight
	// request) are delivered to the client rather than dropped.
	c, err := client.NewStreamableHttpClient(ts.URL, transport.WithContinuousListening())
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

	// The server only delivers notifications/message once the client has set a
	// logging level, so raise it before broadcasting.
	require.NoError(t, c.SetLoggingLevel(ctx, mcp.LoggingLevelInfo))

	type recorded struct {
		method string
		params mcp.NotificationParams
	}
	var (
		mu       sync.Mutex
		got      []recorded
		progChan = make(chan recorded, 1)
		logChan  = make(chan recorded, 1)
	)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		r := recorded{method: n.Method, params: n.Params}
		mu.Lock()
		got = append(got, r)
		mu.Unlock()
		switch n.Method {
		case "notifications/progress":
			select {
			case progChan <- r:
			default:
			}
		case "notifications/message":
			select {
			case logChan <- r:
			default:
			}
		}
	})

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

	// Confirm the progress notification actually arrived with its params.
	select {
	case p := <-progChan:
		assert.Equal(t, "notifications/progress", p.method)
		assert.Equal(t, "t", p.params.AdditionalFields["progressToken"])
		assert.InDelta(t, 0.5, p.params.AdditionalFields["progress"], 1e-9)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notifications/progress broadcast")
	}
	// Confirm the message notification actually arrived with its params.
	select {
	case l := <-logChan:
		assert.Equal(t, "notifications/message", l.method)
		assert.Equal(t, "info", l.params.AdditionalFields["level"])
		assert.Equal(t, "hello", l.params.AdditionalFields["data"])
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notifications/message broadcast")
	}
}

// TestSSEHandlers verifies SSEServer exposes non-nil SSE and message handlers.
func TestSSEHandlers(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("sse-server", "1.0.0")
	sse := server.NewSSEServer(srv)
	assert.NotNil(t, sse.SSEHandler())
	assert.NotNil(t, sse.MessageHandler())
}

// TestListChanged_EmittedOnSetSessionTools verifies that the go-sdk server
// auto-emits a notifications/tools/list_changed notification to the connected
// client when a per-session tool overlay is applied via SetSessionTools. This
// restores the mcp-go behavior where mutating a session's tool set notifies
// the client, and depends on WithToolCapabilities(true) so the server
// advertises (and emits) list_changed. Without the per-session sync onto the
// go-sdk server (syncSessionTools), the notification would never fire.
func TestListChanged_EmittedOnSetSessionTools(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var (
		regSession server.ClientSession
		regDone    = make(chan struct{})
	)
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, s server.ClientSession) {
		regSession = s
		close(regDone)
	})

	srv := server.NewMCPServer("lc-server", "1.0.0",
		server.WithToolCapabilities(true),
		server.WithHooks(hooks),
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	// WithContinuousListening opens the standalone SSE stream so server-initiated
	// notifications (the list_changed fired by SetSessionTools, which arrives
	// outside any in-flight request) can be delivered. Without it the go-sdk
	// streamable transport has no channel to carry such notifications and drops
	// them (see streamable.go streamableServerConn.Write -> streams[""]).
	c, err := client.NewStreamableHttpClient(ts.URL, transport.WithContinuousListening())
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	var (
		gotListChanged atomic.Bool
		done           = make(chan struct{})
	)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		if n.Method == "notifications/tools/list_changed" && gotListChanged.CompareAndSwap(false, true) {
			close(done)
		}
	})

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: "lc-client", Version: "1"},
		},
	})
	require.NoError(t, err)

	// Wait for the OnRegisterSession hook to fire (it runs during initialize) so
	// we have a handle to the session to mutate.
	select {
	case <-regDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnRegisterSession")
	}

	// SetSessionTools must be exposed on the session; assert it and mutate the
	// overlay, which reconciles onto the live go-sdk server and triggers the
	// auto-emitted list_changed notification.
	swt, ok := regSession.(server.SessionWithTools)
	require.True(t, ok, "session must implement SessionWithTools")
	swt.SetSessionTools(map[string]server.ServerTool{
		"injected": {
			Tool: mcp.NewTool("injected", mcp.WithDescription("injected at runtime")),
			Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("ok"), nil
			},
		},
	})

	// go-sdk debounces list_changed by ~10ms. Exit as soon as the list_changed
	// notification arrives (via done), falling back to a generous timeout.
	select {
	case <-done:
	case <-time.After(1500 * time.Millisecond):
	}
	assert.True(t, gotListChanged.Load(),
		"expected notifications/tools/list_changed after SetSessionTools")
}
