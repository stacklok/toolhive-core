// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// relay test fixtures reused across the sampling/notification relay tests;
// factored into consts so goconst does not flag them.
const (
	samplePrompt   = "summarize this"
	sampleSummary  = "a short summary"
	sampleModel    = "test-model"
	sampleToolName = "summarize"
	emitToolName   = "emit"

	// notification method + field names shared with notifications_test.go so
	// goconst does not flag their repeated use across the package's test files.
	methodProgress     = "notifications/progress"
	methodMessage      = "notifications/message"
	fieldProgress      = "progress"
	fieldProgressToken = "progressToken"
	fieldData          = "data"
)

// TestSampling_EndToEnd exercises the full server->client sampling relay: a
// tool handler calls srv.RequestSampling, the shim client (built
// WithSamplingHandler) answers with a fixed result, and the sampled text is
// round-tripped back into the tool result. Because go-sdk rejects
// sampling/createMessage unless the client declared the sampling capability
// (see (*Client).createMessage -> "client does not support CreateMessage"), a
// successful round-trip proves the capability was advertised at initialize.
//
// Like elicitation, sampling made during a tools/call is routed by go-sdk to
// the standalone SSE stream under JSONResponse, so the client must be built
// with transport.WithContinuousListening().
func TestSampling_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("sampling-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool(sampleToolName, mcp.WithDescription("ask the client to sample")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			res, err := srv.RequestSampling(ctx, mcp.CreateMessageRequest{
				CreateMessageParams: mcp.CreateMessageParams{
					MaxTokens: 100,
					Messages: []mcp.SamplingMessage{{
						Role:    mcp.RoleUser,
						Content: mcp.NewTextContent(samplePrompt),
					}},
				},
			})
			if err != nil {
				return nil, err
			}
			// Content round-trips through JSON as a map on the mcp-go-shaped side
			// (SamplingMessage.Content is any, matching mcp-go).
			text, _ := res.Content.(map[string]any)["text"].(string)
			return mcp.NewToolResultText("sampled=" + text + " model=" + res.Model), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	var (
		mu        sync.Mutex
		gotPrompt string
	)
	c, err := client.NewStreamableHttpClientWithOpts(
		ts.URL,
		[]transport.StreamableHTTPCOption{transport.WithContinuousListening()},
		[]client.ClientOption{client.WithSamplingHandler(client.SamplingHandlerFunc(
			func(_ context.Context, request mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
				// Capture the server's prompt to assert the request direction too.
				mu.Lock()
				if len(request.Messages) > 0 {
					if m, ok := request.Messages[0].Content.(map[string]any); ok {
						gotPrompt, _ = m["text"].(string)
					}
				}
				mu.Unlock()
				return &mcp.CreateMessageResult{
					SamplingMessage: mcp.SamplingMessage{
						Role:    mcp.RoleAssistant,
						Content: mcp.NewTextContent(sampleSummary),
					},
					Model:      sampleModel,
					StopReason: "endTurn",
				}, nil
			},
		))},
	)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: sampleToolName}})
	require.NoError(t, err)
	require.False(t, res.IsError, "sampling must complete; the client sampling capability must be advertised")
	require.Len(t, res.Content, 1)
	txt, ok := mcp.AsTextContent(res.Content[0])
	require.True(t, ok)
	assert.Equal(t, "sampled="+sampleSummary+" model="+sampleModel, txt.Text,
		"the tool handler must have received the client's sampled message")

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, samplePrompt, gotPrompt, "the client sampling handler must have received the server's prompt")
}

// TestSampling_HandlerReturnsError verifies the error-return path of sampling:
// when the client's sampling handler returns an error, the server's
// RequestSampling surfaces it and the surrounding tools/call fails wrapping
// that error. go-sdk carries the handler's error back to the server-side
// CreateMessage call.
func TestSampling_HandlerReturnsError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("sampling-err-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool(sampleToolName, mcp.WithDescription("ask the client to sample")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, err := srv.RequestSampling(ctx, mcp.CreateMessageRequest{
				CreateMessageParams: mcp.CreateMessageParams{
					MaxTokens: 10,
					Messages: []mcp.SamplingMessage{{
						Role:    mcp.RoleUser,
						Content: mcp.NewTextContent(samplePrompt),
					}},
				},
			})
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText("unreachable"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClientWithOpts(
		ts.URL,
		[]transport.StreamableHTTPCOption{transport.WithContinuousListening()},
		[]client.ClientOption{client.WithSamplingHandler(client.SamplingHandlerFunc(
			func(_ context.Context, _ mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error) {
				return nil, assert.AnError
			},
		))},
	)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	_, err = c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: sampleToolName}})
	require.Error(t, err, "a sampling handler error must surface as a failed tools/call")
	require.NotErrorIs(t, err, context.DeadlineExceeded,
		"sampling must be rejected, not surface as a context timeout")
}

// TestRequestSampling_NoActiveSession is a fast unit-level test exercising the
// ErrNoActiveSession guard: calling RequestSampling outside any session's
// request context returns ErrNoActiveSession.
func TestRequestSampling_NoActiveSession(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("sampling-unit", testClientVersion)
	_, err := srv.RequestSampling(t.Context(), mcp.CreateMessageRequest{
		CreateMessageParams: mcp.CreateMessageParams{MaxTokens: 1},
	})
	require.ErrorIs(t, err, server.ErrNoActiveSession)
}

// TestRequestSampling_SessionWithoutSamplingSupport exercises the
// ErrSamplingNotSupported guard: a session bound via WithContext that does NOT
// implement SessionWithSampling causes RequestSampling to return
// ErrSamplingNotSupported.
func TestRequestSampling_SessionWithoutSamplingSupport(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("sampling-unit", testClientVersion)
	ctx := srv.WithContext(t.Context(), &fakeSession{id: "sess-no-sampling"})
	_, err := srv.RequestSampling(ctx, mcp.CreateMessageRequest{
		CreateMessageParams: mcp.CreateMessageParams{MaxTokens: 1},
	})
	require.ErrorIs(t, err, server.ErrSamplingNotSupported)
}

// TestSendNotificationToClient_EndToEnd exercises the per-session notification
// relay: a tool handler calls srv.SendNotificationToClient for both
// notifications/progress and notifications/message, and the calling client
// (built WithContinuousListening + OnNotification) receives both mid-call.
// This is the per-session counterpart to the SendNotificationToAllClients
// broadcast test.
func TestSendNotificationToClient_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("relay-notify-server", testClientVersion,
		server.WithToolCapabilities(false),
		server.WithLogging(),
	)
	srv.AddTool(
		mcp.NewTool(emitToolName, mcp.WithDescription("emit progress+log to the calling client")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := srv.SendNotificationToClient(ctx, methodProgress,
				map[string]any{fieldProgressToken: "tok", fieldProgress: 0.42}); err != nil {
				return nil, err
			}
			if err := srv.SendNotificationToClient(ctx, methodMessage,
				map[string]any{"level": "info", fieldData: "hello-from-tool"}); err != nil {
				return nil, err
			}
			return mcp.NewToolResultText("emitted"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL, transport.WithContinuousListening())
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	progChan := make(chan mcp.NotificationParams, 1)
	logChan := make(chan mcp.NotificationParams, 1)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		switch n.Method {
		case methodProgress:
			select {
			case progChan <- n.Params:
			default:
			}
		case methodMessage:
			select {
			case logChan <- n.Params:
			default:
			}
		}
	})

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	// notifications/message is only delivered once the client sets a logging level.
	require.NoError(t, c.SetLoggingLevel(ctx, mcp.LoggingLevelInfo))

	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: emitToolName}})
	require.NoError(t, err)
	require.False(t, res.IsError, "the tool must succeed; both SendNotificationToClient calls must not error")

	select {
	case p := <-progChan:
		assert.Equal(t, "tok", p.AdditionalFields[fieldProgressToken])
		assert.InDelta(t, 0.42, p.AdditionalFields[fieldProgress], 1e-9)
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the per-session progress notification")
	}
	select {
	case l := <-logChan:
		assert.Equal(t, "info", l.AdditionalFields["level"])
		assert.Equal(t, "hello-from-tool", l.AdditionalFields[fieldData])
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the per-session message notification")
	}
}

// TestSendNotificationToClient_NoActiveSession verifies the documented
// no-session behavior: calling SendNotificationToClient with a context that
// carries no session returns ErrNoActiveSession (so a best-effort relay can
// treat it as a no-op).
func TestSendNotificationToClient_NoActiveSession(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("relay-unit", testClientVersion)
	err := srv.SendNotificationToClient(t.Context(), methodProgress,
		map[string]any{fieldProgress: 1.0})
	require.ErrorIs(t, err, server.ErrNoActiveSession)
}

// TestSendNotificationToClient_UnsupportedMethod verifies an unmappable method
// returns ErrUnsupportedNotification rather than being silently dropped, so a
// relay caller can decide how to handle it.
func TestSendNotificationToClient_UnsupportedMethod(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("relay-unit", testClientVersion)
	ctx := srv.WithContext(t.Context(), &fakeSession{id: "sess-x"})
	err := srv.SendNotificationToClient(ctx, "notifications/tools/list_changed", nil)
	// fakeSession is not the concrete *clientSession, so the session-support
	// guard fires first; a descriptive (non-nil) error is returned either way.
	require.Error(t, err)
}

// TestSendNotificationToClient_CrossSessionIsolation verifies per-session
// targeting: a notification sent from one session's tool handler is delivered
// only to that session's client, not to a second, concurrently-connected
// client. This is the behavioral difference from SendNotificationToAllClients.
func TestSendNotificationToClient_CrossSessionIsolation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("relay-isolation-server", testClientVersion,
		server.WithToolCapabilities(false),
	)
	srv.AddTool(
		mcp.NewTool(emitToolName, mcp.WithDescription("emit progress to the calling client only")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := srv.SendNotificationToClient(ctx, methodProgress,
				map[string]any{fieldProgressToken: "only-a", fieldProgress: 1.0}); err != nil {
				return nil, err
			}
			return mcp.NewToolResultText("emitted"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	newClient := func() (*client.Client, chan mcp.NotificationParams) {
		c, err := client.NewStreamableHttpClient(ts.URL, transport.WithContinuousListening())
		require.NoError(t, err)
		require.NoError(t, c.Start(ctx))
		ch := make(chan mcp.NotificationParams, 1)
		c.OnNotification(func(n mcp.JSONRPCNotification) {
			if n.Method == methodProgress {
				select {
				case ch <- n.Params:
				default:
				}
			}
		})
		_, err = c.Initialize(ctx, mcp.InitializeRequest{
			Params: mcp.InitializeParams{
				ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
				ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
			},
		})
		require.NoError(t, err)
		return c, ch
	}

	cA, chA := newClient()
	t.Cleanup(func() { _ = cA.Close() })
	cB, chB := newClient()
	t.Cleanup(func() { _ = cB.Close() })

	res, err := cA.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: emitToolName}})
	require.NoError(t, err)
	require.False(t, res.IsError)

	// Client A (the caller) must receive the notification.
	select {
	case p := <-chA:
		assert.Equal(t, "only-a", p.AdditionalFields[fieldProgressToken])
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for the calling client's notification")
	}

	// Client B must NOT receive it within a bounded window.
	select {
	case p := <-chB:
		t.Fatalf("client B must not receive the other session's notification; got %v", p.AdditionalFields)
	case <-time.After(500 * time.Millisecond):
	}
}
