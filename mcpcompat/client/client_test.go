// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

type echoInput struct {
	Message string `json:"message"`
}

// echoToolName is the shared tool name used across the client tests.
const echoToolName = "echo"

// testClientVersion is the shared client/server version string used in tests.
const testClientVersion = "1.0.0"

// testClientName is the shared client name used in InitializeParams across tests.
const testClientName = "test-client"

// newTestServer stands up a real go-sdk MCP server exposing a single "echo"
// tool, served over Streamable HTTP via httptest.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := gosdk.NewServer(&gosdk.Implementation{Name: "testserver", Version: "9.9.9"}, nil)
	gosdk.AddTool(srv, &gosdk.Tool{Name: echoToolName, Description: "echo the message"},
		func(_ context.Context, _ *gosdk.CallToolRequest, in echoInput) (*gosdk.CallToolResult, any, error) {
			return &gosdk.CallToolResult{
				Content: []gosdk.Content{&gosdk.TextContent{Text: "echo: " + in.Message}},
			}, nil, nil
		})
	handler := gosdk.NewStreamableHTTPHandler(func(*http.Request) *gosdk.Server { return srv }, nil)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// TestStreamableClient_EndToEnd drives the full client path against a live
// go-sdk server: Start, Initialize, ListTools, CallTool, Ping, transport
// handle, and Close.
func TestStreamableClient_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newTestServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)

	require.NoError(t, c.Start(ctx))
	assert.False(t, c.IsInitialized())

	initRes, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "testserver", initRes.ServerInfo.Name)
	assert.True(t, c.IsInitialized())

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools.Tools, 1)
	assert.Equal(t, echoToolName, tools.Tools[0].Name)

	callRes, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name:      echoToolName,
			Arguments: map[string]any{"message": "hi"},
		},
	})
	require.NoError(t, err)
	assert.False(t, callRes.IsError)
	require.Len(t, callRes.Content, 1)
	txt, ok := mcp.AsTextContent(callRes.Content[0])
	require.True(t, ok)
	assert.Equal(t, "echo: hi", txt.Text)

	require.NoError(t, c.Ping(ctx))

	// GetTransport must yield a *transport.StreamableHTTP, as ToolHive expects.
	sh, ok := c.GetTransport().(*transport.StreamableHTTP)
	require.True(t, ok)
	assert.Equal(t, c.GetSessionId(), sh.GetSessionId())

	require.NoError(t, c.Close())
}

// TestCallBeforeInitialize verifies methods fail cleanly before Initialize.
func TestCallBeforeInitialize(t *testing.T) {
	t.Parallel()
	c, err := client.NewStreamableHttpClient("http://example.invalid")
	require.NoError(t, err)
	_, err = c.ListTools(context.Background(), mcp.ListToolsRequest{})
	assert.Error(t, err)
}

// TestGetTransport_SSEIsNil verifies an SSE client returns a nil transport
// handle (so a type assertion to *StreamableHTTP fails gracefully rather than
// panicking).
func TestGetTransport_SSEIsNil(t *testing.T) {
	t.Parallel()
	c, err := client.NewSSEMCPClient("http://example.invalid")
	require.NoError(t, err)
	_, ok := c.GetTransport().(*transport.StreamableHTTP)
	assert.False(t, ok)
	assert.Empty(t, c.GetSessionId())
}

// newProgressLoggingServer stands up a real go-sdk MCP server whose "notify"
// tool handler emits both a progress notification and a log message on the
// calling session. The client must register the progress token it wants
// echoed back via the call's _meta; the server reads it off the request _meta.
func newProgressLoggingServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := gosdk.NewServer(
		&gosdk.Implementation{Name: "notify-server", Version: testClientVersion},
		&gosdk.ServerOptions{Capabilities: &gosdk.ServerCapabilities{Logging: &gosdk.LoggingCapabilities{}}},
	)
	srv.AddTool(&gosdk.Tool{
		Name:        "notify",
		Description: "emit progress + log",
		InputSchema: map[string]any{"type": "object"},
	},
		func(ctx context.Context, req *gosdk.CallToolRequest) (*gosdk.CallToolResult, error) {
			// Pull the progress token the client sent in _meta and echo it back
			// on a notifications/progress. If absent, use a fixed token.
			token := any("fallback-token")
			if len(req.Params.Meta) > 0 {
				if v, ok := req.Params.Meta["progressToken"]; ok {
					token = v
				}
			}
			_ = req.Session.NotifyProgress(ctx, &gosdk.ProgressNotificationParams{
				ProgressToken: token,
				Progress:      0.5,
				Total:         1.0,
				Message:       "halfway",
			})
			_ = req.Session.Log(ctx, &gosdk.LoggingMessageParams{
				Level: gosdk.LoggingLevel("info"),
				Data:  "hello from server",
			})
			return &gosdk.CallToolResult{
				Content: []gosdk.Content{&gosdk.TextContent{Text: "notified"}},
			}, nil
		})
	handler := gosdk.NewStreamableHTTPHandler(func(*http.Request) *gosdk.Server { return srv }, nil)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// TestOnNotification_ProgressAndLogging verifies the shim wires the go-sdk
// ProgressNotificationHandler and LoggingMessageHandler so server->client
// notifications/progress and notifications/message reach the registered
// OnNotification callback with their params (progressToken/progress and
// level/data). Without the fix, neither handler is registered and the callback
// never fires.
func TestOnNotification_ProgressAndLogging(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newProgressLoggingServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	type recordedNotif struct {
		method string
		params mcp.NotificationParams
	}
	var (
		mu       sync.Mutex
		got      []recordedNotif
		progChan = make(chan recordedNotif, 1)
		logChan  = make(chan recordedNotif, 1)
	)
	c.OnNotification(func(n mcp.JSONRPCNotification) {
		mu.Lock()
		got = append(got, recordedNotif{method: n.Method, params: n.Params})
		mu.Unlock()
		switch n.Method {
		case "notifications/progress":
			select {
			case progChan <- recordedNotif{method: n.Method, params: n.Params}:
			default:
			}
		case "notifications/message":
			select {
			case logChan <- recordedNotif{method: n.Method, params: n.Params}:
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

	// The server only delivers notifications/message once the client has set a
	// logging level, so raise it before invoking the tool.
	require.NoError(t, c.SetLoggingLevel(ctx, mcp.LoggingLevelInfo))

	const token = "tok-123"
	_, err = c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "notify",
			Meta: mcp.NewMetaFromMap(map[string]any{"progressToken": token}),
		},
	})
	require.NoError(t, err)

	// Both notifications should arrive shortly; they are delivered on the
	// session's connection goroutine.
	select {
	case p := <-progChan:
		assert.Equal(t, "notifications/progress", p.method)
		assert.Equal(t, token, p.params.AdditionalFields["progressToken"])
		assert.InDelta(t, 0.5, p.params.AdditionalFields["progress"], 1e-9)
		assert.InDelta(t, 1.0, p.params.AdditionalFields["total"], 1e-9)
		assert.Equal(t, "halfway", p.params.AdditionalFields["message"])
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notifications/progress")
	}
	select {
	case l := <-logChan:
		assert.Equal(t, "notifications/message", l.method)
		assert.Equal(t, "info", l.params.AdditionalFields["level"])
		assert.Equal(t, "hello from server", l.params.AdditionalFields["data"])
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for notifications/message")
	}

	mu.Lock()
	defer mu.Unlock()
	require.GreaterOrEqual(t, len(got), 2, "at least progress and logging notifications expected")
}

// TestInitialize_StatefulServerNegotiatesLegacyProtocolVersion verifies that
// Initialize() against a stateful (non-stateless) shim server still
// negotiates the shim-owned 2025-11-25 protocol version, and that subsequent
// calls succeed.
//
// go-sdk v1.7 changed (*gosdk.Client).Connect to be "Modern-first": per
// SEP-2575 it always tries the stateless server/discover RPC first, because
// the client's default protocol version is now the SDK's latest
// (2026-07-28). This shim's client does not opt into that (WithStateless is
// out of scope for this PR; see PR2/PR3), so the discover probe against a
// stateful server is rejected and go-sdk correctly falls back to the legacy
// initialize handshake, negotiating down to LATEST_PROTOCOL_VERSION exactly
// as it did on go-sdk v1.6. This test pins that fallback so a future go-sdk
// bump cannot silently break it.
func TestInitialize_StatefulServerNegotiatesLegacyProtocolVersion(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newTestServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	initRes, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)
	// go-sdk v1.7's discover-first Connect must still fall back to the legacy
	// handshake and negotiate the shim-owned 2025-11-25 constant against a
	// stateful server.
	assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, initRes.ProtocolVersion)

	tests := []struct {
		name string
	}{
		{name: "ListTools"},
		{name: "CallTool"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			switch tc.name {
			case "ListTools":
				tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
				require.NoError(t, err)
				require.Len(t, tools.Tools, 1)
				assert.Equal(t, echoToolName, tools.Tools[0].Name)
			case "CallTool":
				callRes, err := c.CallTool(ctx, mcp.CallToolRequest{
					Params: mcp.CallToolParams{
						Name:      echoToolName,
						Arguments: map[string]any{"message": "hi"},
					},
				})
				require.NoError(t, err)
				assert.False(t, callRes.IsError)
				require.Len(t, callRes.Content, 1)
				txt, ok := mcp.AsTextContent(callRes.Content[0])
				require.True(t, ok)
				assert.Equal(t, "echo: hi", txt.Text)
			}
		})
	}
}

// TestSetLevel_CompatAlias verifies that the SetLevel compatibility alias
// (mcp-go's client.Client.SetLevel idiom) delegates to SetLoggingLevel and
// successfully sets the server's logging level. This guards against the
// drop-in contract breaking for downstream code using c.SetLevel(ctx,
// mcp.SetLevelRequest{...}).
func TestSetLevel_CompatAlias(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newProgressLoggingServer(t)

	c, err := client.NewStreamableHttpClient(ts.URL)
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

	// SetLevel must work exactly like SetLoggingLevel — it forwards to it.
	err = c.SetLevel(ctx, mcp.SetLevelRequest{
		Params: mcp.SetLevelParams{Level: mcp.LoggingLevelDebug},
	})
	assert.NoError(t, err, "SetLevel compat alias must succeed")
}

// needsInputToolName is the tool name used by the MRTR (SEP-2322) opt-out
// tests: every call requires further client input and is never fulfilled by
// the test server.
const needsInputToolName = "needs-input"

// elicitModeForm and needsInputMessage are the ElicitParams fields shared by
// the MRTR opt-out test servers below.
const (
	elicitModeForm    = "form"
	needsInputMessage = "need more info"
)

// newMRTRTestServer stands up a real go-sdk MCP server, served stateless (so
// the shim client negotiates MCP 2026-07-28 rather than falling back to the
// legacy handshake; see TestInitialize_StatefulServerNegotiatesLegacyProtocolVersion),
// exposing a single tool whose handler always returns an input-required
// result (InputRequests set, no Content) and increments calls on every
// invocation.
func newMRTRTestServer(t *testing.T, calls *int32) *httptest.Server {
	t.Helper()
	srv := gosdk.NewServer(&gosdk.Implementation{Name: "mrtr-server", Version: testClientVersion}, nil)
	srv.AddTool(&gosdk.Tool{
		Name:        needsInputToolName,
		Description: "always requires further client input",
		InputSchema: map[string]any{"type": "object"},
	},
		func(_ context.Context, _ *gosdk.CallToolRequest) (*gosdk.CallToolResult, error) {
			atomic.AddInt32(calls, 1)
			return &gosdk.CallToolResult{
				InputRequests: gosdk.InputRequestMap{
					"q1": &gosdk.ElicitParams{Mode: elicitModeForm, Message: needsInputMessage},
				},
			}, nil
		})
	handler := gosdk.NewStreamableHTTPHandler(
		func(*http.Request) *gosdk.Server { return srv }, &gosdk.StreamableHTTPOptions{Stateless: true},
	)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// TestWithoutMultiRoundTrip verifies the client.WithoutMultiRoundTrip opt-out:
// with it set, the input-required result from the server is surfaced directly
// to the caller (mcp.CallToolResult.NeedsInput true, err nil, handler invoked
// once); without it (the default), go-sdk's automatic MRTR loop engages and,
// lacking an elicitation handler to fulfill the server's request, CallTool
// returns a non-nil error.
//
// The two subtests intentionally run sequentially (not in t.Parallel()):
// both exercise the same server-side tool and atomic call counter, and the
// opt-out subtest asserts an exact invocation count, which would be racy
// against a concurrently-running sibling subtest.
//
//nolint:tparallel // subtests share server-side state (atomic call counter); see doc comment.
func TestWithoutMultiRoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	var calls int32
	ts := newMRTRTestServer(t, &calls)

	t.Run("opt-out surfaces input-required result", func(t *testing.T) { //nolint:paralleltest // shares call counter; see doc comment.
		c, err := client.NewStreamableHttpClientWithOpts(
			ts.URL, nil, []client.ClientOption{client.WithoutMultiRoundTrip()},
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

		before := atomic.LoadInt32(&calls)
		res, err := c.CallTool(ctx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{Name: needsInputToolName},
		})
		require.NoError(t, err)
		assert.True(t, res.NeedsInput())
		assert.Equal(t, before+1, atomic.LoadInt32(&calls), "handler must be invoked exactly once")
	})

	t.Run("default MRTR errors without a fulfilling handler", func(t *testing.T) { //nolint:paralleltest // shares call counter; see doc comment.
		c, err := client.NewStreamableHttpClient(ts.URL)
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

		_, err = c.CallTool(ctx, mcp.CallToolRequest{
			Params: mcp.CallToolParams{Name: needsInputToolName},
		})
		require.Error(t, err, "the auto MRTR loop must fail without an elicitation handler")
		// Pin the actual go-sdk contract ((*Client).elicit's rejection when no
		// elicitation handler is registered) rather than accepting any error, so
		// an unrelated failure (e.g. a transport EOF) can't satisfy this test.
		var wireErr *jsonrpc.Error
		require.True(t, errors.As(err, &wireErr), "expected a *jsonrpc.Error, got %T: %v", err, err)
		assert.Equal(t, int64(jsonrpc.CodeInvalidParams), wireErr.Code)
		assert.Equal(t, "client does not support elicitation", wireErr.Message)
	})
}

// needsInputPromptName and needsInputResourceURI are the prompt/resource used
// by the prompts/get and resources/read MRTR opt-out tests below.
const (
	needsInputPromptName  = "needs-input-prompt"
	needsInputResourceURI = "test://needs-input-resource"
)

// newMRTRPromptResourceTestServer stands up a real go-sdk MCP server, served
// stateless (see newMRTRTestServer), exposing a prompt and a resource whose
// handlers always return an input-required result (InputRequests set, no
// Messages/Contents).
func newMRTRPromptResourceTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := gosdk.NewServer(&gosdk.Implementation{Name: "mrtr-server", Version: testClientVersion}, nil)
	srv.AddPrompt(&gosdk.Prompt{Name: needsInputPromptName, Description: "always requires further client input"},
		func(context.Context, *gosdk.GetPromptRequest) (*gosdk.GetPromptResult, error) {
			return &gosdk.GetPromptResult{
				InputRequests: gosdk.InputRequestMap{
					"q1": &gosdk.ElicitParams{Mode: elicitModeForm, Message: needsInputMessage},
				},
			}, nil
		})
	srv.AddResource(&gosdk.Resource{URI: needsInputResourceURI, Name: "needs-input-resource"},
		func(context.Context, *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
			return &gosdk.ReadResourceResult{
				InputRequests: gosdk.InputRequestMap{
					"q1": &gosdk.ElicitParams{Mode: elicitModeForm, Message: needsInputMessage},
				},
			}, nil
		})
	handler := gosdk.NewStreamableHTTPHandler(
		func(*http.Request) *gosdk.Server { return srv }, &gosdk.StreamableHTTPOptions{Stateless: true},
	)
	ts := httptest.NewServer(handler)
	t.Cleanup(ts.Close)
	return ts
}

// TestWithoutMultiRoundTrip_PromptAndResource verifies the client.
// WithoutMultiRoundTrip opt-out also surfaces input-required results for
// prompts/get and resources/read (not just tools/call): go-sdk's MRTR
// middleware intercepts all three methods, and the shim's GetPromptResult and
// ReadResourceResult must classify them via NeedsInput just like
// CallToolResult does.
func TestWithoutMultiRoundTrip_PromptAndResource(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	ts := newMRTRPromptResourceTestServer(t)

	c, err := client.NewStreamableHttpClientWithOpts(
		ts.URL, nil, []client.ClientOption{client.WithoutMultiRoundTrip()},
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

	promptRes, err := c.GetPrompt(ctx, mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{Name: needsInputPromptName},
	})
	require.NoError(t, err)
	assert.True(t, promptRes.NeedsInput())

	resourceRes, err := c.ReadResource(ctx, mcp.ReadResourceRequest{
		Params: mcp.ReadResourceParams{URI: needsInputResourceURI},
	})
	require.NoError(t, err)
	assert.True(t, resourceRes.NeedsInput())
}
