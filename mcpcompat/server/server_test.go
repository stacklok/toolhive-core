// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// testClientVersion and testClientName are reused across the e2e tests below.
const (
	testClientName    = "test-client"
	testClientVersion = "1.0.0"
)

// TestGlobalServer_EndToEnd registers a tool on the compat server, serves it
// over Streamable HTTP, and drives it with the compat client — exercising the
// whole server->go-sdk->client path through both shims.
func TestGlobalServer_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var registered server.ClientSession
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, s server.ClientSession) { registered = s })

	srv := server.NewMCPServer("compat-server", "1.2.3",
		server.WithToolCapabilities(false),
		server.WithLogging(),
		server.WithHooks(hooks),
	)

	srv.AddTool(
		mcp.NewTool("greet",
			mcp.WithDescription("greet someone"),
			mcp.WithString("name", mcp.Required()),
		),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := req.GetString("name", "world")
			return mcp.NewToolResultText("hello " + name), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))

	initRes, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "compat-server", initRes.ServerInfo.Name)

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools.Tools, 1)
	assert.Equal(t, "greet", tools.Tools[0].Name)

	callRes, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "greet", Arguments: map[string]any{"name": "ada"}},
	})
	require.NoError(t, err)
	require.False(t, callRes.IsError)
	require.Len(t, callRes.Content, 1)
	txt, ok := mcp.AsTextContent(callRes.Content[0])
	require.True(t, ok)
	assert.Equal(t, "hello ada", txt.Text)

	require.NoError(t, c.Close())

	// The OnRegisterSession hook should have fired for the connected session.
	assert.NotNil(t, registered)
	if registered != nil {
		assert.NotEmpty(t, registered.SessionID())
	}
}

// TestGlobalServer_NilSchemaToolAdvertisesObject verifies that a globally
// registered tool with no declared input schema (mcp-go's leniency) is served
// over Streamable HTTP with its input schema normalized to {"type":"object"},
// which is what go-sdk's AddTool requires. go-sdk would otherwise panic on a
// nil/empty schema; normalizeObjectSchema rewrites it so the tool registers
// and advertises the empty object schema on the wire.
func TestGlobalServer_NilSchemaToolAdvertisesObject(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("schema-server", testClientVersion, server.WithToolCapabilities(false))
	// A tool with neither InputSchema nor RawInputSchema set: mcp-go tolerated
	// this; the shim must normalize it to {"type":"object"}.
	srv.AddTool(mcp.Tool{Name: "no-schema"},
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

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

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools.Tools, 1)
	assert.Equal(t, "no-schema", tools.Tools[0].Name)
	// The advertised input schema must be the normalized empty object schema.
	assert.Equal(t, "object", tools.Tools[0].InputSchema.Type)
	assert.Empty(t, tools.Tools[0].InputSchema.Properties)
}

// TestServeStdio_Builds verifies the stdio entrypoint constructs a server from
// the registered tools without error (it blocks on Run, so we only exercise the
// build path here via a server with a tool registered).
func TestServer_RegistrationSurface(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("s", "1",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
	)

	srv.AddTool(mcp.Tool{Name: "t", Description: "d"},
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil })
	srv.AddResource(mcp.Resource{URI: "file:///r", Name: "r"},
		func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) { return nil, nil })
	srv.AddPrompt(mcp.Prompt{Name: "p"},
		func(context.Context, mcp.GetPromptRequest) (*mcp.GetPromptResult, error) { return nil, nil })

	// ServerTool / ServerResource / ServerPrompt are the registration units
	// ToolHive stores; verify they compose with the handler types.
	_ = server.ServerTool{Tool: mcp.Tool{Name: "x"}, Handler: func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil }}
	_ = server.ServerResource{Resource: mcp.Resource{URI: "u"}, Handler: func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) { return nil, nil }}
	_ = server.ServerPrompt{Prompt: mcp.Prompt{Name: "p"}, Handler: func(context.Context, mcp.GetPromptRequest) (*mcp.GetPromptResult, error) { return nil, nil }}

	srv.DeleteTools("t")
}

// TestAdvertisesToolsCapability_WithNoGlobalTools verifies that calling
// WithToolCapabilities forces the tools capability to be advertised in the
// initialize result even when NO global tools are registered at build time.
// This matters for ToolHive's vMCP projection, which registers tools
// per-session AFTER initialize: go-sdk otherwise infers capabilities only from
// registered features and would advertise no tools capability, so
// spec-compliant clients that gate tools/list on capabilities.tools would see
// no tools. Without the fix (mapping capability flags to ServerOptions), the
// Tools field is absent.
func TestAdvertisesToolsCapability_WithNoGlobalTools(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("cap-server", testClientVersion,
		server.WithToolCapabilities(false),
		server.WithResourceCapabilities(false, false),
		server.WithPromptCapabilities(false),
	)
	// Deliberately register NO tools/resources/prompts globally.

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))

	initRes, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, initRes.Capabilities, "server must advertise capabilities")
	assert.NotNil(t, initRes.Capabilities.Tools, "capabilities.tools must be advertised when WithToolCapabilities is set")
	assert.NotNil(t, initRes.Capabilities.Resources, "capabilities.resources must be advertised when WithResourceCapabilities is set")
	assert.NotNil(t, initRes.Capabilities.Prompts, "capabilities.prompts must be advertised when WithPromptCapabilities is set")

	require.NoError(t, c.Close())
}

// reqIDKey is a per-request context value used by
// TestPerRequestContext_NotClobberedConcurrently. The client sets it via a
// header (read by the server's WithHTTPContextFunc) so the value flows from the
// call's context, through an HTTP header, back into the handler context via
// go-sdk's request-context propagation.
type reqIDKey struct{}

// TestPerRequestContext_NotClobberedConcurrently verifies that per-request
// context values are NOT keyed by session ID: two concurrent tools/call POSTs
// on the SAME session, each carrying a distinct request-scoped value, must each
// see their OWN value in the tool handler. Before the fix, the shim stored a
// single context per session (pendingReqCtx[sessionID]), so concurrent POSTs
// clobbered each other and one handler intermittently saw the other's value.
//
// The per-request value is injected by the server's WithHTTPContextFunc from an
// X-Request-Id header, and the client sets that header per call via its
// per-request HTTPHeaderFunc. go-sdk does NOT propagate the per-POST HTTP
// request's context into handlers for requests on an existing session (it
// handles them on the session's connection goroutine using the initialize-time
// context), so the value reaches the handler via the nonce bridge: ServeHTTP
// stores the request context keyed by a per-POST X-MCP-Req-Nonce header, the
// dispatch middleware reads that header off the per-request RequestExtra and
// bridges the stored context into the handler via valueBridgeContext. Without
// the bridge, handlers see empty/clobbered values (verified by short-circuiting
// the bridge — the test then fails with handlers recording "").
func TestPerRequestContext_NotClobberedConcurrently(t *testing.T) {
	t.Parallel()

	const (
		toolName   = "echo-req"
		headerName = "X-Request-Id"
	)

	var seen struct {
		sync.Mutex
		values []string
	}
	srv := server.NewMCPServer("ctx-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool(toolName, mcp.WithDescription("echo request id")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			v, _ := ctx.Value(reqIDKey{}).(string)
			seen.Lock()
			seen.values = append(seen.values, v)
			seen.Unlock()
			// Block briefly to widen the concurrency window and make a race
			// observable when the value is keyed by session.
			time.Sleep(20 * time.Millisecond)
			return mcp.NewToolResultText(v), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv,
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			if id := r.Header.Get(headerName); id != "" {
				return context.WithValue(ctx, reqIDKey{}, id)
			}
			return ctx
		}),
	)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL,
		transport.WithHTTPHeaderFunc(func(ctx context.Context) map[string]string {
			if v, ok := ctx.Value(reqIDKey{}).(string); ok {
				return map[string]string{headerName: v}
			}
			return nil
		}),
	)
	require.NoError(t, err)
	require.NoError(t, c.Start(context.Background()))
	t.Cleanup(func() { _ = c.Close() })

	_, err = c.Initialize(context.Background(), mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	const iterations = 100
	for i := 0; i < iterations; i++ {
		var wg sync.WaitGroup
		var a, b = "A", "B"
		wg.Add(2)
		go func() {
			defer wg.Done()
			ctx := context.WithValue(context.Background(), reqIDKey{}, a)
			_, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: toolName}})
			assert.NoError(t, err)
		}()
		go func() {
			defer wg.Done()
			ctx := context.WithValue(context.Background(), reqIDKey{}, b)
			_, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: toolName}})
			assert.NoError(t, err)
		}()
		wg.Wait()

		seen.Lock()
		got := append([]string(nil), seen.values...)
		seen.values = seen.values[:0]
		seen.Unlock()

		require.Len(t, got, 2, "iteration %d: both handlers must record a value", i)
		// Each handler must have seen its OWN value; if the per-request context
		// were keyed by session, one value would appear twice and the other zero
		// times.
		assert.ElementsMatch(t, []string{a, b}, got, "iteration %d: handlers saw clobbered values %v", i, got)
	}
}

// TestPageSize_Configurable verifies that WithPageSize threads go-sdk's
// ServerOptions.PageSize so tools/list is paginated at the configured size
// (issue #156, item 6). With PageSize(2) and 3 tools, the first tools/list must
// return at most 2 tools and a nextCursor to fetch the remaining page. go-sdk's
// default (DefaultPageSize=1000) would otherwise return all tools in one page,
// breaking vMCP aggregators with >1000 tools.
func TestPageSize_Configurable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("page-server", testClientVersion,
		server.WithToolCapabilities(false),
		server.WithPageSize(2),
	)
	for i := 0; i < 3; i++ {
		name := fmt.Sprintf("t%d", i)
		srv.AddTool(mcp.NewTool(name, mcp.WithDescription("tool "+name)),
			func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("ok"), nil
			})
	}

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

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

	// First page: at most 2 tools, plus a nextCursor signalling more remain.
	first, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	assert.LessOrEqual(t, len(first.Tools), 2, "first page must respect the configured page size")
	assert.NotEmpty(t, first.NextCursor, "a nextCursor must be returned when more tools remain")

	// Second page: fetch the rest with the cursor; together they cover all 3.
	secondReq := mcp.ListToolsRequest{}
	secondReq.Params.Cursor = first.NextCursor
	second, err := c.ListTools(ctx, secondReq)
	require.NoError(t, err)
	total := len(first.Tools) + len(second.Tools)
	assert.Equal(t, 3, total, "both pages together must return all registered tools")
}

// TestDisableLocalhostProtection_PassedThrough verifies that
// WithDisableLocalhostProtection propagates to go-sdk's
// StreamableHTTPOptions.DisableLocalhostProtection (issue #156, item 5). go-sdk
// by default 403s requests on a loopback listener with a non-localhost Host
// header; with the option set, a request carrying a custom Host header must
// proceed rather than be rejected.
//
// This mirrors TestDisableLocalhostProtection_DefaultRejectsNonLocalhostHost:
// a raw http.Request with req.Host set to a non-localhost value is the only
// way to exercise go-sdk's DNS-rebinding check (the compat client sends a
// localhost Host header, which go-sdk never 403s). With the option disabled
// the same request that the default-rejects test expects to 403 must instead
// succeed (200), proving the option actually toggles the protection.
func TestDisableLocalhostProtection_PassedThrough(t *testing.T) {
	t.Parallel()

	srv := server.NewMCPServer("host-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(mcp.NewTool("ping", mcp.WithDescription("ping")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("pong"), nil
		})

	httpSrv := server.NewStreamableHTTPServer(srv, server.WithDisableLocalhostProtection(true))
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// A non-localhost Host header would trigger go-sdk's DNS-rebinding
	// protection by default; WithDisableLocalhostProtection(true) must let it
	// through.
	req.Host = "evil.example.com"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "with protection disabled a non-localhost Host must be accepted")
}

// TestDisableLocalhostProtection_DefaultRejectsNonLocalhostHost verifies that
// WITHOUT WithDisableLocalhostProtection, go-sdk's default localhost protection
// is in effect: a request on a loopback listener carrying a non-localhost Host
// header is rejected with 403. This confirms the knob actually toggles the
// protection (the default is "protected").
func TestDisableLocalhostProtection_DefaultRejectsNonLocalhostHost(t *testing.T) {
	t.Parallel()

	srv := server.NewMCPServer("prot-server", testClientVersion, server.WithToolCapabilities(false))
	httpSrv := server.NewStreamableHTTPServer(srv) // no disable option
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	// A non-localhost Host header triggers go-sdk's DNS-rebinding protection.
	req.Host = "evil.example.com"

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "default localhost protection must reject a non-localhost Host")
}

// TestHeartbeat_WiredToKeepAlive verifies that WithHeartbeatInterval is wired to
// go-sdk's per-session keep-alive (issue #156, item 2) via an e2e check: a
// server built with a heartbeat disconnects a session whose transport stops
// responding to pings. go-sdk pings the peer at KeepAlive and closes the session
// when a ping goes unanswered, observable as the client's stream/sessions
// closing. Because ServerOptions.KeepAlive is not observable directly, this is
// an e2e test.
//
// We observe the wiring through the resulting server's session lifecycle: a
// raw JSON-RPC initialize against a server configured with a short heartbeat,
// after which the client stops reading, must lead to the session being closed
// within a bounded window. This proves the heartbeat is no longer a no-op.
func TestHeartbeat_WiredToKeepAlive(t *testing.T) {
	t.Parallel()

	srv := server.NewMCPServer("hb-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(mcp.NewTool("ping", mcp.WithDescription("ping")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("pong"), nil
		})

	httpSrv := server.NewStreamableHTTPServer(srv, server.WithHeartbeatInterval(150*time.Millisecond))
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	// Initialize a session via raw JSON-RPC, then stop reading the response
	// stream entirely (abandon the connection). With KeepAlive wired, go-sdk's
	// per-session pinger will fail to get a pong back and must close the session
	// within a bounded window. We assert the session is gone by issuing a
	// follow-up request with the same session id: once the SDK has evicted the
	// dead session, it 404s the id (the go-sdk handler does not recognize it).
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sid := initSession(t, ts.URL)

	// Give the keep-alive pinger time to fire and evict the unresponsive session.
	// The heartbeat is 150ms; allow a generous multiple for the ping timeout +
	// eviction.
	deadline := time.Now().Add(3 * time.Second)
	var got404 bool
	for time.Now().Before(deadline) {
		resp := postRPC(ctx, t, ts.URL, sid, `{"jsonrpc":"2.0","id":7,"method":"tools/list","params":{}}`)
		sc := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if sc == http.StatusNotFound {
			got404 = true
			break
		}
		// A 200 means the session is still alive; back off briefly and retry.
		time.Sleep(100 * time.Millisecond)
	}
	assert.True(t, got404, "session must be evicted by keep-alive within the bounded window once the client stops responding to pings")
}
