// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// testClientVersion and testClientName are reused across the e2e tests below.
const (
	testClientName    = "test-client"
	testClientVersion = "1.0.0"
)

// schema fixture literals shared across the elicitation tests below; factored
// into consts so goconst does not flag them across the test file.
const (
	schemaType = "type"
	objectType = "object"
	stringType = "string"
	nameKey    = "name"
	properties = "properties"

	// elicitMessage and elicitToolName are reused across the elicitation tests;
	// factored into consts so goconst does not flag them.
	elicitMessage  = "What is your name?"
	elicitToolName = "ask"
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

// TestHeartbeat_NoOpDoesNotEvictHealthySession documents the current state of
// WithHeartbeatInterval (issue #156): it stores the interval but does NOT wire
// it to go-sdk's ServerOptions.KeepAlive, because go-sdk's KeepAlive sends an
// active ping request that closes JSON-only client sessions (no standalone SSE
// stream) on the first tick. This test asserts the inverse of the old
// session-killing behavior: an idle, healthy client session configured with a
// short heartbeat (150ms) must still be alive well past the heartbeat interval
// (500ms), proving the interval is not wired to an evicting KeepAlive. If a
// future passive keep-alive is wired here, this test will need updating.
func TestHeartbeat_NoOpDoesNotEvictHealthySession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("hb-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(mcp.NewTool("ping", mcp.WithDescription("ping")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("pong"), nil
		})

	httpSrv := server.NewStreamableHTTPServer(srv, server.WithHeartbeatInterval(150*time.Millisecond))
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

	// Idle past the heartbeat interval (150ms). Wait 500ms — well over 3 ticks —
	// so an evicting KeepAlive would have fired by now.
	time.Sleep(500 * time.Millisecond)

	// The session must still be alive and serve the call.
	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "ping"}})
	require.NoError(t, err, "healthy idle session must survive past the heartbeat interval (no-op KeepAlive)")
	require.False(t, res.IsError)
	txt, ok := mcp.AsTextContent(res.Content[0])
	require.True(t, ok)
	assert.Equal(t, "pong", txt.Text)
}

// TestBeforeCallTool_ReceivesToolNameAndArgs verifies that the before-call hook
// fired by sessionDispatchMiddleware receives a populated mcp.CallToolRequest
// (tool name and arguments) rather than an empty one (issue #156, item U9).
// Before the fix the hook was fired with mcp.CallToolRequest{} (no name, no
// args): vMCP's hooks only use ctx today, but any future hook reading the
// request would break silently. The hook records the request it saw; after a
// tools/call the recorded name must match and the arguments must be present.
func TestBeforeCallTool_ReceivesToolNameAndArgs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var (
		hookMu   sync.Mutex
		hookName string
		hookArgs any
	)
	hooks := &server.Hooks{}
	hooks.AddBeforeCallTool(func(_ context.Context, _ any, req *mcp.CallToolRequest) {
		hookMu.Lock()
		defer hookMu.Unlock()
		hookName = req.Params.Name
		hookArgs = req.Params.Arguments
	})

	srv := server.NewMCPServer("hook-server", testClientVersion,
		server.WithToolCapabilities(false),
		server.WithHooks(hooks),
	)
	srv.AddTool(
		mcp.NewTool("greet", mcp.WithDescription("greet"), mcp.WithString("name", mcp.Required())),
		func(_ context.Context, r mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("hi " + r.GetString("name", "world")), nil
		},
	)

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

	_, err = c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "greet", Arguments: map[string]any{"name": "ada"}},
	})
	require.NoError(t, err)

	hookMu.Lock()
	defer hookMu.Unlock()
	assert.Equal(t, "greet", hookName, "before-call hook must receive the tool name")
	args, _ := hookArgs.(map[string]any)
	require.Contains(t, args, "name", "before-call hook must receive the arguments")
	assert.Equal(t, "ada", args["name"], "before-call hook must receive the argument values")
}

// TestBeforeListTools_ReceivesCursor verifies that the before-list-tools hook
// receives the pagination cursor from the request (issue #156, item U9).
func TestBeforeListTools_ReceivesCursor(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var (
		hookMu     sync.Mutex
		hookCursor string
	)
	hooks := &server.Hooks{}
	hooks.AddBeforeListTools(func(_ context.Context, _ any, req *mcp.ListToolsRequest) {
		hookMu.Lock()
		defer hookMu.Unlock()
		hookCursor = string(req.Params.Cursor)
	})

	srv := server.NewMCPServer("hook-server", testClientVersion,
		server.WithToolCapabilities(false),
		server.WithPageSize(1),
		server.WithHooks(hooks),
	)
	srv.AddTool(mcp.NewTool("t0", mcp.WithDescription("d")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})
	srv.AddTool(mcp.NewTool("t1", mcp.WithDescription("d")),
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

	first, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.NotEmpty(t, first.NextCursor, "need a nextCursor to exercise the cursor path")

	// Second list with the cursor: the before-list hook must see that cursor.
	secondReq := mcp.ListToolsRequest{}
	secondReq.Params.Cursor = first.NextCursor
	_, err = c.ListTools(ctx, secondReq)
	require.NoError(t, err)

	hookMu.Lock()
	defer hookMu.Unlock()
	assert.Equal(t, string(first.NextCursor), hookCursor, "before-list-tools hook must receive the request cursor")
}

// TestElicitation_DefaultConfig verifies the elicitation delivery contract
// (issue #156, item U4): the shim server keeps JSONResponse on, so a
// server->client elicitation made during a tools/call is routed by go-sdk to
// the standalone SSE stream. With transport.WithContinuousListening() the
// client opens that stream and an installed elicitation handler answers, so
// elicitation completes and the tool handler receives the response. Without
// continuous listening the standalone SSE stream is absent and elicitation
// cannot be delivered (documented separately below).
func TestElicitation_DefaultConfig(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("elicit-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool(elicitToolName, mcp.WithDescription("elicit then answer")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			res, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
				Params: mcp.ElicitationParams{
					Message: elicitMessage,
					RequestedSchema: map[string]any{
						schemaType: objectType,
						properties: map[string]any{
							nameKey: map[string]any{schemaType: stringType},
						},
					},
				},
			})
			if err != nil {
				return nil, err
			}
			name, _ := res.Content.(map[string]any)[nameKey].(string)
			return mcp.NewToolResultText("hello " + name), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClientWithOpts(
		ts.URL,
		[]transport.StreamableHTTPCOption{transport.WithContinuousListening()},
		[]client.ClientOption{client.WithElicitationHandler(client.ElicitationHandlerFunc(
			func(_ context.Context, _ mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
				return &mcp.ElicitationResult{
					ElicitationResponse: mcp.ElicitationResponse{
						Action:  mcp.ElicitationResponseActionAccept,
						Content: map[string]any{nameKey: "grace"},
					},
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

	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: elicitToolName}})
	require.NoError(t, err)
	require.False(t, res.IsError, "tool call must succeed; elicitation must complete")
	require.Len(t, res.Content, 1)
	txt, ok := mcp.AsTextContent(res.Content[0])
	require.True(t, ok)
	assert.Equal(t, "hello grace", txt.Text, "the tool handler must have received the elicited response")
}

// TestElicitation_WithoutContinuousListening_Documented documents the
// limitation (issue #156, item U4): with the shim client's default config
// (DisableStandaloneSSE: true, i.e. NO transport.WithContinuousListening), the
// client never opens a standalone SSE stream. Under JSONResponse the go-sdk
// routes a server->client elicitation request to that (absent) stream, so the
// write is rejected and the server's Elicit call fails; the tool call surfaces
// an error rather than completing. This asserts that expected failure so the
// limitation is regression-tested: if a future go-sdk change made elicitation
// work without a standalone stream, this test would start failing and the
// decision docs would need updating.
func TestElicitation_WithoutContinuousListening_Documented(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("elicit-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool(elicitToolName, mcp.WithDescription("elicit then answer")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
				Params: mcp.ElicitationParams{
					Message: elicitMessage,
					RequestedSchema: map[string]any{
						schemaType: objectType,
						properties: map[string]any{
							nameKey: map[string]any{schemaType: stringType},
						},
					},
				},
			})
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText("ok"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	// Default config: no WithContinuousListening, so DisableStandaloneSSE is
	// true and no standalone SSE stream is opened. An elicitation handler is
	// still installed so the capability is declared (otherwise the failure
	// would be "client does not support elicitation" rather than the
	// stream-delivery failure this test documents).
	c, err := client.NewStreamableHttpClientWithOpts(
		ts.URL,
		nil,
		[]client.ClientOption{client.WithElicitationHandler(client.ElicitationHandlerFunc(
			func(_ context.Context, _ mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
				return &mcp.ElicitationResult{
					ElicitationResponse: mcp.ElicitationResponse{
						Action:  mcp.ElicitationResponseActionAccept,
						Content: map[string]any{nameKey: "grace"},
					},
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

	_, err = c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: elicitToolName}})
	require.Error(t, err, "elicitation must fail without a standalone SSE stream (documented limitation)")
	// Distinguish "elicitation was rejected" from "the test timed out": a
	// context.DeadlineExceeded would mean elicitation hung rather than failed,
	// and a future go-sdk change making elicitation silently succeed (no error)
	// is already caught by the require.Error above. This guard catches the
	// inverse regression where the failure masquerades as a timeout.
	require.NotErrorIs(t, err, context.DeadlineExceeded,
		"elicitation must be rejected, not surface as a context timeout")
}

// TestElicitation_HandlerReturnsError verifies the error-return path of
// elicitation: when the client's elicitation handler returns an error, the
// server's RequestElicitation surfaces it and the surrounding tools/call fails
// wrapping that error. go-sdk carries the elicitation handler's error back to
// the server-side Elicit call, so the tool handler returns it and the
// CallTool result carries it.
func TestElicitation_HandlerReturnsError(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	srv := server.NewMCPServer("elicit-err-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool(elicitToolName, mcp.WithDescription("elicit then answer")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			_, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
				Params: mcp.ElicitationParams{
					Message: elicitMessage,
					RequestedSchema: map[string]any{
						schemaType: objectType,
						properties: map[string]any{
							nameKey: map[string]any{schemaType: stringType},
						},
					},
				},
			})
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText("ok"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClientWithOpts(
		ts.URL,
		[]transport.StreamableHTTPCOption{transport.WithContinuousListening()},
		[]client.ClientOption{client.WithElicitationHandler(client.ElicitationHandlerFunc(
			func(_ context.Context, _ mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
				return nil, fmt.Errorf("declined")
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

	_, err = c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: elicitToolName}})
	require.Error(t, err, "tool call must fail when the elicitation handler returns an error")
	assert.Contains(t, err.Error(), "declined", "the CallTool error must wrap the handler's error")
}

// TestCallUnknownTool_ErrorContainsToolName is a regression test for the
// translateUnknownToolError fix: calling a tool that does not exist over the
// Streamable HTTP transport must surface an error naming the missing tool
// (e.g. `tool "nope" not found`), NOT the empty-name `tool "" not found`.
// The fix changed the type assertion in translateUnknownToolError from
// *gosdk.CallToolParams to *gosdk.CallToolParamsRaw so the tool name is
// populated; the HandleMessage path (request_handler_test.go) does not exercise
// translateUnknownToolError, so this drives it end-to-end through the HTTP
// transport and the go-sdk dispatch middleware.
func TestCallUnknownTool_ErrorContainsToolName(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("unk-tool-server", testClientVersion, server.WithToolCapabilities(false))
	srv.AddTool(
		mcp.NewTool("greet", mcp.WithDescription("greet")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("hi"), nil
		},
	)

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

	_, err = c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{Name: "nope"}})
	require.Error(t, err, "calling an unknown tool must error")
	// The translated error must carry the requested tool name, proving the
	// *CallToolParamsRaw assertion populated it (rather than leaving it "").
	assert.Contains(t, err.Error(), `tool "nope" not found`,
		"unknown-tool error must name the requested tool, not the empty name")
	assert.NotContains(t, err.Error(), `tool "" not found`,
		"unknown-tool error must not carry the empty tool name")
}

// TestSessionPrompts_ListAndGet_EndToEnd is the regression anchor for
// per-session prompts (SessionWithPrompts): a prompt injected onto a session via
// the OnRegisterSession hook's SetSessionPrompts must be served by BOTH
// prompts/list AND prompts/get. Before SessionWithPrompts existed, prompts/get
// returned -32602 (InvalidParams) for a session-injected prompt because nothing
// registered it onto the session's go-sdk server. This drives the whole
// server->go-sdk->client path over Streamable HTTP and asserts the prompt is
// listed, gettable (returning the handler's distinctive result), that a global
// prompt is merged alongside it, and that a SECOND session whose hook injects
// nothing does NOT see the per-session prompt (session isolation).
func TestSessionPrompts_ListAndGet_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	const (
		sessionPromptName = "session-prompt"
		globalPromptName  = "global-prompt"
		promptReply       = "session prompt reply"
	)

	// injectPrompts controls whether the register hook installs the per-session
	// prompt; the second client below flips it off to assert isolation.
	var injectPrompts atomic.Bool
	injectPrompts.Store(true)

	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, s server.ClientSession) {
		if !injectPrompts.Load() {
			return
		}
		swp, ok := s.(server.SessionWithPrompts)
		require.True(t, ok, "session must implement SessionWithPrompts")
		swp.SetSessionPrompts(map[string]server.ServerPrompt{
			sessionPromptName: {
				Prompt: mcp.Prompt{Name: sessionPromptName, Description: "per-session prompt"},
				Handler: func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
					return &mcp.GetPromptResult{
						Description: "per-session prompt",
						Messages: []mcp.PromptMessage{
							mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent(promptReply)),
						},
					}, nil
				},
			},
		})
	})

	srv := server.NewMCPServer("prompt-server", testClientVersion,
		server.WithPromptCapabilities(true),
		server.WithHooks(hooks),
	)
	// A cheap global prompt to assert list returns global+session merged.
	srv.AddPrompt(mcp.Prompt{Name: globalPromptName, Description: "global prompt"},
		func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{
				Messages: []mcp.PromptMessage{
					mcp.NewPromptMessage(mcp.RoleUser, mcp.NewTextContent("global reply")),
				},
			}, nil
		})

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

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
	require.NotNil(t, initRes.Capabilities.Prompts, "prompts capability must be advertised")

	// prompts/list must return both the global and the session-injected prompt.
	list, err := c.ListPrompts(ctx, mcp.ListPromptsRequest{})
	require.NoError(t, err)
	names := make([]string, 0, len(list.Prompts))
	for _, p := range list.Prompts {
		names = append(names, p.Name)
	}
	assert.Contains(t, names, sessionPromptName, "prompts/list must include the per-session prompt")
	assert.Contains(t, names, globalPromptName, "prompts/list must include the global prompt")

	// prompts/get on the session-injected prompt must succeed (NOT -32602) and
	// return the handler's distinctive result.
	got, err := c.GetPrompt(ctx, mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{Name: sessionPromptName},
	})
	require.NoError(t, err, "prompts/get on a session-injected prompt must succeed (regression: was -32602)")
	require.Len(t, got.Messages, 1)
	txt, ok := mcp.AsTextContent(got.Messages[0].Content)
	require.True(t, ok)
	assert.Equal(t, promptReply, txt.Text, "prompts/get must return the session prompt handler's result")

	// Session isolation: a SECOND client whose hook injects nothing must not see
	// the per-session prompt.
	injectPrompts.Store(false)
	c2, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c2.Start(ctx))
	t.Cleanup(func() { _ = c2.Close() })

	_, err = c2.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	list2, err := c2.ListPrompts(ctx, mcp.ListPromptsRequest{})
	require.NoError(t, err)
	names2 := make([]string, 0, len(list2.Prompts))
	for _, p := range list2.Prompts {
		names2 = append(names2, p.Name)
	}
	assert.NotContains(t, names2, sessionPromptName,
		"a session without an injected prompt must not see another session's prompt")
	assert.Contains(t, names2, globalPromptName, "the global prompt must still be visible to the second session")

	// prompts/get for the un-injected per-session prompt must fail on the second
	// session (the regression's original -32602 behavior is correct HERE).
	_, err = c2.GetPrompt(ctx, mcp.GetPromptRequest{
		Params: mcp.GetPromptParams{Name: sessionPromptName},
	})
	require.Error(t, err, "prompts/get for a prompt not injected on this session must fail")
}

// TestRequestElicitation_NoActiveSession is a fast unit-level test (no HTTP
// server) exercising the ErrNoActiveSession guard: calling RequestElicitation
// outside any session's request context returns ErrNoActiveSession.
func TestRequestElicitation_NoActiveSession(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("elicit-unit", testClientVersion)
	_, err := srv.RequestElicitation(context.Background(), mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{Message: "hi"},
	})
	require.ErrorIs(t, err, server.ErrNoActiveSession)
}

// TestRequestElicitation_SessionWithoutElicitationSupport is a fast unit-level
// test exercising the ErrElicitationNotSupported guard: a session bound via
// WithContext that does NOT implement SessionWithElicitation causes
// RequestElicitation to return ErrElicitationNotSupported (not a nil-panic or
// a silent success).
func TestRequestElicitation_SessionWithoutElicitationSupport(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("elicit-unit", testClientVersion)
	// fakeSession implements ClientSession but NOT SessionWithElicitation.
	ctx := srv.WithContext(context.Background(), &fakeSession{id: "sess-no-elicit"})
	_, err := srv.RequestElicitation(ctx, mcp.ElicitationRequest{
		Params: mcp.ElicitationParams{Message: "hi"},
	})
	require.ErrorIs(t, err, server.ErrElicitationNotSupported)
}

// TestGlobalTool_NonObjectSchema_DoesNotPoisonServer is a regression test for
// issue #156, finding 2: a global tool whose RawInputSchema is a non-object
// schema (a $ref) makes go-sdk's AddTool panic at build time. Before the fix
// that panic ran inside sync.Once.Do, marking Once done while buildErr stayed
// nil and handler stayed nil — so every subsequent request nil-panicked
// forever, bricking the server. With the recover in addGlobalTool, buildServer
// returns a clean error, buildErr is set, and requests get a 500 (not a
// nil-pointer panic). A subsequent request (e.g. against a SEPARATE server with
// a valid tool) proves the server object itself is usable; this test asserts
// the poisoned server returns a clean 500 on every request rather than panicking.
func TestGlobalTool_NonObjectSchema_DoesNotPoisonServer(t *testing.T) {
	t.Parallel()

	srv := server.NewMCPServer("bad-schema-server", testClientVersion, server.WithToolCapabilities(false))
	// A non-object schema ($ref). normalizeObjectSchema passes it through
	// verbatim; go-sdk AddTool panics on it. addGlobalTool must recover and
	// convert the panic into a build error.
	srv.AddTool(mcp.NewToolWithRawSchema("bad", "bad schema", json.RawMessage(`{"$ref":"#"}`)),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("ok"), nil
		})

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// The first request must get a clean 500 (build error), NOT a nil-pointer
	// panic (which would surface as a connection reset / 502).
	resp := postRPC(ctx, t, ts.URL, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"a bad global tool schema must surface as a clean 500, not a nil panic")
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()

	// A second request with the same poisoned server must ALSO get a clean 500
	// (sync.Once is properly poisoned with buildErr, not nil-handler-nil-error).
	resp2 := postRPC(ctx, t, ts.URL, "", `{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
	assert.Equal(t, http.StatusInternalServerError, resp2.StatusCode,
		"sync.Once must remain poisoned with the build error, not nil-panic on retry")
	_, _ = io.Copy(io.Discard, resp2.Body)
	_ = resp2.Body.Close()
}

// TestGlobalTool_TypeOmittedObjectSchema_Callable verifies the
// normalizeObjectSchema improvement (issue #156, finding 2): a spec-loose
// object schema with NO "type" key but WITH "properties" (a shape mcp-go
// served verbatim and callable) is normalized to include type:"object" so the
// tool registers under go-sdk and is callable end-to-end. Without the
// normalization, go-sdk's AddTool would panic (top-level type not "object")
// and the tool would fail to register.
func TestGlobalTool_TypeOmittedObjectSchema_Callable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("loose-schema-server", testClientVersion, server.WithToolCapabilities(false))
	// Object schema with type OMITTED but properties present. mcp-go served
	// this verbatim and the tool was callable; normalizeObjectSchema now adds
	// type:"object" so go-sdk's AddTool accepts it.
	srv.AddTool(mcp.NewToolWithRawSchema("loose", "loose object schema",
		json.RawMessage(`{"properties":{"name":{"type":"string"}},"required":["name"]}`)),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			name := req.GetString("name", "world")
			return mcp.NewToolResultText("hi " + name), nil
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
	require.NoError(t, err, "server with a type-omitted object schema tool must build and initialize")

	// The tool must be advertised and callable.
	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools.Tools, 1)
	assert.Equal(t, "loose", tools.Tools[0].Name)

	res, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "loose", Arguments: map[string]any{nameKey: "loose-user"}},
	})
	require.NoError(t, err, "type-omitted object schema tool must be callable")
	require.False(t, res.IsError)
	txt, ok := mcp.AsTextContent(res.Content[0])
	require.True(t, ok)
	assert.Equal(t, "hi loose-user", txt.Text)
}
