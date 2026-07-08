// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http"
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
