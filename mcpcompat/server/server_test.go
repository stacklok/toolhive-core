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
			ClientInfo:      mcp.Implementation{Name: "test-client", Version: "1.0.0"},
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
