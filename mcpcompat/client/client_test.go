// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

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
			ClientInfo:      mcp.Implementation{Name: "test-client", Version: "1.0.0"},
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
