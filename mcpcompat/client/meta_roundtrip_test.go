// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpclient "github.com/stacklok/toolhive-core/mcpcompat/client"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// TestCallToolMetadataRoundTrip verifies that the request _meta survives the
// full client->server round-trip: the client sends a tools/call with a _meta
// field, the server handler observes it, and echoes it back in the result's
// _meta. ToolHive relies on this to propagate metadata through vMCP to backends.
func TestCallToolMetadataRoundTrip(t *testing.T) {
	t.Parallel()

	var seen map[string]any
	mcpSrv := server.NewMCPServer("srv", "1.0.0")
	mcpSrv.AddTool(mcp.NewTool("echo", mcp.WithDescription("echoes meta")),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if req.Params.Meta != nil {
				seen = req.Params.Meta.AdditionalFields
			}
			res := mcp.NewToolResultText("ok")
			// Echo the request meta back on the result.
			res.Meta = &mcp.Meta{AdditionalFields: map[string]any{"echoed": "yes"}}
			return res, nil
		})
	ts := httptest.NewServer(server.NewStreamableHTTPServer(mcpSrv))
	defer ts.Close()

	c, err := mcpclient.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, c.Start(ctx))
	_, err = c.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	res, err := c.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "echo",
			Meta: &mcp.Meta{AdditionalFields: map[string]any{"trace-id": "abc123"}},
		},
	})
	require.NoError(t, err)

	// The server handler must have seen the request _meta.
	require.NotNil(t, seen, "server tool handler must receive the request _meta")
	assert.Equal(t, "abc123", seen["trace-id"], "request _meta must reach the handler")

	// The result _meta must survive the trip back to the client.
	require.NotNil(t, res.Meta, "result _meta must be preserved to the client")
	assert.Equal(t, "yes", res.Meta.AdditionalFields["echoed"])
}
