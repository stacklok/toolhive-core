// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestWithHTTPHeaderFunc_PerRequestHeaders verifies that headers returned by the
// function passed to transport.WithHTTPHeaderFunc are attached to outgoing
// requests and observed by the server.
func TestWithHTTPHeaderFunc_PerRequestHeaders(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := gosdk.NewServer(&gosdk.Implementation{Name: "hdr", Version: "1"}, nil)
	gosdk.AddTool(srv, &gosdk.Tool{Name: echoToolName, Description: echoToolName},
		func(_ context.Context, _ *gosdk.CallToolRequest, _ echoInput) (*gosdk.CallToolResult, any, error) {
			return &gosdk.CallToolResult{Content: []gosdk.Content{&gosdk.TextContent{Text: "ok"}}}, nil, nil
		})
	inner := gosdk.NewStreamableHTTPHandler(func(*http.Request) *gosdk.Server { return srv }, nil)

	var mu sync.Mutex
	seen := map[string]string{}
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Header.Get("X-Caller"); v != "" {
			mu.Lock()
			seen["X-Caller"] = v
			mu.Unlock()
		}
		inner.ServeHTTP(w, r)
	})
	ts := httptest.NewServer(wrapped)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL,
		transport.WithHTTPHeaderFunc(func(context.Context) map[string]string {
			return map[string]string{"X-Caller": "tenant-42"}
		}),
	)
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

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "tenant-42", seen["X-Caller"], "server should observe the per-request header")
}
