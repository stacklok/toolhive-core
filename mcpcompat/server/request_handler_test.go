// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// newHandlerTestServer builds an MCPServer with one tool, resource, resource
// template and prompt registered, for driving HandleMessage directly.
func newHandlerTestServer() *server.MCPServer {
	srv := server.NewMCPServer("handler-server", "4.5.6",
		server.WithToolCapabilities(true),
		server.WithResourceCapabilities(true, true),
		server.WithPromptCapabilities(true),
		server.WithLogging(),
	)
	srv.AddTool(
		mcp.NewTool("greet", mcp.WithDescription("greet"), mcp.WithString("name", mcp.Required())),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("hello " + req.GetString("name", "world")), nil
		},
	)
	srv.AddResource(
		mcp.Resource{URI: "file://readme", Name: "readme"},
		func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{mcp.TextResourceContents{URI: "file://readme", Text: "body"}}, nil
		},
	)
	srv.AddResourceTemplate(
		mcp.ResourceTemplate{Name: "tmpl"},
		func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return nil, nil
		},
	)
	srv.AddPrompt(
		mcp.Prompt{Name: "p1"},
		func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) {
			return &mcp.GetPromptResult{Description: "desc"}, nil
		},
	)
	return srv
}

// marshalResult marshals a HandleMessage response and unmarshals into a generic
// map for structural assertions.
func marshalResult(t *testing.T, msg mcp.JSONRPCMessage) map[string]any {
	t.Helper()
	require.NotNil(t, msg)
	b, err := json.Marshal(msg)
	require.NoError(t, err)
	var m map[string]any
	require.NoError(t, json.Unmarshal(b, &m))
	return m
}

func TestHandleMessage(t *testing.T) {
	t.Parallel()
	srv := newHandlerTestServer()
	ctx := context.Background()

	tests := []struct {
		name       string
		message    string
		wantNil    bool
		wantErr    bool
		assertResp func(t *testing.T, resp map[string]any)
	}{
		{
			name:    "initialize",
			message: `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				result, ok := resp["result"].(map[string]any)
				require.True(t, ok, "result present")
				assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, result["protocolVersion"])
				info := result["serverInfo"].(map[string]any)
				assert.Equal(t, "handler-server", info["name"])
				assert.Contains(t, result, "capabilities")
			},
		},
		{
			name:    "ping",
			message: `{"jsonrpc":"2.0","id":2,"method":"ping"}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				assert.Contains(t, resp, "result")
			},
		},
		{
			name:    "tools/list",
			message: `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				tools := resp["result"].(map[string]any)["tools"].([]any)
				require.Len(t, tools, 1)
				assert.Equal(t, "greet", tools[0].(map[string]any)["name"])
			},
		},
		{
			name:    "tools/call",
			message: `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"greet","arguments":{"name":"bob"}}}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				content := resp["result"].(map[string]any)["content"].([]any)
				require.Len(t, content, 1)
				assert.Equal(t, "hello bob", content[0].(map[string]any)["text"])
			},
		},
		{
			name:    "tools/call unknown tool",
			message: `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}`,
			wantErr: true,
		},
		{
			name:    "resources/list",
			message: `{"jsonrpc":"2.0","id":6,"method":"resources/list"}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				res := resp["result"].(map[string]any)["resources"].([]any)
				require.Len(t, res, 1)
				assert.Equal(t, "file://readme", res[0].(map[string]any)["uri"])
			},
		},
		{
			name:    "resources/templates/list",
			message: `{"jsonrpc":"2.0","id":7,"method":"resources/templates/list"}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				tmpls := resp["result"].(map[string]any)["resourceTemplates"].([]any)
				require.Len(t, tmpls, 1)
			},
		},
		{
			name:    "resources/read",
			message: `{"jsonrpc":"2.0","id":8,"method":"resources/read","params":{"uri":"file://readme"}}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				contents := resp["result"].(map[string]any)["contents"].([]any)
				require.Len(t, contents, 1)
				assert.Equal(t, "body", contents[0].(map[string]any)["text"])
			},
		},
		{
			name:    "resources/read unknown",
			message: `{"jsonrpc":"2.0","id":9,"method":"resources/read","params":{"uri":"file://missing"}}`,
			wantErr: true,
		},
		{
			name:    "prompts/list",
			message: `{"jsonrpc":"2.0","id":10,"method":"prompts/list"}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				prompts := resp["result"].(map[string]any)["prompts"].([]any)
				require.Len(t, prompts, 1)
			},
		},
		{
			name:    "prompts/get",
			message: `{"jsonrpc":"2.0","id":11,"method":"prompts/get","params":{"name":"p1"}}`,
			assertResp: func(t *testing.T, resp map[string]any) {
				t.Helper()
				assert.Equal(t, "desc", resp["result"].(map[string]any)["description"])
			},
		},
		{
			name:    "unknown method",
			message: `{"jsonrpc":"2.0","id":12,"method":"does/not/exist"}`,
			wantErr: true,
		},
		{
			name:    "bad jsonrpc version",
			message: `{"jsonrpc":"1.0","id":13,"method":"ping"}`,
			wantErr: true,
		},
		{
			name:    "parse error",
			message: `{not json`,
			wantErr: true,
		},
		{
			name:    "notification returns nil",
			message: `{"jsonrpc":"2.0","method":"notifications/initialized"}`,
			wantNil: true,
		},
		{
			name:    "server response returns nil",
			message: `{"jsonrpc":"2.0","id":14,"result":{}}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := srv.HandleMessage(ctx, json.RawMessage(tt.message))
			if tt.wantNil {
				assert.Nil(t, resp)
				return
			}
			m := marshalResult(t, resp)
			if tt.wantErr {
				assert.Contains(t, m, "error")
				return
			}
			assert.NotContains(t, m, "error")
			if tt.assertResp != nil {
				tt.assertResp(t, m)
			}
		})
	}
}

func TestWithContext(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("ctx-server", "1.0.0")

	// A ClientSession stored via WithContext must be recoverable via
	// ClientSessionFromContext.
	sess := &fakeSession{id: "sess-123"}
	ctx := srv.WithContext(context.Background(), sess)

	got := server.ClientSessionFromContext(ctx)
	require.NotNil(t, got)
	assert.Equal(t, "sess-123", got.SessionID())

	// A context with no session yields nil.
	assert.Nil(t, server.ClientSessionFromContext(context.Background()))
}

// fakeSession is a minimal ClientSession for WithContext round-tripping.
type fakeSession struct {
	id string
}

func (f *fakeSession) SessionID() string                                 { return f.id }
func (*fakeSession) Initialize()                                         {}
func (*fakeSession) Initialized() bool                                   { return true }
func (*fakeSession) NotificationChannel() chan<- mcp.JSONRPCNotification { return nil }
