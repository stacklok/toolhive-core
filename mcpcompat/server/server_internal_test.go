// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// Compile-time interface checks: the concrete session must satisfy the
// per-session interfaces ToolHive relies on.
var (
	_ ClientSession          = (*clientSession)(nil)
	_ SessionWithTools       = (*clientSession)(nil)
	_ SessionWithResources   = (*clientSession)(nil)
	_ SessionWithElicitation = (*clientSession)(nil)
)

func TestClientSession_Store(t *testing.T) {
	t.Parallel()
	cs := newClientSession("sess-1")

	assert.Equal(t, "sess-1", cs.SessionID())
	assert.False(t, cs.Initialized())
	cs.Initialize()
	assert.True(t, cs.Initialized())
	assert.NotNil(t, cs.NotificationChannel())

	cs.SetSessionTools(map[string]ServerTool{
		"echo": {Tool: mcp.Tool{Name: "echo"}},
	})
	got := cs.GetSessionTools()
	require.Contains(t, got, "echo")

	// GetSessionTools must return a copy (mutating it must not affect the store).
	got["echo2"] = ServerTool{}
	assert.NotContains(t, cs.GetSessionTools(), "echo2")

	cs.SetSessionResources(map[string]ServerResource{
		"file:///r": {Resource: mcp.Resource{URI: "file:///r"}},
	})
	assert.Contains(t, cs.GetSessionResources(), "file:///r")
}

// TestSetSessionTools_NonObjectSchemaDoesNotPanic verifies that a per-session
// overlay tool whose RawInputSchema is a non-object schema ($ref) does NOT crash
// the session when synced onto the go-sdk server. go-sdk v1.6.1 AddTool panics
// unless the input schema's top-level type is "object"; normalizeObjectSchema
// passes non-object schemas through verbatim (to mirror mcp-go), so the panic
// must be recovered by MCPServer.addSessionTool and the offending tool skipped
// while other tools in the same overlay still register. Without the recover in
// syncSessionTools, this test panics mid-call.
func TestSetSessionTools_NonObjectSchemaDoesNotPanic(t *testing.T) {
	t.Parallel()
	s := NewMCPServer("s", "1")
	srv, err := s.buildServer(nil, 0)
	require.NoError(t, err)

	cs := s.sessionFor("sid-bad-schema")
	cs.SetSessionTools(map[string]ServerTool{
		// A non-object schema (a $ref). normalizeObjectSchema returns this
		// verbatim; go-sdk AddTool panics on it. addSessionTool must recover.
		"bad-schema": {
			Tool: mcp.Tool{
				Name:           "bad-schema",
				RawInputSchema: json.RawMessage(`{"$ref":"#"}`),
			},
			Handler: func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil },
		},
		// A well-formed object-schema tool in the same overlay. It must still
		// register despite the sibling's bad schema.
		"good-schema": {
			Tool: mcp.NewTool("good-schema", mcp.WithDescription("ok")),
			Handler: func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("ok"), nil
			},
		},
	})

	// Must not panic (go-sdk AddTool would panic on the $ref schema without
	// the recover in addSessionTool).
	assert.NotPanics(t, func() { s.syncSessionTools(srv, cs) })

	// The offending tool is skipped; the well-formed sibling is registered.
	cs.mu.RLock()
	registered := make(map[string]struct{}, len(cs.sdkToolNames))
	for n := range cs.sdkToolNames {
		registered[n] = struct{}{}
	}
	cs.mu.RUnlock()
	assert.NotContains(t, registered, "bad-schema", "the non-object-schema tool must be skipped, not registered")
	assert.Contains(t, registered, "good-schema", "the well-formed sibling tool must still register")
}

func TestHooks_Fire(t *testing.T) {
	t.Parallel()
	h := &Hooks{}

	var gotSession ClientSession
	h.AddOnRegisterSession(func(_ context.Context, s ClientSession) { gotSession = s })

	var gotCallName string
	h.AddBeforeCallTool(func(_ context.Context, _ any, m *mcp.CallToolRequest) { gotCallName = m.Params.Name })

	var listFired bool
	h.AddBeforeListTools(func(_ context.Context, _ any, _ *mcp.ListToolsRequest) { listFired = true })

	cs := newClientSession("s")
	h.registerSession(context.Background(), cs)
	assert.Equal(t, cs, gotSession)

	req := &mcp.CallToolRequest{}
	req.Params.Name = "greet"
	h.beforeCallTool(context.Background(), "id", req)
	assert.Equal(t, "greet", gotCallName)

	h.beforeListTools(context.Background(), "id", &mcp.ListToolsRequest{})
	assert.True(t, listFired)
}

func TestBuildServer_GlobalAndSessionTools(t *testing.T) {
	t.Parallel()
	s := NewMCPServer("s", "1")
	s.AddTool(mcp.NewTool("global", mcp.WithDescription("g")),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil })

	// Building the global server (with the globally-registered tool) must succeed.
	// Per-session overlays are no longer baked in here; they are synced onto the
	// per-session server by syncSessionTools once the session registers.
	srv, err := s.buildServer(nil, 0)
	require.NoError(t, err)
	require.NotNil(t, srv)

	// A session carrying an additional per-session tool syncs onto the server
	// without error, including a tool that declares no input schema (mcp-go was
	// lenient; the shim normalizes it to the empty object schema).
	cs := s.sessionFor("sid")
	cs.SetSessionTools(map[string]ServerTool{
		"session-only": {
			Tool:    mcp.Tool{Name: "session-only"},
			Handler: func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil },
		},
	})
	assert.NotPanics(t, func() { s.syncSessionTools(srv, cs) })
}

func TestBuildServer_WithSessionIDGenerator(t *testing.T) {
	t.Parallel()
	s := NewMCPServer("s", "1")
	called := false
	gen := func() string { called = true; return "generated-id" }

	srv, err := s.buildServer(gen, 0)
	require.NoError(t, err)
	require.NotNil(t, srv)
	// The generator is installed on the server (invoked by the SDK per new
	// session), not called at build time.
	assert.False(t, called)
}

func TestClientSessionFromContext_Empty(t *testing.T) {
	t.Parallel()
	assert.Nil(t, ClientSessionFromContext(context.Background()))
}

// fakeIDManager verifies the SessionIdManager interface is satisfiable.
type fakeIDManager struct{}

func (fakeIDManager) Generate() string               { return "id" }
func (fakeIDManager) Validate(string) (bool, error)  { return false, nil }
func (fakeIDManager) Terminate(string) (bool, error) { return false, nil }

var _ SessionIdManager = fakeIDManager{}

// TestNormalizeObjectSchema verifies that only nil/empty input schemas are
// normalized to {"type":"object"}; all other schemas pass through verbatim,
// matching mcp-go (which passed RawInputSchema through unchanged). Previously
// any schema whose top-level "type" was not "object" was clobbered, stripping
// valid $ref/oneOf/boolean/object-with-type-omitted schemas.
//
//nolint:goconst // test fixtures legitimately repeat schema keys
func TestNormalizeObjectSchema(t *testing.T) {
	t.Parallel()
	emptyObject := map[string]any{schemaTypeKey: schemaTypeObject}

	tests := []struct {
		name  string
		input any
		want  any
	}{
		{
			name:  "nil",
			input: nil,
			want:  emptyObject,
		},
		{
			name:  "empty map",
			input: map[string]any{},
			want:  emptyObject,
		},
		{
			name:  "type is the empty string (mcp-go wire sentinel)",
			input: map[string]any{schemaTypeKey: ""},
			want:  emptyObject,
		},
		{
			name:  "type empty with properties (mcp-go wire sentinel)",
			input: map[string]any{schemaTypeKey: "", "properties": map[string]any{}},
			want: map[string]any{
				schemaTypeKey: schemaTypeObject,
				"properties":  map[string]any{},
			},
		},
		{
			name:  "empty string",
			input: "",
			want:  emptyObject,
		},
		{
			name: "object schema with type object",
			input: map[string]any{
				schemaTypeKey: schemaTypeObject,
				"properties": map[string]any{
					"name": map[string]any{schemaTypeKey: "string"},
				},
			},
			want: map[string]any{
				schemaTypeKey: schemaTypeObject,
				"properties": map[string]any{
					"name": map[string]any{schemaTypeKey: "string"},
				},
			},
		},
		{
			name: "object schema with type omitted",
			input: map[string]any{
				"properties": map[string]any{
					"name": map[string]any{schemaTypeKey: "string"},
				},
			},
			want: map[string]any{
				"properties": map[string]any{
					"name": map[string]any{schemaTypeKey: "string"},
				},
			},
		},
		{
			name:  "$ref schema",
			input: map[string]any{"$ref": "#"},
			want:  map[string]any{"$ref": "#"},
		},
		{
			name:  "oneOf schema",
			input: map[string]any{"oneOf": []any{map[string]any{schemaTypeKey: "string"}, map[string]any{schemaTypeKey: "number"}}},
			want:  map[string]any{"oneOf": []any{map[string]any{schemaTypeKey: "string"}, map[string]any{schemaTypeKey: "number"}}},
		},
		{
			name:  "boolean true schema",
			input: true,
			want:  true,
		},
		{
			name:  "boolean false schema",
			input: false,
			want:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeObjectSchema(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}
