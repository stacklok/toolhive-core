// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// Compile-time interface checks: the concrete session must satisfy the
// per-session interfaces ToolHive relies on.
var (
	_ ClientSession        = (*clientSession)(nil)
	_ SessionWithTools     = (*clientSession)(nil)
	_ SessionWithResources = (*clientSession)(nil)
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
	srv, err := s.buildServer(nil)
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

	srv, err := s.buildServer(gen)
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
