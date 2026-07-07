// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpclient "github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// sharedSessionManager is an in-memory SessionIdManager standing in for
// ToolHive's Redis-backed cross-replica store.
type sharedSessionManager struct {
	mu         sync.Mutex
	valid      map[string]bool
	terminated map[string]bool
}

func newSharedSessionManager() *sharedSessionManager {
	return &sharedSessionManager{valid: map[string]bool{}, terminated: map[string]bool{}}
}

func (m *sharedSessionManager) Generate() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	m.valid[id] = true
	return id
}

func (m *sharedSessionManager) Validate(sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.terminated[sessionID] {
		return true, nil
	}
	if !m.valid[sessionID] {
		return false, fmt.Errorf("session %q not found", sessionID)
	}
	return false, nil
}

func (m *sharedSessionManager) Terminate(sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.terminated[sessionID] = true
	return false, nil
}

// TestClientResumeWithoutInitialize verifies STAGE B: a client created with
// transport.WithSession(id) can Start and issue requests WITHOUT calling
// Initialize, resuming a session established by another client. It exercises the
// full round-trip against a shim server whose Streamable HTTP transport
// rehydrates the resumed session.
func TestClientResumeWithoutInitialize(t *testing.T) {
	t.Parallel()

	mgr := newSharedSessionManager()

	newReplica := func(name string) *httptest.Server {
		s := server.NewMCPServer(name, "1.0.0")
		s.AddTool(mcp.NewTool("greet", mcp.WithDescription("greets")),
			func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				return mcp.NewToolResultText("hello"), nil
			})
		ts := httptest.NewServer(server.NewStreamableHTTPServer(s, server.WithSessionIdManager(mgr)))
		return ts
	}

	// Replica A handles initialize; replica B (separate instance sharing the
	// session manager) is where the client resumes — the real cross-replica flow.
	tsA := newReplica("A")
	defer tsA.Close()
	tsB := newReplica("B")
	defer tsB.Close()

	// Client 1: normal initialize on A, capture the session ID and tools.
	client1, err := mcpclient.NewStreamableHttpClient(tsA.URL)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, client1.Start(ctx))
	_, err = client1.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err)
	sid := client1.GetSessionId()
	require.NotEmpty(t, sid)
	tools1, err := client1.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools1.Tools, 1)
	defer func() { _ = client1.Close() }()

	// Client 2: resume with the SAME session ID against replica B, NO Initialize.
	client2, err := mcpclient.NewStreamableHttpClient(tsB.URL, transport.WithSession(sid))
	require.NoError(t, err)
	require.NoError(t, client2.Start(ctx))
	defer func() { _ = client2.Close() }()

	require.Equal(t, sid, client2.GetSessionId(), "resumed client reports the resumed session ID")

	tools2, err := client2.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err, "resumed ListTools must succeed without Initialize")
	names := make([]string, 0, len(tools2.Tools))
	for _, tl := range tools2.Tools {
		names = append(names, tl.Name)
	}
	assert.Equal(t, []string{"greet"}, names, "resumed session returns the same tools")

	// A tool call over the resumed session must also work.
	res, err := client2.CallTool(ctx, mcp.CallToolRequest{
		Params: mcp.CallToolParams{Name: "greet"},
	})
	require.NoError(t, err)
	require.Len(t, res.Content, 1)

	// Terminate the session in the shared store; the resumed client's next request
	// must surface transport.ErrSessionTerminated (the 404 -> sentinel mapping
	// ToolHive relies on to detect cross-replica lazy eviction).
	_, _ = mgr.Terminate(sid)
	_, err = client2.ListTools(ctx, mcp.ListToolsRequest{})
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrSessionTerminated,
		"resumed client must report ErrSessionTerminated after the session is terminated")
}
