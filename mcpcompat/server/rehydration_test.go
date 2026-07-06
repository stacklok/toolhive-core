// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// sharedSessionManager is a test double for ToolHive's Redis-backed
// SessionIdManager: an in-memory store that multiple StreamableHTTPServer
// instances share, standing in for cross-replica shared state.
type sharedSessionManager struct {
	mu         sync.Mutex
	valid      map[string]bool // sessionID -> terminated?
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

// greetTool registers a simple "greet" tool on the server.
func addGreetTool(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("greet", mcp.WithDescription("greets")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("hello"), nil
		})
}

// rpcResult holds the parsed JSON-RPC envelope for the response to a request.
type rpcResult struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// postRPC sends a single JSON-RPC message to url and returns the HTTP response
// so the caller can inspect status codes or stream SSE.
func postRPC(ctx context.Context, t *testing.T, url, sessionID string, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if sessionID != "" {
		req.Header.Set("Mcp-Session-Id", sessionID)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// readFirstResult reads the first JSON-RPC result/error message from an HTTP
// response, transparently handling both application/json and text/event-stream
// bodies.
func readFirstResult(t *testing.T, resp *http.Response) rpcResult {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "application/json") {
		var r rpcResult
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&r))
		return r
	}
	// SSE: scan "data:" lines for the first message carrying a result or error.
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		var r rpcResult
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &r); err != nil {
			continue
		}
		if len(r.Result) > 0 || r.Error != nil {
			return r
		}
	}
	t.Fatalf("no JSON-RPC result found in SSE stream")
	return rpcResult{}
}

// initSession initializes a session against url using raw JSON-RPC and returns
// the assigned session ID.
func initSession(t *testing.T, url string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`
	resp := postRPC(ctx, t, url, "", body)
	sid := resp.Header.Get("Mcp-Session-Id")
	_ = readFirstResult(t, resp)
	require.NotEmpty(t, sid, "initialize must assign a session ID")
	// Send notifications/initialized to complete the handshake.
	notif := `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	nresp := postRPC(ctx, t, url, sid, notif)
	_ = nresp.Body.Close()
	return sid
}

// listToolNames issues tools/list against url (optionally with a session ID) and
// returns the tool names.
func listToolNames(t *testing.T, url, sessionID string) []string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`
	resp := postRPC(ctx, t, url, sessionID, body)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	r := readFirstResult(t, resp)
	require.Nil(t, r.Error, "tools/list should not error")
	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(r.Result, &res))
	names := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

// TestCrossReplicaSessionRouting verifies that a session initialized on replica
// A is accepted on replica B (which shares the SessionIdManager) and returns the
// same tools — the core production fix for Redis-shared cross-replica sessions.
func TestCrossReplicaSessionRouting(t *testing.T) {
	t.Parallel()
	mgr := newSharedSessionManager()

	// Replica A: registers greet globally.
	streamA := server.NewMCPServer("A", "1.0.0")
	addGreetTool(streamA)
	sA := server.NewStreamableHTTPServer(streamA, server.WithSessionIdManager(mgr))
	tsA := httptest.NewServer(sA)
	defer tsA.Close()

	// Replica B: same global tools (separate process in production).
	streamB := server.NewMCPServer("B", "1.0.0")
	addGreetTool(streamB)
	sB := server.NewStreamableHTTPServer(streamB, server.WithSessionIdManager(mgr))
	tsB := httptest.NewServer(sB)
	defer tsB.Close()

	// Initialize on A.
	sid := initSession(t, tsA.URL)
	toolsA := listToolNames(t, tsA.URL, sid)
	require.Contains(t, toolsA, "greet")

	// Same session ID, replica B — must be accepted via rehydration.
	toolsB := listToolNames(t, tsB.URL, sid)
	assert.ElementsMatch(t, toolsA, toolsB, "replica B must return the same tools for the shared session")
}

// TestCrossReplicaLazyToolInjection mirrors ToolHive's real cross-replica
// mechanism: replica B has NO globally-registered tools; instead a before-list
// hook lazily injects per-session tools when the session has none (the
// rehydrated case, matching Server.lazyInjectSessionTools). It proves the
// before-hooks fire on a rehydrated session with a usable ClientSession in
// context and that the injected overlay is served by tools/list.
func TestCrossReplicaLazyToolInjection(t *testing.T) {
	t.Parallel()
	mgr := newSharedSessionManager()

	// Replica A initializes the session.
	streamA := server.NewMCPServer("A", "1.0.0")
	sA := server.NewStreamableHTTPServer(streamA, server.WithSessionIdManager(mgr))
	tsA := httptest.NewServer(sA)
	defer tsA.Close()

	// Replica B: no global tools; a before-list hook injects per-session tools.
	hooks := &server.Hooks{}
	var injected bool
	hooks.AddBeforeListTools(func(ctx context.Context, _ any, _ *mcp.ListToolsRequest) {
		sess := server.ClientSessionFromContext(ctx)
		require.NotNil(t, sess, "before-list hook must see a ClientSession for the rehydrated session")
		swt, ok := sess.(server.SessionWithTools)
		require.True(t, ok, "session must support per-session tools")
		if len(swt.GetSessionTools()) > 0 {
			return
		}
		injected = true
		swt.SetSessionTools(map[string]server.ServerTool{
			"lazy": {
				Tool: mcp.NewTool("lazy", mcp.WithDescription("lazily injected")),
				Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("ok"), nil
				},
			},
		})
	})
	streamB := server.NewMCPServer("B", "1.0.0", server.WithHooks(hooks))
	sB := server.NewStreamableHTTPServer(streamB, server.WithSessionIdManager(mgr))
	tsB := httptest.NewServer(sB)
	defer tsB.Close()

	sid := initSession(t, tsA.URL)

	toolsB := listToolNames(t, tsB.URL, sid)
	assert.True(t, injected, "before-list hook should have injected tools on the rehydrated replica")
	assert.Contains(t, toolsB, "lazy", "rehydrated session must serve the lazily-injected per-session tool")
}

// TestRehydrationRejectsUnknownAndTerminated verifies the 404 paths.
func TestRehydrationRejectsUnknownAndTerminated(t *testing.T) {
	t.Parallel()
	mgr := newSharedSessionManager()
	mcpSrv := server.NewMCPServer("B", "1.0.0")
	addGreetTool(mcpSrv)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithSessionIdManager(mgr))
	ts := httptest.NewServer(s)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`

	// Unknown session ID -> 404.
	resp := postRPC(ctx, t, ts.URL, "does-not-exist", body)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	_ = resp.Body.Close()

	// Terminated session ID -> 404.
	sid := mgr.Generate()
	_, _ = mgr.Terminate(sid)
	resp2 := postRPC(ctx, t, ts.URL, sid, body)
	assert.Equal(t, http.StatusNotFound, resp2.StatusCode)
	_ = resp2.Body.Close()
}

// TestRehydratedSessionElicitation proves a rehydrated session is a full,
// stateful session (NOT stateless): a tool handler on the rehydrating replica
// performs a server->client elicitation, and the client responds over the same
// session, completing the tool call.
func TestRehydratedSessionElicitation(t *testing.T) {
	t.Parallel()
	mgr := newSharedSessionManager()

	// Replica A only initializes the session (client uses elicitation cap).
	streamA := server.NewMCPServer("A", "1.0.0")
	sA := server.NewStreamableHTTPServer(streamA, server.WithSessionIdManager(mgr))
	tsA := httptest.NewServer(sA)
	defer tsA.Close()

	// Replica B has a tool that elicits input from the client.
	streamB := server.NewMCPServer("B", "1.0.0")
	var srvB = streamB
	streamB.AddTool(mcp.NewTool("ask", mcp.WithDescription("asks the user")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			res, err := srvB.RequestElicitation(ctx, mcp.ElicitationRequest{
				Params: mcp.ElicitationParams{
					Message:         "your name?",
					RequestedSchema: map[string]any{"type": "object"},
				},
			})
			if err != nil {
				return nil, err
			}
			return mcp.NewToolResultText("action=" + string(res.Action)), nil
		})
	sB := server.NewStreamableHTTPServer(streamB, server.WithSessionIdManager(mgr))
	tsB := httptest.NewServer(sB)
	defer tsB.Close()

	// Initialize on A (declares elicitation capability at the wire level via the
	// rehydrated seed on B; the session id is shared).
	sid := initSession(t, tsA.URL)

	// Fire tools/call ask on B. This POST's SSE stream will carry a server->client
	// elicitation request; we respond on a second POST with the same session id.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	callBody := `{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"ask","arguments":{}}}`
	resp := postRPC(ctx, t, tsB.URL, sid, callBody)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Read the SSE stream: when we see the elicitation request, answer it; then
	// expect the tool result.
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	var gotToolResult bool
	for sc.Scan() {
		line := sc.Text()
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		var msg rpcResult
		if err := json.Unmarshal([]byte(strings.TrimSpace(data)), &msg); err != nil {
			continue
		}
		if msg.Method == "elicitation/create" {
			// Respond to the server->client request on a separate POST.
			respBody := fmt.Sprintf(
				`{"jsonrpc":"2.0","id":%s,"result":{"action":"accept","content":{}}}`,
				string(msg.ID))
			ackCtx, ackCancel := context.WithTimeout(context.Background(), 10*time.Second)
			ack := postRPC(ackCtx, t, tsB.URL, sid, respBody)
			_ = ack.Body.Close()
			ackCancel()
			continue
		}
		if bytes.Equal(msg.ID, []byte("42")) && len(msg.Result) > 0 {
			var res struct {
				Content []struct {
					Text string `json:"text"`
				} `json:"content"`
			}
			require.NoError(t, json.Unmarshal(msg.Result, &res))
			require.NotEmpty(t, res.Content)
			assert.Equal(t, "action=accept", res.Content[0].Text)
			gotToolResult = true
			break
		}
	}
	assert.True(t, gotToolResult, "expected the elicited tool call to complete on the rehydrated session")
}
