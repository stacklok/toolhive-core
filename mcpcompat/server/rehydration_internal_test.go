// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// rehydrationSessionManager is a minimal in-memory SessionIdManager shared by
// two replicas, standing in for ToolHive's Redis-backed manager. The external
// test package has a fuller copy (sharedSessionManager).
type rehydrationSessionManager struct {
	mu    sync.Mutex
	valid map[string]bool
}

func (m *rehydrationSessionManager) Generate() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.valid == nil {
		m.valid = map[string]bool{}
	}
	id := uuid.NewString()
	m.valid[id] = true
	return id
}

func (m *rehydrationSessionManager) Validate(sessionID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.valid[sessionID] {
		return false, fmt.Errorf("session %q not found", sessionID)
	}
	return false, nil
}

func (*rehydrationSessionManager) Terminate(string) (bool, error) { return false, nil }

// rehydrationLogBuffer is a goroutine-safe log sink.
type rehydrationLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *rehydrationLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *rehydrationLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// rehydrationPost sends one JSON-RPC message and returns the status code and
// body.
func rehydrationPost(t *testing.T, url, sessionID, body string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
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
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	if sid := resp.Header.Get("Mcp-Session-Id"); sid != "" && sessionID == "" {
		return resp.StatusCode, sid + "\n" + string(data)
	}
	return resp.StatusCode, string(data)
}

// TestAbandonedRequest_RehydratedSession_Refused covers a session that replica
// B rehydrated from a session ID minted by replica A. A tools/call that reaches
// B's session while the request context is already gone must be dispatched and
// refused, not run with the rehydrating request's context.
//
// notifications/cancelled is blocked in B's receiving middleware. go-sdk
// handles notifications synchronously, so this stalls B's session queue; the
// next POST is only queued, and its HTTP request is abandoned before dispatch.
func TestAbandonedRequest_RehydratedSession_Refused(t *testing.T) {
	t.Parallel()
	mgr := &rehydrationSessionManager{}

	// Replica A only mints the session.
	srvA := NewMCPServer("A", "1.0.0")
	tsA := httptest.NewServer(NewStreamableHTTPServer(srvA, WithSessionIdManager(mgr)))
	t.Cleanup(tsA.Close)

	// Registered before anything can block: session close waits for in-flight
	// requests, so a failed assertion would otherwise hang the test.
	releaseCh := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseCh) }) }
	t.Cleanup(release)
	entered := make(chan struct{}, 1)

	var toolCalls, hookCalls atomic.Int32
	logs := &rehydrationLogBuffer{}
	hooks := &Hooks{}
	hooks.AddBeforeCallTool(func(context.Context, any, *mcp.CallToolRequest) { hookCalls.Add(1) })
	logger := slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	srvB := NewMCPServer("B", "1.0.0", WithHooks(hooks), WithLogger(logger))
	srvB.AddTool(mcp.NewTool("greet", mcp.WithDescription("greets")),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			toolCalls.Add(1)
			return mcp.NewToolResultText("hello"), nil
		})
	srvB.testReceivingMiddleware = []gosdk.Middleware{
		func(next gosdk.MethodHandler) gosdk.MethodHandler {
			return func(ctx context.Context, method string, req gosdk.Request) (gosdk.Result, error) {
				if method == "notifications/cancelled" {
					select {
					case entered <- struct{}{}:
					default:
					}
					<-releaseCh
				}
				return next(ctx, method, req)
			}
		},
	}
	httpB := NewStreamableHTTPServer(srvB, WithSessionIdManager(mgr))
	tsB := httptest.NewServer(httpB)
	t.Cleanup(tsB.Close)

	// Initialize on A.
	status, out := rehydrationPost(t, tsA.URL, "",
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`)
	require.Equal(t, http.StatusOK, status)
	sid, _, _ := strings.Cut(out, "\n")
	require.NotEmpty(t, sid)

	// Rehydrate on B with a normal request.
	status, out = rehydrationPost(t, tsB.URL, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	require.Equal(t, http.StatusOK, status)
	require.Contains(t, out, "greet")

	// Stall B's session queue with a notification.
	cancelledDone := make(chan struct{})
	go func() {
		defer close(cancelledDone)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tsB.URL,
			strings.NewReader(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":"does-not-exist"}}`))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		req.Header.Set("Mcp-Session-Id", sid)
		if resp, err := http.DefaultClient.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for notifications/cancelled to reach the middleware")
	}

	// Queue a tools/call whose HTTP request context is already cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/mcp",
		strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"greet","arguments":{}}}`)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("Mcp-Session-Id", sid)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		httpB.ServeHTTP(httptest.NewRecorder(), req)
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		t.Fatal("ServeHTTP did not return for a cancelled request")
	}

	release()
	select {
	case <-cancelledDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for notifications/cancelled to finish")
	}

	// The refusal line proves the call was dispatched and refused, not just
	// never dispatched.
	require.Eventually(t, func() bool {
		return strings.Contains(logs.String(), "refusing dispatch of abandoned request")
	}, 10*time.Second, 10*time.Millisecond,
		"the queued call must be dispatched and refused, not silently dropped")
	assert.Zero(t, toolCalls.Load(), "tool handler must not run for an abandoned request")
	assert.Zero(t, hookCalls.Load(), "before-call hook must not run for an abandoned request")

	// The session still serves normal calls.
	status, out = rehydrationPost(t, tsB.URL, sid,
		`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"greet","arguments":{}}}`)
	require.Equal(t, http.StatusOK, status)
	var env struct {
		Error *json.RawMessage `json:"error"`
	}
	for _, line := range strings.Split(out, "\n") {
		if data, ok := strings.CutPrefix(line, "data:"); ok {
			_ = json.Unmarshal([]byte(strings.TrimSpace(data)), &env)
		}
	}
	assert.Nil(t, env.Error, "a normal call after an abandoned one must succeed: %s", out)
	assert.Contains(t, out, "hello")
	assert.Equal(t, int32(1), toolCalls.Load())
}
