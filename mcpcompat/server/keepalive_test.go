// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// keepAliveMarker is the SSE comment the shim writes as its passive keep-alive.
// It is asserted on the wire; it must match keepAliveComment in keepalive.go.
const keepAliveMarker = ": keep-alive"

// openGETStream opens the standalone GET SSE stream for a session and returns
// the response. The caller must close the body.
func openGETStream(ctx context.Context, t *testing.T, url, sid string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// awaitKeepAliveComment scans an SSE stream until it reads a keep-alive comment
// line or the deadline (carried by the response body's request context) elapses.
// It returns true if a comment was seen. Running the scan in a goroutine with a
// timeout guard means a silent stream cannot hang the test.
func awaitKeepAliveComment(t *testing.T, resp *http.Response, timeout time.Duration) bool {
	t.Helper()
	found := make(chan bool, 1)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if strings.HasPrefix(sc.Text(), keepAliveMarker) {
				found <- true
				return
			}
		}
		found <- false
	}()
	select {
	case ok := <-found:
		return ok
	case <-time.After(timeout):
		return false
	}
}

// TestKeepAlive_EndToEnd_StreamGetsComments verifies that with
// WithHeartbeatInterval set, an idle standalone GET SSE stream receives
// keep-alive comments, while the initialize POST response body carries none.
func TestKeepAlive_EndToEnd_StreamGetsComments(t *testing.T) {
	t.Parallel()
	stream := server.NewMCPServer("ka", "1.0.0")
	addGreetTool(stream)
	s := server.NewStreamableHTTPServer(stream, server.WithHeartbeatInterval(50*time.Millisecond))
	ts := httptest.NewServer(s)
	defer ts.Close()

	// Establish the session via the shared handshake helper.
	sid := initSession(t, ts.URL)

	// POST purity: a POST (JSON) response body must never carry keep-alive bytes.
	// A unique request id keeps this literal distinct from the other tests'.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	postResp := postRPC(ctx, t, ts.URL, sid, `{"jsonrpc":"2.0","id":8801,"method":"tools/list","params":{}}`)
	postBody, err := io.ReadAll(postResp.Body)
	require.NoError(t, err)
	_ = postResp.Body.Close()
	assert.NotContains(t, string(postBody), keepAliveMarker,
		"a POST (JSON) response must not carry keep-alive bytes")

	// Open the standalone GET stream: it must receive keep-alive comments.
	streamCtx, streamCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer streamCancel()
	getResp := openGETStream(streamCtx, t, ts.URL, sid)
	defer func() { _ = getResp.Body.Close() }()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	require.True(t, strings.HasPrefix(getResp.Header.Get("Content-Type"), "text/event-stream"),
		"GET stream must be an SSE stream")

	assert.True(t, awaitKeepAliveComment(t, getResp, 3*time.Second),
		"idle GET stream must receive a keep-alive comment when a heartbeat is configured")
}

// TestKeepAlive_Disabled_IdleStreamSilent verifies mcp-go parity: with no
// heartbeat configured, an idle GET stream receives no keep-alive comments.
func TestKeepAlive_Disabled_IdleStreamSilent(t *testing.T) {
	t.Parallel()
	stream := server.NewMCPServer("noka", "1.0.0")
	addGreetTool(stream)
	// No WithHeartbeatInterval: keep-alive disabled.
	s := server.NewStreamableHTTPServer(stream)
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts.URL)

	streamCtx, streamCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer streamCancel()
	getResp := openGETStream(streamCtx, t, ts.URL, sid)
	defer func() { _ = getResp.Body.Close() }()
	require.Equal(t, http.StatusOK, getResp.StatusCode)

	// Within a bounded window the idle stream must stay silent (no comment).
	assert.False(t, awaitKeepAliveComment(t, getResp, 400*time.Millisecond),
		"idle GET stream must be silent when no heartbeat is configured")
}

// TestKeepAlive_RehydratedStreamGetsComments verifies the keep-alive covers the
// cross-replica serveRehydrated path: a session initialized on replica A gets a
// GET stream on replica B (rehydrated) that receives keep-alive comments.
func TestKeepAlive_RehydratedStreamGetsComments(t *testing.T) {
	t.Parallel()
	mgr := newSharedSessionManager()

	streamA := server.NewMCPServer("A", "1.0.0")
	addGreetTool(streamA)
	sA := server.NewStreamableHTTPServer(streamA, server.WithSessionIdManager(mgr))
	tsA := httptest.NewServer(sA)
	defer tsA.Close()

	// Replica B carries the heartbeat.
	streamB := server.NewMCPServer("B", "1.0.0")
	addGreetTool(streamB)
	sB := server.NewStreamableHTTPServer(streamB,
		server.WithSessionIdManager(mgr),
		server.WithHeartbeatInterval(50*time.Millisecond))
	tsB := httptest.NewServer(sB)
	defer tsB.Close()

	// Initialize on A, then open the GET stream on B (which must rehydrate).
	sid := initSession(t, tsA.URL)
	// Prime the rehydrated session on B with a request so the stream attaches to
	// a known session.
	require.Contains(t, listToolNames(t, tsB.URL, sid), "greet")

	streamCtx, streamCancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer streamCancel()
	getResp := openGETStream(streamCtx, t, tsB.URL, sid)
	defer func() { _ = getResp.Body.Close() }()
	require.Equal(t, http.StatusOK, getResp.StatusCode)
	require.True(t, strings.HasPrefix(getResp.Header.Get("Content-Type"), "text/event-stream"),
		"rehydrated GET stream must be an SSE stream")

	assert.True(t, awaitKeepAliveComment(t, getResp, 3*time.Second),
		"rehydrated GET stream must receive a keep-alive comment")
}
