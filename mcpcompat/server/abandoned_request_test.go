// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

const refusalLogLine = "refusing dispatch of abandoned request"

// lockedBuffer is a goroutine-safe bytes.Buffer for capturing slog output.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// abandonedFixture is a local (single-replica) stateful server whose
// OnRegisterSession hook blocks the initialize POST until release is called.
// While initialize is blocked, go-sdk has the session registered and
// initialized but its connection goroutine is stalled, so any further message
// sent to the session is only queued.
type abandonedFixture struct {
	t         *testing.T
	httpSrv   *server.StreamableHTTPServer
	url       string
	logs      *lockedBuffer
	toolCalls atomic.Int32
	hookCalls atomic.Int32

	sessionID string
	initDone  chan struct{}
	release   func()
}

func newAbandonedFixture(t *testing.T) *abandonedFixture {
	t.Helper()
	f := &abandonedFixture{t: t, logs: &lockedBuffer{}, initDone: make(chan struct{})}

	releaseCh := make(chan struct{})
	var once sync.Once
	f.release = func() { once.Do(func() { close(releaseCh) }) }
	// Registered before anything can block: session close waits for in-flight
	// requests, so a failed assertion would otherwise hang the test.
	t.Cleanup(f.release)

	sidCh := make(chan string, 1)
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, s server.ClientSession) {
		sidCh <- s.SessionID()
		<-releaseCh
	})
	hooks.AddBeforeCallTool(func(context.Context, any, *mcp.CallToolRequest) {
		f.hookCalls.Add(1)
	})

	logger := slog.New(slog.NewTextHandler(f.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	srv := server.NewMCPServer("abandoned", "1.0.0",
		server.WithHooks(hooks),
		server.WithLogger(logger),
	)
	srv.AddTool(mcp.NewTool("greet", mcp.WithDescription("greets")),
		func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			f.toolCalls.Add(1)
			return mcp.NewToolResultText("hello"), nil
		})

	f.httpSrv = server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(f.httpSrv)
	t.Cleanup(ts.Close)
	f.url = ts.URL

	// Send initialize from a goroutine; it blocks inside the hook.
	go func() {
		defer close(f.initDone)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, f.url, strings.NewReader(body))
		if err != nil {
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return
		}
		_ = resp.Body.Close()
	}()

	select {
	case f.sessionID = <-sidCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for OnRegisterSession")
	}
	return f
}

// serveCancelled POSTs body to the session through in-process ServeHTTP with an
// already-cancelled request context and returns the recorder. ServeHTTP must
// return even though the session is stalled.
func (f *abandonedFixture) serveCancelled(body string) *httptest.ResponseRecorder {
	f.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set("Mcp-Session-Id", f.sessionID)
	rec := httptest.NewRecorder()

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		f.httpSrv.ServeHTTP(rec, req)
	}()
	select {
	case <-returned:
	case <-time.After(10 * time.Second):
		f.t.Fatal("ServeHTTP did not return for a cancelled request")
	}
	return rec
}

// releaseAndWaitInit unblocks the initialize hook and waits for the initialize
// POST to finish.
func (f *abandonedFixture) releaseAndWaitInit() {
	f.t.Helper()
	f.release()
	select {
	case <-f.initDone:
	case <-time.After(10 * time.Second):
		f.t.Fatal("timed out waiting for initialize to complete")
	}
}

func (f *abandonedFixture) waitForRefusal() {
	f.t.Helper()
	require.Eventually(f.t, func() bool {
		return strings.Contains(f.logs.String(), refusalLogLine)
	}, 10*time.Second, 10*time.Millisecond,
		"the queued call must be dispatched and refused, not silently dropped")
}

// abandon queues a tools/call on the stalled session with a cancelled context,
// releases initialize and waits until the call is dispatched and refused.
func (f *abandonedFixture) abandon() {
	f.t.Helper()
	const call = `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"greet","arguments":{}}}`
	f.serveCancelled(call)
	f.releaseAndWaitInit()
	f.waitForRefusal()
}

func (f *abandonedFixture) post(body string) *http.Response {
	f.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	f.t.Cleanup(cancel)
	return postRPC(ctx, f.t, f.url, f.sessionID, body)
}

func (f *abandonedFixture) callGreet(id int) rpcResult {
	f.t.Helper()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"greet","arguments":{}}}`, id)
	resp := f.post(body)
	require.Equal(f.t, http.StatusOK, resp.StatusCode)
	return readFirstResult(f.t, resp)
}

func TestAbandonedRequest_LocalSession_Refused(t *testing.T) {
	t.Parallel()
	f := newAbandonedFixture(t)

	f.abandon()

	// The refusal line proves the call reached the dispatch middleware and was
	// refused there; the handler and the before-call hook must not have run.
	assert.Zero(t, f.toolCalls.Load(), "tool handler must not run for an abandoned request")
	assert.Zero(t, f.hookCalls.Load(), "before-call hook must not run for an abandoned request")
}

func TestAbandonedRequest_LocalSession_StillUsable(t *testing.T) {
	t.Parallel()
	f := newAbandonedFixture(t)

	f.abandon()

	nresp := f.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	require.Equal(t, http.StatusAccepted, nresp.StatusCode)
	_ = nresp.Body.Close()

	r := f.callGreet(3)
	require.Nil(t, r.Error, "a normal call after an abandoned one must succeed")
	assert.Equal(t, int32(1), f.toolCalls.Load(), "only the live call may run the tool")
}

func TestAbandonedRequest_NotificationsUnaffected(t *testing.T) {
	t.Parallel()
	f := newAbandonedFixture(t)
	f.releaseAndWaitInit()

	nresp := f.post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	require.Equal(t, http.StatusAccepted, nresp.StatusCode)
	_ = nresp.Body.Close()

	// A notification posted with an already-cancelled context is still
	// accepted and never refused.
	rec := f.serveCancelled(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	assert.Equal(t, http.StatusAccepted, rec.Code)

	// The session stays usable; by the time this call returns, the earlier
	// notification has been dispatched (the session handles messages in order).
	r := f.callGreet(2)
	require.Nil(t, r.Error)
	assert.Equal(t, int32(1), f.toolCalls.Load())
	assert.NotContains(t, f.logs.String(), refusalLogLine)
}
