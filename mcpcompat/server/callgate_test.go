// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// denialMsg is the stock denial message used across the gate tests.
const denialMsg = "denied"

// addSpyTool registers a "greet" tool whose handler flips called when invoked,
// so a test can assert the handler never runs on the deny path (i.e. dispatch
// was short-circuited, not merely accompanied by a 403).
func addSpyTool(s *server.MCPServer, called *atomic.Bool) {
	s.AddTool(mcp.NewTool("greet", mcp.WithDescription("greets")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			called.Store(true)
			return mcp.NewToolResultText("hello"), nil
		})
}

// addEchoTool registers a tool that echoes its "msg" string argument back in
// the result. It lets a test prove the request body reached the handler intact
// (i.e. the gate did not consume it) by asserting the argument round-trips.
func addEchoTool(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("echo", mcp.WithDescription("echoes msg")),
		func(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(req.GetString("msg", "")), nil
		})
}

// callToolBody builds a tools/call JSON-RPC request for the named tool.
func callToolBody(id, name, argsJSON string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` +
		name + `","arguments":` + argsJSON + `}}`
}

// recordingGate wraps a decision function and records every (method) it was
// consulted for, so a test can assert the gate is (or is not) invoked.
type recordingGate struct {
	mu      sync.Mutex
	methods []string
	decide  func(r *http.Request) *server.Denial
}

func (g *recordingGate) gate() server.CallGate {
	return func(_ context.Context, r *http.Request) *server.Denial {
		g.mu.Lock()
		g.methods = append(g.methods, r.Method)
		g.mu.Unlock()
		return g.decide(r)
	}
}

func (g *recordingGate) seen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.methods...)
}

// denyAll is a gate that denies every request with the given denial.
func denyAll(d *server.Denial) server.CallGate {
	return func(_ context.Context, _ *http.Request) *server.Denial { return d }
}

// doRequest issues an arbitrary HTTP request and returns the response.
func doRequest(ctx context.Context, t *testing.T, method, url, sid, body string) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	} else {
		rdr = strings.NewReader("")
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}

// TestCallGate_DenyPath verifies a denying gate short-circuits dispatch with
// HTTP 403, a JSON content type, and a JSON-RPC error envelope that echoes the
// request id and carries the host-chosen code and message.
func TestCallGate_DenyPath(t *testing.T) {
	t.Parallel()
	var toolCalled atomic.Bool
	srv := server.NewMCPServer("test", "1.0.0")
	addSpyTool(srv, &toolCalled)
	// A distinct application-space code (NOT 403) proves error.code is taken from
	// the Denial, not derived from the HTTP status.
	s := server.NewStreamableHTTPServer(srv,
		server.WithCallGate(denyAll(&server.Denial{Code: 1001, Message: "denied by policy"})))
	ts := httptest.NewServer(s)
	defer ts.Close()

	// No session established: the gate runs before session validation, so the
	// denial does not depend on a live session.
	resp := postRPC(t.Context(), t, ts.URL, "", callToolBody("42", "greet", "{}"))
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"),
		"denial must be written as application/json")

	r := readFirstResult(t, resp)
	require.NotNil(t, r.Error, "denial must carry a JSON-RPC error")
	assert.Equal(t, 1001, r.Error.Code, "error.code must come from the Denial, not the HTTP status")
	assert.Equal(t, "denied by policy", r.Error.Message)
	assert.Equal(t, "42", string(r.ID), "the request id must be echoed")
	assert.False(t, toolCalled.Load(), "tool handler must not run on the deny path")
}

// TestCallGate_AllowPath verifies a nil-returning gate lets the request
// dispatch normally, and that the request body reaches the handler intact (the
// echoed argument round-trips, proving the gate did not consume the body).
func TestCallGate_AllowPath(t *testing.T) {
	t.Parallel()
	rg := &recordingGate{decide: func(_ *http.Request) *server.Denial { return nil }}
	srv := server.NewMCPServer("test", "1.0.0")
	addEchoTool(srv)
	s := server.NewStreamableHTTPServer(srv, server.WithCallGate(rg.gate()))
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts.URL)
	resp := postRPC(t.Context(), t, ts.URL, sid, callToolBody("7", "echo", `{"msg":"ping"}`))
	require.Equal(t, http.StatusOK, resp.StatusCode)

	r := readFirstResult(t, resp)
	require.Nil(t, r.Error, "allowed call must not error")
	assert.Contains(t, string(r.Result), "ping",
		"echoed argument must round-trip, proving the gate left the body intact")
	// The gate was consulted (initialize + notifications/initialized + this
	// call are all POSTs), but only ever for POST methods.
	seen := rg.seen()
	require.NotEmpty(t, seen, "gate must have been consulted at least once")
	for _, m := range seen {
		assert.Equal(t, http.MethodPost, m, "gate must only be consulted for POST")
	}
}

// TestCallGate_NoGate is the additive-behavior regression guard: with no gate
// configured, a tools/call dispatches exactly as before.
func TestCallGate_NoGate(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("test", "1.0.0")
	addEchoTool(srv)
	s := server.NewStreamableHTTPServer(srv) // no WithCallGate
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts.URL)
	resp := postRPC(t.Context(), t, ts.URL, sid, callToolBody("9", "echo", `{"msg":"pong"}`))
	require.Equal(t, http.StatusOK, resp.StatusCode)
	r := readFirstResult(t, resp)
	require.Nil(t, r.Error)
	assert.Contains(t, string(r.Result), "pong")
}

// TestCallGate_DenyBefore404 verifies the 403-before-404 ordering contract: a
// denied POST carrying a session ID that would otherwise 404 still gets the
// denial, both on the local-handler path (no manager) and on the cross-replica
// rehydration path (manager configured, session foreign).
func TestCallGate_DenyBefore404(t *testing.T) {
	t.Parallel()

	t.Run("bogus session, no manager", func(t *testing.T) {
		t.Parallel()
		srv := server.NewMCPServer("test", "1.0.0")
		addGreetTool(srv)
		s := server.NewStreamableHTTPServer(srv,
			server.WithCallGate(denyAll(&server.Denial{Code: 403, Message: denialMsg})))
		ts := httptest.NewServer(s)
		defer ts.Close()

		resp := postRPC(t.Context(), t, ts.URL, "bogus-session-id", callToolBody("1", "greet", "{}"))
		require.Equal(t, http.StatusForbidden, resp.StatusCode, "gate must win over the handler's 404")
		r := readFirstResult(t, resp)
		require.NotNil(t, r.Error)
		assert.Equal(t, 403, r.Error.Code)
	})

	t.Run("foreign session, manager configured (rehydration path)", func(t *testing.T) {
		t.Parallel()
		mgr := newSharedSessionManager()
		srv := server.NewMCPServer("test", "1.0.0")
		addGreetTool(srv)
		s := server.NewStreamableHTTPServer(srv,
			server.WithSessionIdManager(mgr),
			server.WithCallGate(denyAll(&server.Denial{Code: 403, Message: denialMsg})))
		ts := httptest.NewServer(s)
		defer ts.Close()

		// "unknown-foreign" is not local and unknown to the manager, so without
		// the gate serveRehydrated would 404. The gate runs first.
		resp := postRPC(t.Context(), t, ts.URL, "unknown-foreign", callToolBody("2", "greet", "{}"))
		require.Equal(t, http.StatusForbidden, resp.StatusCode,
			"gate must win over the rehydration path's 404")
		r := readFirstResult(t, resp)
		require.NotNil(t, r.Error)
		assert.Equal(t, 403, r.Error.Code)
	})
}

// TestCallGate_UnparsableBodyDeny verifies the id is null when the request body
// cannot be attributed to a single request — malformed JSON, a batch, or a
// well-formed message with no id — while still emitting a 403 + envelope.
func TestCallGate_UnparsableBodyDeny(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"malformed json":      `{not valid json`,
		"batch array":         `[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`,
		"empty body":          ``,
		"notification, no id": `{"jsonrpc":"2.0","method":"notifications/cancelled"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			srv := server.NewMCPServer("test", "1.0.0")
			s := server.NewStreamableHTTPServer(srv,
				server.WithCallGate(denyAll(&server.Denial{Code: 403, Message: denialMsg})))
			ts := httptest.NewServer(s)
			defer ts.Close()

			resp := postRPC(t.Context(), t, ts.URL, "", body)
			require.Equal(t, http.StatusForbidden, resp.StatusCode)
			r := readFirstResult(t, resp)
			require.NotNil(t, r.Error)
			assert.Equal(t, 403, r.Error.Code)
			assert.Equal(t, "null", string(r.ID), "unattributable id must be null")
		})
	}
}

// TestCallGate_NonPOSTBypass verifies GET (SSE) and DELETE (terminate) never
// consult the gate — they are transport lifecycle, not calls.
func TestCallGate_NonPOSTBypass(t *testing.T) {
	t.Parallel()
	rg := &recordingGate{decide: func(_ *http.Request) *server.Denial {
		return &server.Denial{Code: 403, Message: denialMsg}
	}}
	srv := server.NewMCPServer("test", "1.0.0")
	addGreetTool(srv)
	s := server.NewStreamableHTTPServer(srv, server.WithCallGate(rg.gate()))
	ts := httptest.NewServer(s)
	defer ts.Close()

	getResp := doRequest(t.Context(), t, http.MethodGet, ts.URL, "", "")
	_ = getResp.Body.Close()
	assert.NotEqual(t, http.StatusForbidden, getResp.StatusCode,
		"GET must not be denied by the gate")

	delResp := doRequest(t.Context(), t, http.MethodDelete, ts.URL, "some-session", "")
	_ = delResp.Body.Close()
	assert.NotEqual(t, http.StatusForbidden, delResp.StatusCode,
		"DELETE must not be denied by the gate")

	assert.Empty(t, rg.seen(), "gate must never be consulted for non-POST methods")
}

// TestCallGate_HTTPStatus verifies HTTPStatus defaults to 403 when zero and is
// honored when set explicitly.
func TestCallGate_HTTPStatus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		denial     *server.Denial
		wantStatus int
	}{
		{"zero defaults to 403", &server.Denial{Code: 403, Message: denialMsg}, http.StatusForbidden},
		{"explicit status honored", &server.Denial{Code: 403, Message: denialMsg, HTTPStatus: http.StatusTooManyRequests}, http.StatusTooManyRequests},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := server.NewMCPServer("test", "1.0.0")
			s := server.NewStreamableHTTPServer(srv, server.WithCallGate(denyAll(tc.denial)))
			ts := httptest.NewServer(s)
			defer ts.Close()

			resp := postRPC(t.Context(), t, ts.URL, "", callToolBody("1", "greet", "{}"))
			require.Equal(t, tc.wantStatus, resp.StatusCode)
			r := readFirstResult(t, resp)
			require.NotNil(t, r.Error)
			assert.Equal(t, 403, r.Error.Code, "JSON-RPC code is independent of HTTP status")
		})
	}
}
