// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// callerFromHeader is a WithHTTPContextFunc that copies the X-Caller header
// into the request context under callerKey, the key skills_test.go declares.
// It stands in for ToolHive's identity middleware.
func callerFromHeader(ctx context.Context, r *http.Request) context.Context {
	return context.WithValue(ctx, callerKey{}, r.Header.Get("X-Caller"))
}

// instructionsForCaller is a WithInstructionsFunc that greets the caller the
// context carries, proving the func sees the per-request context.
func instructionsForCaller(ctx context.Context) string {
	caller, _ := ctx.Value(callerKey{}).(string)
	if caller == "" {
		return ""
	}
	return "instructions for " + caller
}

// legacyInitializeBody is a 2025-11-25 initialize request.
const legacyInitializeBody = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":` +
	`{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}`

// modernDiscoverBody is a SEP-2575 (2026-07-28) server/discover request: the
// handshake fields travel in _meta, and go-sdk serves the method only when
// the request declares the Modern revision (header + _meta).
const modernDiscoverBody = `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{` +
	`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
	`"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1.0"},` +
	`"io.modelcontextprotocol/clientCapabilities":{}}}}`

// instructionsHTTPClient is the transport the tests in this file post with.
// httptest.Server.Close closes http.DefaultTransport's idle connections, so a
// parallel test's in-flight request on http.DefaultClient can fail with
// "CloseIdleConnections called". A transport of our own, with keep-alives
// off, keeps these tests out of that race (as reaping_internal_test.go does).
var instructionsHTTPClient = &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}

// postRaw sends one JSON-RPC request with an optional X-Caller header and
// returns the result object, with the raw bytes for absence checks.
func postRaw(t *testing.T, url, method, caller string) (map[string]json.RawMessage, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body, version := legacyInitializeBody, "2025-11-25"
	if method == "server/discover" {
		body, version = modernDiscoverBody, "2026-07-28"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", version)
	if method == "server/discover" {
		// SEP-2575 routing header, required on every Modern request.
		req.Header.Set("Mcp-Method", method)
	}
	if caller != "" {
		req.Header.Set("X-Caller", caller)
	}
	resp, err := instructionsHTTPClient.Do(req)
	require.NoError(t, err)
	r := readFirstResult(t, resp)
	require.Nil(t, r.Error, "%s must not error", method)
	var result map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(r.Result, &result))
	return result, string(r.Result)
}

func instructionsOf(t *testing.T, result map[string]json.RawMessage) string {
	t.Helper()
	raw, ok := result["instructions"]
	if !ok {
		return ""
	}
	var s string
	require.NoError(t, json.Unmarshal(raw, &s))
	return s
}

func TestInstructions_AbsentByDefault(t *testing.T) {
	t.Parallel()
	ts := httptest.NewServer(server.NewStreamableHTTPServer(server.NewMCPServer("plain", "1.0.0")))
	defer ts.Close()

	_, raw := postRaw(t, ts.URL, "initialize", "")
	assert.NotContains(t, raw, `"instructions"`, "no option set: the key must be absent, as before")
}

func TestInstructions_Static(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("static", "1.0.0", server.WithInstructions("Start with hello."))
	ts := httptest.NewServer(server.NewStreamableHTTPServer(srv))
	defer ts.Close()

	result, _ := postRaw(t, ts.URL, "initialize", "")
	assert.Equal(t, "Start with hello.", instructionsOf(t, result))
}

func TestInstructions_FuncSeesRequestContext(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("dynamic", "1.0.0",
		server.WithInstructions("static text, must lose"),
		server.WithInstructionsFunc(instructionsForCaller))
	ts := httptest.NewServer(server.NewStreamableHTTPServer(srv, server.WithHTTPContextFunc(callerFromHeader)))
	defer ts.Close()

	alice, _ := postRaw(t, ts.URL, "initialize", "alice")
	assert.Equal(t, "instructions for alice", instructionsOf(t, alice))

	bob, _ := postRaw(t, ts.URL, "initialize", "bob")
	assert.Equal(t, "instructions for bob", instructionsOf(t, bob), "each initialize is answered for its own caller")

	_, raw := postRaw(t, ts.URL, "initialize", "")
	assert.NotContains(t, raw, `"instructions"`, "an empty func result omits the key")
}

func TestInstructions_FuncOnStatelessServer(t *testing.T) {
	t.Parallel()
	srv := server.NewMCPServer("stateless", "1.0.0", server.WithInstructionsFunc(instructionsForCaller))
	ts := httptest.NewServer(server.NewStreamableHTTPServer(srv,
		server.WithStateless(true), server.WithHTTPContextFunc(callerFromHeader)))
	defer ts.Close()

	result, _ := postRaw(t, ts.URL, "initialize", "carol")
	assert.Equal(t, "instructions for carol", instructionsOf(t, result))
}

func TestInstructions_Discover(t *testing.T) {
	t.Parallel()
	t.Run("static", func(t *testing.T) {
		t.Parallel()
		srv := server.NewMCPServer("discover-static", "1.0.0", server.WithInstructions("Static for discover."))
		ts := httptest.NewServer(server.NewStreamableHTTPServer(srv))
		defer ts.Close()

		result, _ := postRaw(t, ts.URL, "server/discover", "")
		assert.Equal(t, "Static for discover.", instructionsOf(t, result))
	})
	t.Run("func", func(t *testing.T) {
		t.Parallel()
		srv := server.NewMCPServer("discover-func", "1.0.0", server.WithInstructionsFunc(instructionsForCaller))
		ts := httptest.NewServer(server.NewStreamableHTTPServer(srv, server.WithHTTPContextFunc(callerFromHeader)))
		defer ts.Close()

		result, _ := postRaw(t, ts.URL, "server/discover", "dave")
		assert.Equal(t, "instructions for dave", instructionsOf(t, result))
	})
}

func TestInstructions_HandleMessage(t *testing.T) {
	t.Parallel()
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	t.Run("static", func(t *testing.T) {
		t.Parallel()
		srv := server.NewMCPServer("hm-static", "1.0.0", server.WithInstructions("Static via HandleMessage."))
		resp := handleMessageResult(context.Background(), t, srv, initialize)
		assert.Equal(t, "Static via HandleMessage.", resp["instructions"])
	})
	t.Run("func", func(t *testing.T) {
		t.Parallel()
		srv := server.NewMCPServer("hm-func", "1.0.0", server.WithInstructionsFunc(instructionsForCaller))
		ctx := context.WithValue(context.Background(), callerKey{}, "erin")
		resp := handleMessageResult(ctx, t, srv, initialize)
		assert.Equal(t, "instructions for erin", resp["instructions"])
	})
	t.Run("absent", func(t *testing.T) {
		t.Parallel()
		srv := server.NewMCPServer("hm-plain", "1.0.0")
		resp := handleMessageResult(context.Background(), t, srv, initialize)
		_, present := resp["instructions"]
		assert.False(t, present)
	})
}

// handleMessageResult runs one message through the shim's own dispatcher and
// returns the decoded result object.
func handleMessageResult(ctx context.Context, t *testing.T, srv *server.MCPServer, message string) map[string]any {
	t.Helper()
	msg := srv.HandleMessage(ctx, json.RawMessage(message))
	require.NotNil(t, msg)
	data, err := json.Marshal(msg)
	require.NoError(t, err)
	var resp map[string]any
	require.NoError(t, json.Unmarshal(data, &resp))
	result, ok := resp["result"].(map[string]any)
	require.True(t, ok, "response must carry a result: %s", data)
	return result
}
