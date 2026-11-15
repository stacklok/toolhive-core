// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

// JSON-RPC error preservation and non-2xx status handling over a real client.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// maxCapturedBody mirrors the (unexported) 8 KiB capture limit in errorbody.go.
// The test asserts behavior at this documented boundary.
const maxCapturedBody = 8 << 10

// TestProtocolStatus_JSONRPCErrorPreserved verifies that a JSON-RPC error body
// carried by a non-2xx response reaches the caller intact (go-sdk v1.8 decodes
// it) and that the shim does not reclassify it as an auth or session failure.
func TestProtocolStatus_JSONRPCErrorPreserved(t *testing.T) {
	t.Parallel()

	const (
		code = -32602 // invalid params
		msg  = "bad arguments for echo"
	)
	for _, status := range []int{http.StatusBadRequest, http.StatusForbidden, http.StatusUnprocessableEntity} {
		t.Run(fmt.Sprintf("http_%d", status), func(t *testing.T) {
			t.Parallel()
			arm := armed()
			ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, call rpcCall) {
				arm.Store(false)
				writeRPCError(w, status, call.ID, code, msg, map[string]any{"field": "arguments"})
			}))
			c := newInitializedClient(t, ss.URL)

			ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
			defer cancel()
			_, err := callEcho(ctx, c, "x")
			require.Error(t, err)

			var wire *jsonrpc.Error
			require.True(t, errors.As(err, &wire), "JSON-RPC error must survive the non-2xx status: %v", err)
			assert.Equal(t, int64(code), wire.Code)
			assert.Equal(t, msg, wire.Message)
			assert.JSONEq(t, `{"field":"arguments"}`, string(wire.Data))

			assert.False(t, errors.Is(err, transport.ErrUnauthorized), "must not classify as unauthorized: %v", err)
			assert.False(t, errors.Is(err, transport.ErrSessionTerminated), "must not classify as terminated: %v", err)
			assert.False(t, errors.Is(err, mcp.ErrMethodNotFound), "must not classify as method-not-found: %v", err)

			requireUsable(t, c, "after-"+fmt.Sprint(status))
		})
	}
}

// TestProtocolStatus_TransientStatusBodyStillReachesCaller documents the SDK
// contract for transient statuses: go-sdk v1.8 does not decode JSON-RPC bodies
// for 429/5xx (it reports only the status text), so the shim's error-body
// capture is what keeps the server's detail visible.
func TestProtocolStatus_TransientStatusBodyStillReachesCaller(t *testing.T) {
	t.Parallel()
	arm := armed()
	ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, call rpcCall) {
		arm.Store(false)
		writeRPCError(w, http.StatusServiceUnavailable, call.ID, -32000, "backend overloaded", nil)
	}))
	c := newInitializedClient(t, ss.URL)

	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	_, err := callEcho(ctx, c, "x")
	require.Error(t, err)

	assert.Contains(t, err.Error(), "request failed with status 503")
	assert.Contains(t, err.Error(), "backend overloaded", "captured body must be re-attached")
	assert.False(t, errors.Is(err, transport.ErrUnauthorized))
	assert.False(t, errors.Is(err, transport.ErrSessionTerminated))

	requireUsable(t, c, "after-503")
}

// TestProtocolStatus_Bare404WithJSONRPCBody pins the documented precedence: the
// MCP spec reserves HTTP 404 for a terminated session, so the shim reports
// ErrSessionTerminated for any 404 except one carrying JSON-RPC method-not-found.
// The decoded JSON-RPC error stays reachable through errors.As. go-sdk itself
// keeps the connection open for such a response, so the follow-up call works;
// callers must therefore treat this classification as "re-initialize may be
// needed", not proof the session is gone.
func TestProtocolStatus_Bare404WithJSONRPCBody(t *testing.T) {
	t.Parallel()
	arm := armed()
	ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, call rpcCall) {
		arm.Store(false)
		writeRPCError(w, http.StatusNotFound, call.ID, -32002, "resource gone", nil)
	}))
	c := newInitializedClient(t, ss.URL)

	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	_, err := callEcho(ctx, c, "x")
	require.Error(t, err)
	assert.True(t, errors.Is(err, transport.ErrSessionTerminated), "got %v", err)
	assert.False(t, errors.Is(err, mcp.ErrMethodNotFound), "got %v", err)
	var wire *jsonrpc.Error
	require.True(t, errors.As(err, &wire), "JSON-RPC error must stay reachable: %v", err)
	assert.Equal(t, int64(-32002), wire.Code)
	assert.Equal(t, "resource gone", wire.Message)

	requireUsable(t, c, "after-404-json-rpc")
}

// TestProtocolStatus_ErrorBodyIsBounded verifies an oversized error body neither
// hangs the client nor is re-attached beyond the capture limit.
func TestProtocolStatus_ErrorBodyIsBounded(t *testing.T) {
	t.Parallel()
	arm := armed()
	huge := strings.Repeat("A", 8*maxCapturedBody) + "TAIL-MARKER"
	ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, _ rpcCall) {
		arm.Store(false)
		http.Error(w, huge, http.StatusForbidden)
	}))
	c := newInitializedClient(t, ss.URL)

	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	_, err := callEcho(ctx, c, "x")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "request failed with status 403")
	assert.LessOrEqual(t, len(err.Error()), maxCapturedBody+512, "captured body must respect the 8 KiB cap")
	assert.NotContains(t, err.Error(), "TAIL-MARKER")
	// Recovery is not asserted: go-sdk treats a 4xx without a JSON-RPC body as
	// a fatal connection error.
}
