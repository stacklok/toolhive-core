// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
)

func TestMapTransportError_Unauthorized(t *testing.T) {
	t.Parallel()
	err := mapTransportError(errors.New("request failed: 401 Unauthorized"), nil)

	// ToolHive branches on all of these for its OAuth/401 handling.
	assert.True(t, errors.Is(err, transport.ErrUnauthorized), "errors.Is ErrUnauthorized")
	assert.True(t, errors.Is(err, transport.ErrAuthorizationRequired), "errors.Is ErrAuthorizationRequired")

	var te *transport.Error
	assert.True(t, errors.As(err, &te), "errors.As *transport.Error")

	var are *transport.AuthorizationRequiredError
	assert.True(t, errors.As(err, &are), "errors.As *AuthorizationRequiredError")
}

func TestMapTransportError_SessionTerminated(t *testing.T) {
	t.Parallel()
	err := mapTransportError(errors.New("server returned 404: session not found"), nil)
	assert.True(t, errors.Is(err, transport.ErrSessionTerminated))
}

func TestMapTransportError_LegacySSE(t *testing.T) {
	t.Parallel()
	err := mapTransportError(errors.New("405 method not allowed"), nil)
	assert.True(t, errors.Is(err, transport.ErrLegacySSEServer))
}

func TestMapTransportError_Passthrough(t *testing.T) {
	t.Parallel()
	orig := errors.New("some unrelated failure")
	assert.Equal(t, orig, mapTransportError(orig, nil))
}

func TestMapTransportError_Nil(t *testing.T) {
	t.Parallel()
	assert.NoError(t, mapTransportError(nil, nil))
}

// seedCapture returns a context carrying an errBody holder seeded with the
// given captured HTTP status and body, mirroring what captureErrorBody records
// for a non-2xx response. It is used to simulate a go-sdk transport-level HTTP
// failure without standing up a real server.
func seedCapture(status int, body string) context.Context {
	ctx := withErrCapture(context.Background())
	h := capturedErr(ctx)
	h.status = status
	h.body = body
	return ctx
}

// TestMapCallError_DoesNotMisclassifyJSONRPCErrors is the false-positive fix:
// a JSON-RPC tool error whose message text contains "unauthorized" (e.g. a
// backend returning {"error":"unauthorized to access X"} inside a 2xx response)
// must NOT be reclassified as a transport 401, since that would wrongly trigger
// ToolHive's OAuth refresh flow. There is no captured HTTP status (it's an
// RPC-level error returned in a 2xx body), so the auth/session classification is
// skipped.
func TestMapCallError_DoesNotMisclassifyJSONRPCErrors(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
	}{
		{
			name: "unauthorized in message",
			err:  &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "unauthorized to access resource X"},
		},
		{
			name: "401 in message",
			err:  &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "got 401 from downstream"},
		},
		{
			name: "method not allowed in message but non-method-not-found code",
			err:  &jsonrpc.Error{Code: jsonrpc.CodeInternalError, Message: "method not allowed here"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// No captured body: this is an RPC-level error.
			ctx := withErrCapture(context.Background())
			mapped := mapCallError(ctx, tc.err)
			require.Error(t, mapped)
			assert.False(t, errors.Is(mapped, transport.ErrUnauthorized),
				"RPC-level error must not satisfy ErrUnauthorized: %v", mapped)
			assert.False(t, errors.Is(mapped, transport.ErrAuthorizationRequired),
				"RPC-level error must not satisfy ErrAuthorizationRequired: %v", mapped)
			assert.False(t, errors.Is(mapped, transport.ErrLegacySSEServer),
				"RPC-level error must not satisfy ErrLegacySSEServer: %v", mapped)
			assert.False(t, errors.Is(mapped, transport.ErrSessionTerminated),
				"RPC-level error must not satisfy ErrSessionTerminated: %v", mapped)
		})
	}
}

// TestMapCallError_Transport401 confirms a transport-level 401 (with a captured
// HTTP status) through mapCallError still maps to ErrUnauthorized. Scoping, not
// removal: real transport 401s must keep triggering ToolHive's OAuth flow.
func TestMapCallError_Transport401(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		body   string
		// wantErr is the sentinel the mapped error must satisfy.
		wantErr error
		// notErr is a sentinel it must NOT satisfy (sanity).
		notErr error
	}{
		{
			name:    "captured 401 body",
			status:  http.StatusUnauthorized,
			body:    "Unauthorized",
			wantErr: transport.ErrUnauthorized,
			notErr:  transport.ErrLegacySSEServer,
		},
		{
			// issue #156, finding 4: a 401 with an EMPTY body must still
			// classify as ErrUnauthorized via the status code (not fall back to
			// string matching, which misses bare "401 Unauthorized").
			name:    "empty-body 401",
			status:  http.StatusUnauthorized,
			body:    "",
			wantErr: transport.ErrUnauthorized,
			notErr:  transport.ErrLegacySSEServer,
		},
		{
			name:    "captured 404 session",
			status:  http.StatusNotFound,
			body:    "session not found",
			wantErr: transport.ErrSessionTerminated,
			notErr:  transport.ErrUnauthorized,
		},
		{
			name:    "captured 403 on call is not unauthorized",
			status:  http.StatusForbidden,
			body:    "Unauthorized: denied by policy",
			wantErr: nil, // surfaced unchanged
			notErr:  transport.ErrUnauthorized,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := seedCapture(tc.status, tc.body)
			// A plain (non-RPC) transport error, as go-sdk surfaces for non-2xx.
			src := fmt.Errorf(`calling "tools/call": %s`, http.StatusText(tc.status))
			mapped := mapCallError(ctx, src)
			require.Error(t, mapped)
			if tc.wantErr != nil {
				assert.True(t, errors.Is(mapped, tc.wantErr), "want %v, got %v", tc.wantErr, mapped)
			}
			if tc.notErr != nil {
				assert.False(t, errors.Is(mapped, tc.notErr), "must not satisfy %v, got %v", tc.notErr, mapped)
			}
		})
	}
}

// TestMapConnectError_4xxOnInitialize_LegacySSE restores mcp-go's behavior:
// any 4xx except 401 on the initialize/connect POST is classified as a legacy
// SSE-only server. 401 on connect stays ErrUnauthorized (so OAuth refresh
// triggers) rather than legacy SSE.
func TestMapConnectError_4xxOnInitialize_LegacySSE(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		status  int
		body    string
		wantErr error
		notErr  error
	}{
		{
			name:    "405 method not allowed",
			status:  http.StatusMethodNotAllowed,
			body:    "Method Not Allowed",
			wantErr: transport.ErrLegacySSEServer,
			notErr:  transport.ErrUnauthorized,
		},
		{
			name:    "404 on initialize",
			status:  http.StatusNotFound,
			body:    "Not Found",
			wantErr: transport.ErrLegacySSEServer,
			notErr:  transport.ErrSessionTerminated,
		},
		{
			// issue #156, finding 4: a 404 with an EMPTY body on initialize
			// must still classify as ErrLegacySSEServer via the status code.
			name:    "empty-body 404 on initialize",
			status:  http.StatusNotFound,
			body:    "",
			wantErr: transport.ErrLegacySSEServer,
			notErr:  transport.ErrSessionTerminated,
		},
		{
			name:    "400 bad request",
			status:  http.StatusBadRequest,
			body:    "Bad Request",
			wantErr: transport.ErrLegacySSEServer,
			notErr:  transport.ErrUnauthorized,
		},
		{
			// issue #156, finding 4: a 400 with an EMPTY body on initialize
			// must still classify as ErrLegacySSEServer via the status code.
			name:    "empty-body 400 on initialize",
			status:  http.StatusBadRequest,
			body:    "",
			wantErr: transport.ErrLegacySSEServer,
			notErr:  transport.ErrUnauthorized,
		},
		{
			name:    "403 forbidden on initialize",
			status:  http.StatusForbidden,
			body:    "Forbidden",
			wantErr: transport.ErrLegacySSEServer,
			notErr:  transport.ErrUnauthorized,
		},
		{
			name:    "401 on connect stays unauthorized",
			status:  http.StatusUnauthorized,
			body:    "Unauthorized",
			wantErr: transport.ErrUnauthorized,
			notErr:  transport.ErrLegacySSEServer,
		},
		{
			// issue #156, finding 4: a 401 with an EMPTY body on connect must
			// still classify as ErrUnauthorized via the status code (so OAuth
			// refresh triggers), not fall back to string matching.
			name:    "empty-body 401 on connect",
			status:  http.StatusUnauthorized,
			body:    "",
			wantErr: transport.ErrUnauthorized,
			notErr:  transport.ErrLegacySSEServer,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := seedCapture(tc.status, tc.body)
			src := fmt.Errorf("calling initialize: %s", http.StatusText(tc.status))
			mapped := mapConnectError(ctx, src)
			require.Error(t, mapped)
			assert.True(t, errors.Is(mapped, tc.wantErr), "want %v, got %v", tc.wantErr, mapped)
			assert.False(t, errors.Is(mapped, tc.notErr), "must not satisfy %v, got %v", tc.notErr, mapped)
		})
	}
}

// TestMapConnectError_NoCaptureFallback verifies that when no body was captured
// (e.g. a transport failure before any response), mapConnectError falls back to
// best-effort string matching, preserving the prior behavior for go-sdk errors
// that don't surface a captured status.
func TestMapConnectError_NoCaptureFallback(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background()) // empty holder, no status
	src := errors.New("request failed: 401 Unauthorized")
	mapped := mapConnectError(ctx, src)
	require.Error(t, mapped)
	assert.True(t, errors.Is(mapped, transport.ErrUnauthorized), "fallback should still detect 401: %v", mapped)
}
