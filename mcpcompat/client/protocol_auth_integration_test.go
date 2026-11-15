// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

// Authentication challenges (401, WWW-Authenticate, RFC 9728) over a real client.

import (
	"context"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
)

// TestProtocolStatus_AuthChallengeOnInitialize covers the connect path: the
// initialize POST is rejected with 401, and the go-sdk then sends a cleanup
// DELETE before Connect returns.
func TestProtocolStatus_AuthChallengeOnInitialize(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		headers    []string // WWW-Authenticate values, one header line each
		body       string
		wantURL    string
		wantSubstr string
	}{
		{name: "bearer with resource_metadata, empty body", headers: []string{bearerChallenge}, wantURL: resourceMetadataURL},
		{name: "bearer with resource_metadata, text body", headers: []string{bearerChallenge}, body: "token required",
			wantURL: resourceMetadataURL, wantSubstr: "token required"},
		{name: "missing header", headers: nil, wantURL: ""},
		{name: "challenge without resource_metadata", headers: []string{`Bearer realm="mcp"`}, wantURL: ""},
		{name: "malformed unterminated quote", headers: []string{`Bearer resource_metadata="https://x.test/meta`}, wantURL: ""},
		{name: "multiple header lines, parameter in the second",
			headers: []string{`Basic realm="legacy"`, bearerChallenge}, wantURL: resourceMetadataURL},
		{name: "multiple resource_metadata values, first wins",
			headers: []string{`Bearer resource_metadata="https://first.test/m", Bearer resource_metadata="https://second.test/m"`},
			wantURL: "https://first.test/m"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ss := newStatusServer(t, func(w http.ResponseWriter, r *http.Request, _ rpcCall) bool {
				if r.Method == http.MethodPost {
					for _, h := range tc.headers {
						w.Header().Add("WWW-Authenticate", h)
					}
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = io.WriteString(w, tc.body)
					return true
				}
				return false
			})

			c := newStatusClient(t, ss.URL)
			ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
			defer cancel()
			_, err := c.Initialize(ctx, initRequest())
			require.Error(t, err)

			assertAuthRequired(t, err, tc.wantURL)
			assert.False(t, errors.Is(err, transport.ErrLegacySSEServer), "401 must not be legacy SSE: %v", err)
			assert.False(t, errors.Is(err, transport.ErrSessionTerminated), "401 must not be a session error: %v", err)
			if tc.wantSubstr != "" {
				assert.Contains(t, err.Error(), tc.wantSubstr)
			}
			assert.False(t, c.IsInitialized())
		})
	}
}

func assertAuthRequired(t *testing.T, err error, wantURL string) {
	t.Helper()
	assert.True(t, errors.Is(err, transport.ErrUnauthorized), "ErrUnauthorized: %v", err)
	assert.True(t, errors.Is(err, transport.ErrAuthorizationRequired), "ErrAuthorizationRequired: %v", err)
	var te *transport.Error
	assert.True(t, errors.As(err, &te), "*transport.Error: %v", err)
	var are *transport.AuthorizationRequiredError
	if assert.True(t, errors.As(err, &are), "*AuthorizationRequiredError: %v", err) {
		assert.Equal(t, wantURL, are.ResourceMetadataURL)
	}
}

// TestProtocolStatus_CleanupResponseDoesNotOverwriteChallenge reproduces the
// sequence described in errorbody.go. The initialize POST succeeds (so the
// session ID is known), the follow-up initialized notification is rejected with
// 401, and Connect's cleanup DELETE is answered with a different non-2xx and its
// own WWW-Authenticate. Status, header and body must all describe the first
// (401) response.
func TestProtocolStatus_CleanupResponseDoesNotOverwriteChallenge(t *testing.T) {
	t.Parallel()
	ss := newStatusServer(t, func(w http.ResponseWriter, r *http.Request, call rpcCall) bool {
		switch {
		case r.Method == http.MethodPost && call.Method == "notifications/initialized":
			w.Header().Set("WWW-Authenticate", bearerChallenge)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, "initial challenge")
		case r.Method == http.MethodDelete:
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="https://cleanup.test/other"`)
			http.Error(w, "cleanup says not found", http.StatusNotFound)
		default:
			return false
		}
		return true
	})

	c := newStatusClient(t, ss.URL)
	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	_, err := c.Initialize(ctx, initRequest())
	require.Error(t, err)

	require.Positive(t, ss.deletes.Load(), "the SDK must have sent the cleanup DELETE for this test to be meaningful")
	assertAuthRequired(t, err, resourceMetadataURL)
	assert.False(t, errors.Is(err, transport.ErrLegacySSEServer), "cleanup 404 must not win: %v", err)
	assert.Contains(t, err.Error(), "initial challenge")
	assert.NotContains(t, err.Error(), "cleanup says not found")
}

// TestProtocolStatus_AuthChallengeMidSession covers 401 on a regular call of an
// already-initialized session.
func TestProtocolStatus_AuthChallengeMidSession(t *testing.T) {
	t.Parallel()

	t.Run("JSON-RPC error body keeps status, challenge and the session", func(t *testing.T) {
		t.Parallel()
		arm := armed()
		ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, call rpcCall) {
			arm.Store(false)
			w.Header().Set("WWW-Authenticate", bearerChallenge)
			writeRPCError(w, http.StatusUnauthorized, call.ID, -32001, "token expired", nil)
		}))
		c := newInitializedClient(t, ss.URL)

		ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
		defer cancel()
		_, err := callEcho(ctx, c, "x")
		require.Error(t, err)
		assertAuthRequired(t, err, resourceMetadataURL)
		assert.False(t, errors.Is(err, transport.ErrSessionTerminated), "got %v", err)

		var wire *jsonrpc.Error
		if assert.True(t, errors.As(err, &wire), "decoded JSON-RPC error should be retained: %v", err) {
			assert.Equal(t, "token expired", wire.Message)
		}
		requireUsable(t, c, "after-401")
	})

	t.Run("empty body is still classified by numeric status", func(t *testing.T) {
		t.Parallel()
		arm := armed()
		ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, _ rpcCall) {
			arm.Store(false)
			w.Header().Set("WWW-Authenticate", bearerChallenge)
			w.WriteHeader(http.StatusUnauthorized)
		}))
		c := newInitializedClient(t, ss.URL)

		ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
		defer cancel()
		_, err := callEcho(ctx, c, "x")
		require.Error(t, err)
		assertAuthRequired(t, err, resourceMetadataURL)
		assert.False(t, errors.Is(err, transport.ErrSessionTerminated), "got %v", err)
		// Recovery is deliberately not asserted: go-sdk treats a bodiless 401 as
		// a connection-level failure.
	})

	t.Run("403 is not an authentication challenge", func(t *testing.T) {
		t.Parallel()
		arm := armed()
		ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, _ rpcCall) {
			arm.Store(false)
			http.Error(w, "Unauthorized: denied by policy", http.StatusForbidden)
		}))
		c := newInitializedClient(t, ss.URL)

		ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
		defer cancel()
		_, err := callEcho(ctx, c, "x")
		require.Error(t, err)
		assert.False(t, errors.Is(err, transport.ErrUnauthorized), "body text must not drive classification: %v", err)
		assert.Contains(t, err.Error(), "denied by policy")
	})
}
