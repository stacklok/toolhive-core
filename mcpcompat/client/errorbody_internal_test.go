// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
)

// TestErrorBodyEnrichment reproduces the authz case: a tool call denied with an
// HTTP 403 whose body says "Unauthorized". go-sdk's client would surface only
// "403 Forbidden" (status text, body dropped); the RoundTripper captures the
// body and mapCallError re-attaches it so callers (and ToolHive's authz e2e
// test) see "Unauthorized".
func TestErrorBodyEnrichment(t *testing.T) {
	t.Parallel()

	const bodyText = "Unauthorized: request denied by policy"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(bodyText))
	}))
	t.Cleanup(ts.Close)

	ctx := withErrCapture(context.Background())
	hc := buildHTTPClient(nil, nil, nil, 0)
	require.NotNil(t, hc)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := hc.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	// The RoundTripper must have restored the body for downstream readers.
	restored, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyText, string(restored), "response body must be restored")

	// Simulate go-sdk's status-only error and confirm enrichment surfaces the body.
	gosdkErr := fmt.Errorf(`calling "tools/call": %s`, http.StatusText(resp.StatusCode))
	assert.NotContains(t, gosdkErr.Error(), "Unauthorized", "precondition: go-sdk error lacks the body")

	enriched := mapCallError(ctx, gosdkErr)
	require.Error(t, enriched)
	assert.Contains(t, enriched.Error(), "Unauthorized", "enriched error must include the server body")
	assert.Contains(t, enriched.Error(), "403")
}

// TestErrorBodyEnrichment_NoCaptureNoop verifies enrichment is a no-op when no
// body was captured (e.g. a 2xx path or a non-HTTP error).
func TestErrorBodyEnrichment_NoCaptureNoop(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	orig := fmt.Errorf("some transport failure")
	assert.Equal(t, orig, mapCallError(ctx, orig))
}

// TestCaptureErrorBody_FirstNon2xxWins reproduces issue #179: a server that
// rejects the initialize POST with 401 and then answers the go-sdk's
// session-cleanup DELETE (sent on the same call context before Connect
// returns) with 404. GitLab's remote MCP (gitlab.com/api/v4/mcp) behaves
// exactly like this. The capture must keep the 401 (the response that failed
// the call), so mapConnectError classifies the failure as an auth challenge
// (ErrUnauthorized) rather than by the cleanup response (ErrLegacySSEServer),
// which is what ToolHive's vMCP health checker keys off to treat
// auth-required backends as healthy.
func TestCaptureErrorBody_FirstNon2xxWins(t *testing.T) {
	t.Parallel()

	const (
		unauthorizedBody = `{"message":"401 Unauthorized"}`
		notFoundBody     = `{"error":"404 Not Found"}`
		wwwAuth          = `Bearer realm="GitLab", resource_metadata="https://gitlab.example/.well-known/oauth-protected-resource/mcp"`
	)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(notFoundBody))
			return
		}
		w.Header().Set("WWW-Authenticate", wwwAuth)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(unauthorizedBody))
	}))
	t.Cleanup(ts.Close)

	ctx := withErrCapture(context.Background())
	hc := buildHTTPClient(nil, nil, nil, 0)
	require.NotNil(t, hc)

	do := func(method string) *http.Response {
		req, err := http.NewRequestWithContext(ctx, method, ts.URL, http.NoBody)
		require.NoError(t, err)
		resp, err := hc.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() { _ = resp.Body.Close() })
		return resp
	}

	do(http.MethodPost)           // initialize, rejected with 401
	resp := do(http.MethodDelete) // session cleanup, 404

	// The 404 must pass through untouched for downstream readers.
	deleteBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, notFoundBody, string(deleteBody))

	// The holder must describe the 401, not the later 404.
	h := capturedErr(ctx)
	require.NotNil(t, h)
	assert.Equal(t, http.StatusUnauthorized, h.status, "cleanup DELETE must not overwrite the captured status")
	assert.Equal(t, unauthorizedBody, h.body)
	assert.Equal(t, []string{wwwAuth}, h.wwwAuthHdrs)

	// Classification must follow the 401: auth challenge, not legacy SSE.
	src := fmt.Errorf("calling initialize: %s", http.StatusText(http.StatusUnauthorized))
	mapped := mapConnectError(ctx, src)
	require.Error(t, mapped)
	assert.True(t, errors.Is(mapped, transport.ErrUnauthorized), "want ErrUnauthorized, got %v", mapped)
	assert.False(t, errors.Is(mapped, transport.ErrLegacySSEServer), "must not classify as legacy SSE, got %v", mapped)

	var authErr *transport.AuthorizationRequiredError
	require.True(t, errors.As(mapped, &authErr))
	assert.Equal(t,
		"https://gitlab.example/.well-known/oauth-protected-resource/mcp",
		authErr.ResourceMetadataURL,
		"resource metadata from the 401's WWW-Authenticate must survive")
}
