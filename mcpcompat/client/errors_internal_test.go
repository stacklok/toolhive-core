// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
)

// unauthorizedBody is the canonical body text used across test cases for a 401
// response. Extracted as a constant to satisfy goconst (4+ occurrences).
const unauthorizedBody = "Unauthorized"

func TestMapTransportError_Unauthorized(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	err := mapTransportError(ctx, errors.New("request failed: 401 Unauthorized"), nil)

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
	ctx := withErrCapture(context.Background())
	err := mapTransportError(ctx, errors.New("server returned 404: session not found"), nil)
	assert.True(t, errors.Is(err, transport.ErrSessionTerminated))
}

func TestMapTransportError_LegacySSE(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	err := mapTransportError(ctx, errors.New("405 method not allowed"), nil)
	assert.True(t, errors.Is(err, transport.ErrLegacySSEServer))
}

func TestMapTransportError_Passthrough(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	orig := errors.New("some unrelated failure")
	assert.Equal(t, orig, mapTransportError(ctx, orig, nil))
}

func TestMapTransportError_Nil(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	assert.NoError(t, mapTransportError(ctx, nil, nil))
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
			body:    unauthorizedBody,
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
			body:    unauthorizedBody,
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

// TestMapTransportError_5xxWithUnauthorizedBodyNotMisclassified is the residual
// edge case from wave 4's review: a captured 5xx status whose body contains the
// substring "401" or "unauthorized" must NOT fall through to the string
// fallback and falsely trigger ToolHive's OAuth refresh flow. The status-driven
// classification only covers 4xx (< 500), so without the 5xx guard a 500 body
// saying "unauthorized to access X" would be misclassified as ErrUnauthorized.
func TestMapTransportError_5xxWithUnauthorizedBodyNotMisclassified(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "500 with unauthorized in body",
			status: http.StatusInternalServerError,
			body:   "unauthorized to access internal resource",
		},
		{
			name:   "502 with 401 in body",
			status: http.StatusBadGateway,
			body:   "upstream returned 401 Unauthorized",
		},
		{
			name:   "503 with unauthorized in body",
			status: http.StatusServiceUnavailable,
			body:   "service unauthorized to handle request",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := seedCapture(tc.status, tc.body)
			src := fmt.Errorf(`calling "tools/call": %s`, http.StatusText(tc.status))
			mapped := mapCallError(ctx, src)
			require.Error(t, mapped)
			assert.False(t, errors.Is(mapped, transport.ErrUnauthorized),
				"5xx must not satisfy ErrUnauthorized: %v", mapped)
			assert.False(t, errors.Is(mapped, transport.ErrAuthorizationRequired),
				"5xx must not satisfy ErrAuthorizationRequired: %v", mapped)
		})
	}
}

// TestMapCallError_5xxSurfacesUnchanged confirms a captured 5xx status surfaces
// the error unchanged (not reclassified as any transport sentinel).
func TestMapCallError_5xxSurfacesUnchanged(t *testing.T) {
	t.Parallel()
	ctx := seedCapture(http.StatusInternalServerError, "internal server error")
	src := fmt.Errorf(`calling "tools/call": %s`, http.StatusText(http.StatusInternalServerError))
	mapped := mapCallError(ctx, src)
	require.Error(t, mapped)
	assert.False(t, errors.Is(mapped, transport.ErrUnauthorized))
	assert.False(t, errors.Is(mapped, transport.ErrSessionTerminated))
	assert.False(t, errors.Is(mapped, transport.ErrLegacySSEServer))
	assert.False(t, errors.Is(mapped, transport.ErrAuthorizationRequired))
}

// TestExtractResourceMetadataURL_FromCapturedHeader verifies the shim's own
// headerRoundTripper captures the WWW-Authenticate header and the error mappers
// populate AuthorizationRequiredError.ResourceMetadataURL from it (RFC 9728
// §5.1). The go-sdk does not surface this header on its errors; the shim's
// RoundTripper is the only place it is available.
func TestExtractResourceMetadataURL_FromCapturedHeader(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		header string // WWW-Authenticate header value
		want   string // expected ResourceMetadataURL
	}{
		{
			name:   "bearer with resource_metadata",
			header: `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`,
			want:   "https://example.com/.well-known/oauth-protected-resource",
		},
		{
			name:   "bearer with realm and resource_metadata",
			header: `Bearer realm="api", resource_metadata="https://auth.example.com/prm"`,
			want:   "https://auth.example.com/prm",
		},
		{
			name:   "no resource_metadata parameter",
			header: `Bearer realm="api"`,
			want:   "",
		},
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
		{
			name:   "token value form (unquoted, limited to token chars)",
			header: `Bearer resource_metadata=token123`,
			want:   "token123",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := withErrCapture(context.Background())
			h := capturedErr(ctx)
			h.status = http.StatusUnauthorized
			if tc.header != "" {
				h.wwwAuthHdrs = []string{tc.header}
			}
			got := extractResourceMetadataURL(ctx)
			assert.Equal(t, tc.want, got)
		})
	}
}

// TestMapCallError_Transport401_PopulatesResourceMetadataURL verifies that a
// transport-level 401 with a WWW-Authenticate header populates the
// AuthorizationRequiredError.ResourceMetadataURL field end-to-end through
// mapCallError.
func TestMapCallError_Transport401_PopulatesResourceMetadataURL(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	h := capturedErr(ctx)
	h.status = http.StatusUnauthorized
	h.body = unauthorizedBody
	h.wwwAuthHdrs = []string{
		`Bearer resource_metadata="https://resource.example.com/.well-known/oauth-protected-resource"`,
	}
	src := fmt.Errorf(`calling "tools/call": %s`, http.StatusText(http.StatusUnauthorized))
	mapped := mapCallError(ctx, src)
	require.Error(t, mapped)
	assert.True(t, errors.Is(mapped, transport.ErrUnauthorized))

	var are *transport.AuthorizationRequiredError
	require.True(t, errors.As(mapped, &are))
	assert.Equal(t, "https://resource.example.com/.well-known/oauth-protected-resource", are.ResourceMetadataURL)
}

// TestMapConnectError_Transport401_PopulatesResourceMetadataURL verifies the
// same end-to-end population through mapConnectError (the initialize path).
func TestMapConnectError_Transport401_PopulatesResourceMetadataURL(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	h := capturedErr(ctx)
	h.status = http.StatusUnauthorized
	h.body = unauthorizedBody
	h.wwwAuthHdrs = []string{
		`Bearer realm="api", resource_metadata="https://auth.example.com/prm"`,
	}
	src := fmt.Errorf("calling initialize: %s", http.StatusText(http.StatusUnauthorized))
	mapped := mapConnectError(ctx, src)
	require.Error(t, mapped)
	assert.True(t, errors.Is(mapped, transport.ErrUnauthorized))

	var are *transport.AuthorizationRequiredError
	require.True(t, errors.As(mapped, &are))
	assert.Equal(t, "https://auth.example.com/prm", are.ResourceMetadataURL)
}

// TestCaptureErrorBody_CapturesWWWAuthenticate verifies the headerRoundTripper
// captures the WWW-Authenticate header into the errBody holder for a 401
// response, so the error mappers can parse resource_metadata from it.
func TestCaptureErrorBody_CapturesWWWAuthenticate(t *testing.T) {
	t.Parallel()

	const wwwAuth = `Bearer resource_metadata="https://example.com/.well-known/oauth-protected-resource"`
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("WWW-Authenticate", wwwAuth)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(unauthorizedBody))
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

	h := capturedErr(ctx)
	require.NotNil(t, h)
	assert.Equal(t, http.StatusUnauthorized, h.status)
	assert.Contains(t, h.wwwAuthHdrs, wwwAuth)
	assert.Equal(t, "https://example.com/.well-known/oauth-protected-resource",
		extractResourceMetadataURL(ctx))
}
