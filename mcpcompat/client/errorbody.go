// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
)

// go-sdk v1.8 decodes JSON-RPC error bodies from non-2xx responses, but for
// plain-text bodies it reports only http.StatusText(code). The shim still needs
// those bodies for mcp-go-compatible actionable detail, the numeric HTTP status
// for error classification, and WWW-Authenticate headers for RFC 9728 discovery.
// The client installs a RoundTripper that captures these into a per-call holder
// carried on the request context, and the error mappers enrich the returned error.

// maxCapturedErrBody bounds how much of an error response body we read.
const maxCapturedErrBody = 8 << 10 // 8 KiB

type errBody struct {
	status      int
	body        string
	wwwAuthHdrs []string // captured WWW-Authenticate header values (RFC 9728)
	// answersRequest is set for a 404 whose body is a JSON-RPC error response
	// carrying the request's own ID: the server processed this request on a
	// live session (go-sdk servers answer unknown methods this way on newer
	// protocol versions), so the 404 is not a session-termination signal.
	answersRequest bool
}

type errBodyKey struct{}

// withErrCapture returns a context carrying a holder for a captured non-2xx
// response body. Pass the returned context to the underlying request so the
// RoundTripper can populate it, then hand the same context to mapCallError /
// mapConnectError to enrich the error.
func withErrCapture(ctx context.Context) context.Context {
	return context.WithValue(ctx, errBodyKey{}, &errBody{})
}

func capturedErr(ctx context.Context) *errBody {
	if v, ok := ctx.Value(errBodyKey{}).(*errBody); ok {
		return v
	}
	return nil
}

// captureErrorBody records a non-2xx response body into the context holder (if
// present) and restores resp.Body so downstream readers are unaffected. Safe on
// nil/2xx responses (no-op).
//
// The HTTP status code is recorded regardless of whether the body is non-empty
// (issue #156, finding 4): a 4xx with an empty body — common for 401 and 404 —
// still carries an authoritative status code, and the status-driven
// classification in mapTransportError/mapConnectError relies on h.status being
// set. Previously h.status was only set when the body was non-empty, so an
// empty-body 4xx left h.status == 0 and classification fell to the
// best-effort string fallback, which does not map bare "400 Bad Request"/"404
// Not Found" on initialize to ErrLegacySSEServer.
//
// Only the FIRST non-2xx response on the context is captured, so status, body,
// and WWW-Authenticate all describe the same response (issue #179). Several
// requests can share one call context: when a server rejects the initialize
// POST with 401, the go-sdk sends a session-cleanup DELETE before Connect
// returns, and a non-401 answer to that DELETE (GitLab 404s it) must not
// overwrite the 401. Otherwise mapConnectError classifies the connect failure
// by the cleanup response and an auth challenge surfaces as ErrLegacySSEServer
// instead of ErrUnauthorized. Later non-2xx responses pass through untouched.
func captureErrorBody(req *http.Request, resp *http.Response) {
	if resp == nil || resp.StatusCode < 400 || resp.Body == nil {
		return
	}
	h := capturedErr(req.Context())
	if h == nil || h.status != 0 {
		return
	}
	// Record the status code unconditionally: it is available from the response
	// regardless of body length, and the status-driven classification depends on
	// it. Do this before reading the body so a read error cannot prevent it.
	h.status = resp.StatusCode
	// Capture WWW-Authenticate header values (RFC 9728 §5.1) so the error
	// mappers can populate AuthorizationRequiredError.ResourceMetadataURL. The
	// go-sdk does not surface this header on its errors; the shim's own
	// RoundTripper is the only place it is available.
	if vals := resp.Header.Values("WWW-Authenticate"); len(vals) > 0 {
		h.wwwAuthHdrs = vals
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxCapturedErrBody))
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(data))
	if err == nil {
		h.body = string(data)
		if resp.StatusCode == http.StatusNotFound {
			h.answersRequest = rpcErrorAnswersRequest(req, data)
		}
	}
}

// rpcErrorAnswersRequest reports whether body is a JSON-RPC error response whose
// ID equals the ID of the JSON-RPC request carried by req.
//
// A JSON-RPC error body alone does not prove the session is alive: other SDKs
// also answer a terminated session with a 404 plus a JSON-RPC error, but with a
// null ID (TypeScript SDK) or a fixed placeholder ID (Python SDK's
// "server-error"). Only an ID matching this request shows the server handled
// it. Anything unparseable (including a body truncated at maxCapturedErrBody),
// a notification, or a request whose body cannot be re-read returns false, which
// keeps the safe default of reporting session termination.
func rpcErrorAnswersRequest(req *http.Request, body []byte) bool {
	var resp struct {
		ID    json.RawMessage `json:"id"`
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(body, &resp) != nil || isJSONNull(resp.Error) || isJSONNull(resp.ID) {
		return false
	}
	if req.GetBody == nil {
		return false
	}
	rc, err := req.GetBody()
	if err != nil {
		return false
	}
	defer func() { _ = rc.Close() }()
	var call struct {
		ID json.RawMessage `json:"id"`
	}
	if json.NewDecoder(rc).Decode(&call) != nil || isJSONNull(call.ID) {
		return false
	}
	return jsonRPCIDEqual(call.ID, resp.ID)
}

// isJSONNull reports whether raw is absent or the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null"))
}

// jsonRPCIDEqual compares two JSON-RPC IDs by value, so 7 and 7.0 match. Only
// string and number IDs are valid; anything else never matches.
func jsonRPCIDEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	switch x.(type) {
	case string, float64:
		return x == y
	default:
		return false
	}
}
