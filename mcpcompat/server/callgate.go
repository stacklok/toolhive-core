// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// CallGate is consulted once per HTTP POST on the Streamable HTTP transport,
// BEFORE session-ID validation and BEFORE the message is dispatched to the
// underlying SDK. The gate decides from the request context (the host's own
// middleware has already run and populated it — identity, parsed request);
// the shim passes the request through untouched.
//
// A nil return admits the request. A non-nil *Denial short-circuits dispatch:
// the response is a JSON-RPC error envelope (the request's id echoed
// best-effort; null when unparsable) with Denial.Code/Message, written at
// Denial.HTTPStatus (403 when zero), Content-Type application/json.
//
// Ordering contract: the gate runs before session validation, so a denied
// call with an invalid/terminated session ID receives the denial (e.g. 403),
// not 404 — a denial is determinable without session state, and this matches
// hosts whose authorization middleware sits outside the SDK entirely.
//
// Mechanism only: the shim carries no policy. It never inspects the meaning of
// a Denial beyond its wire fields, and it reads context the host populated
// rather than stuffing context itself. What "denied" means is entirely the
// host's concern.
//
// Scope: the gate covers the Streamable HTTP transport only. The stdio bridge
// (request_handler.go's manual HandleMessage mirror) has no HTTP status to set
// and no per-request identity middleware — on the stdio path authorization is
// expected to deny upstream, before the bridge — and the legacy SSEServer
// transport is likewise not wired. Both are deliberately out of scope; the
// seam can generalize later if a host needs it there.
type CallGate func(ctx context.Context, r *http.Request) *Denial

// Denial describes how a gated request is rejected on the wire.
type Denial struct {
	// Code is the JSON-RPC error code placed in the response envelope. It is
	// host-chosen and MUST NOT be a reserved JSON-RPC code (the -32000..-32768
	// range); it lives in application space so it never collides with SDK codes.
	Code int
	// Message is the JSON-RPC error message.
	Message string
	// HTTPStatus is the HTTP status the denial is written at. Zero means
	// http.StatusForbidden (403).
	HTTPStatus int
}

// WithCallGate installs a per-call denial gate on the Streamable HTTP server.
// The gate is consulted on every POST (see CallGate for the contract). Passing
// a nil gate leaves the server ungated (identical to not calling this option).
func WithCallGate(gate CallGate) StreamableHTTPOption {
	return func(s *StreamableHTTPServer) { s.callGate = gate }
}

// denied consults the call gate for a POST request and, on a non-nil *Denial,
// writes the denial envelope and reports true (the caller must stop). It
// returns false — admitting the request — when no gate is installed, the method
// is not POST (GET/SSE and DELETE/terminate are transport lifecycle, not
// calls), or the gate returns nil. On the admit path the request body is never
// read, so the happy path carries zero overhead.
func (s *StreamableHTTPServer) denied(w http.ResponseWriter, r *http.Request) bool {
	if s.callGate == nil || r.Method != http.MethodPost {
		return false
	}
	d := s.callGate(r.Context(), r)
	if d == nil {
		return false
	}
	writeDenial(w, r, d)
	return true
}

// writeDenial emits the JSON-RPC error envelope for a denied request. It reads
// the POST body exactly once to echo the request's id best-effort (null on a
// parse failure or a batch), then writes the shim's standard mcp.JSONRPCError
// envelope at the chosen HTTP status with Content-Type application/json — so a
// denial is byte-identical in shape to every other JSON-RPC error the shim
// emits.
//
// This runs only on the deny path: on allow the body is never touched, so the
// happy path incurs zero read-and-restore overhead. Because the request is not
// forwarded once denied, there is no need to restore r.Body.
func writeDenial(w http.ResponseWriter, r *http.Request, d *Denial) {
	status := d.HTTPStatus
	if status == 0 {
		status = http.StatusForbidden
	}

	envelope := mcp.JSONRPCError{
		JSONRPC: "2.0",
		ID:      extractRequestID(r),
		Error:   mcp.NewJSONRPCErrorDetails(d.Code, d.Message, nil),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(envelope)
}

// extractRequestID reads the POST body once and returns the JSON-RPC id to echo
// in the error envelope. A zero-valued mcp.RequestId marshals to null, which is
// what is returned for anything that cannot be confidently attributed to a
// single request: an unreadable or unparsable body, a batch (JSON array), or a
// message with no id. The body is drained regardless so nothing is left
// half-read.
//
// The read is deliberately unbounded here: the host is expected to bound the
// request body outermost in its middleware chain (e.g. http.MaxBytesReader), so
// an over-cap body makes io.ReadAll error and falls through to a null id. A
// second limiter in this generic shim would redundantly hardcode a body-size
// policy that belongs to the host.
func extractRequestID(r *http.Request) mcp.RequestId {
	var zero mcp.RequestId // marshals to null
	if r.Body == nil {
		return zero
	}
	raw, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil || len(raw) == 0 {
		return zero
	}
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	// json.Unmarshal fails on a batch (top-level array) and on malformed JSON,
	// and leaves msg.ID empty for a well-formed message with no id — all of which
	// correctly fall through to the null id.
	if err := json.Unmarshal(raw, &msg); err != nil || len(msg.ID) == 0 {
		return zero
	}
	var id mcp.RequestId
	if err := json.Unmarshal(msg.ID, &id); err != nil {
		return zero
	}
	return id
}
