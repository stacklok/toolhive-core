// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strconv"
)

// LATEST_PROTOCOL_VERSION is the most recent version of the MCP protocol.
const LATEST_PROTOCOL_VERSION = "2025-11-25"

// JSONRPC_VERSION is the version of JSON-RPC used by MCP.
const JSONRPC_VERSION = "2.0"

// ProgressToken is used to associate progress notifications with the original request.
type ProgressToken any

// Cursor is an opaque token used to represent a cursor for pagination.
type Cursor string

// Meta is metadata attached to a request's parameters. This can include fields
// formally defined by the protocol or other arbitrary data.
type Meta struct {
	// If specified, the caller is requesting out-of-band progress
	// notifications for this request (as represented by
	// notifications/progress). The value of this parameter is an
	// opaque token that will be attached to any subsequent
	// notifications. The receiver is not obligated to provide these
	// notifications.
	ProgressToken ProgressToken

	// AdditionalFields are any fields present in the Meta that are not
	// otherwise defined in the protocol.
	AdditionalFields map[string]any
}

// MarshalJSON implements json.Marshaler for Meta.
//
//nolint:revive // method name intentionally matches mcp-go for drop-in compatibility.
func (m *Meta) MarshalJSON() ([]byte, error) {
	raw := make(map[string]any)
	if m.ProgressToken != nil {
		raw["progressToken"] = m.ProgressToken
	}
	maps.Copy(raw, m.AdditionalFields)

	return json.Marshal(raw)
}

// UnmarshalJSON implements json.Unmarshaler for Meta.
//
//nolint:revive // method name intentionally matches mcp-go for drop-in compatibility.
func (m *Meta) UnmarshalJSON(data []byte) error {
	raw := make(map[string]any)
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.ProgressToken = raw["progressToken"]
	delete(raw, "progressToken")
	m.AdditionalFields = raw
	return nil
}

// NewMetaFromMap builds a *Meta from a raw map.
func NewMetaFromMap(m map[string]any) *Meta {
	progressToken := m["progressToken"]
	if progressToken != nil {
		delete(m, "progressToken")
	}

	return &Meta{
		ProgressToken:    progressToken,
		AdditionalFields: m,
	}
}

// Request is the base type embedded in protocol request messages.
type Request struct {
	Method string        `json:"method"`
	Params RequestParams `json:"params,omitzero"`
}

// RequestParams is the base params type carrying _meta.
type RequestParams struct {
	Meta *Meta `json:"_meta,omitempty"`
}

// Notification is the base of a JSON-RPC notification (method + params).
type Notification struct {
	Method string             `json:"method"`
	Params NotificationParams `json:"params,omitzero"`
}

// NotificationParams carries a notification's params.
type NotificationParams struct {
	// This parameter name is reserved by MCP to allow clients and
	// servers to attach additional metadata to their notifications.
	Meta map[string]any `json:"_meta,omitempty"`

	// Additional fields can be added to this map
	AdditionalFields map[string]any `json:"-"`
}

// MarshalJSON implements custom JSON marshaling
func (p NotificationParams) MarshalJSON() ([]byte, error) {
	// Create a map to hold all fields
	m := make(map[string]any)

	// Add Meta if it exists
	if p.Meta != nil {
		m["_meta"] = p.Meta
	}

	// Add all additional fields
	for k, v := range p.AdditionalFields {
		// Ensure we don't override the _meta field
		if k != "_meta" {
			m[k] = v
		}
	}

	return json.Marshal(m)
}

// UnmarshalJSON implements custom JSON unmarshaling
func (p *NotificationParams) UnmarshalJSON(data []byte) error {
	// Create a map to hold all fields
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}

	// Initialize maps if they're nil
	if p.Meta == nil {
		p.Meta = make(map[string]any)
	}
	if p.AdditionalFields == nil {
		p.AdditionalFields = make(map[string]any)
	}

	// Process all fields
	for k, v := range m {
		if k == "_meta" {
			// Handle Meta field
			if meta, ok := v.(map[string]any); ok {
				p.Meta = meta
			}
		} else {
			// Handle additional fields
			p.AdditionalFields[k] = v
		}
	}

	return nil
}

// Result is the base type embedded in protocol result messages.
type Result struct {
	// This result property is reserved by the protocol to allow clients and
	// servers to attach additional metadata to their responses.
	Meta *Meta `json:"_meta,omitempty"`
}

// RequestId is a uniquely identifying ID for a request in JSON-RPC.
// It can be any JSON-serializable value, typically a number or string.
type RequestId struct {
	value any
}

// NewRequestId creates a new RequestId with the given value
func NewRequestId(value any) RequestId {
	return RequestId{value: value}
}

// Value returns the underlying value of the RequestId
func (r RequestId) Value() any {
	return r.value
}

// String returns a string representation of the RequestId
func (r RequestId) String() string {
	switch v := r.value.(type) {
	case string:
		return "string:" + v
	case int64:
		return "int64:" + strconv.FormatInt(v, 10)
	case float64:
		if v == float64(int64(v)) {
			return "int64:" + strconv.FormatInt(int64(v), 10)
		}
		return "float64:" + strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return "<nil>"
	default:
		return "unknown:" + fmt.Sprintf("%v", v)
	}
}

// IsNil returns true if the RequestId is nil
func (r RequestId) IsNil() bool {
	return r.value == nil
}

// MarshalJSON implements json.Marshaler for RequestId.
//
//nolint:revive // method name intentionally matches mcp-go for drop-in compatibility.
func (r RequestId) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.value)
}

// UnmarshalJSON implements json.Unmarshaler for RequestId.
//
//nolint:revive // method name intentionally matches mcp-go for drop-in compatibility.
func (r *RequestId) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		r.value = nil
		return nil
	}

	// Try unmarshaling as string first
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		r.value = s
		return nil
	}

	// JSON numbers are unmarshaled as float64 in Go
	var f float64
	if err := json.Unmarshal(data, &f); err == nil {
		if f == float64(int64(f)) {
			r.value = int64(f)
		} else {
			r.value = f
		}
		return nil
	}

	return fmt.Errorf("invalid request id: %s", string(data))
}

// JSONRPCMessage represents either a JSONRPCRequest, JSONRPCNotification, JSONRPCResponse, or JSONRPCError
type JSONRPCMessage any

// JSONRPCNotification represents a notification which does not expect a response.
type JSONRPCNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Notification
}

// JSONRPCResponse represents a successful (non-error) response to a request.
type JSONRPCResponse struct {
	JSONRPC string    `json:"jsonrpc"`
	ID      RequestId `json:"id"`
	Result  any       `json:"result"`
}

// JSONRPCError represents a non-successful (error) response to a request.
type JSONRPCError struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      RequestId           `json:"id"`
	Error   JSONRPCErrorDetails `json:"error"`
}

// JSONRPCErrorDetails represents a JSON-RPC error for Go error handling.
// This is separate from the JSONRPCError type which represents the full JSON-RPC error response structure.
type JSONRPCErrorDetails struct {
	// The error type that occurred.
	Code int `json:"code"`
	// A short description of the error. The message SHOULD be limited
	// to a concise single sentence.
	Message string `json:"message"`
	// Additional information about the error. The value of this member
	// is defined by the sender (e.g. detailed error information, nested errors etc.).
	Data any `json:"data,omitempty"`
}

// UnmarshalJSON handles both the standard JSON-RPC error object
// ({"code": -32600, "message": "..."}) and non-compliant servers that
// return the error as a plain string (e.g. "cursor_invalid").
func (e *JSONRPCErrorDetails) UnmarshalJSON(data []byte) error {
	// Try the spec-compliant object shape first.
	type plain JSONRPCErrorDetails
	if err := json.Unmarshal(data, (*plain)(e)); err == nil {
		return nil
	}
	// Some servers (e.g. Slack MCP) return a bare string.
	var msg string
	if err := json.Unmarshal(data, &msg); err != nil {
		return fmt.Errorf("error field is neither an object nor a string: %w", err)
	}
	e.Code = INTERNAL_ERROR
	e.Message = msg
	return nil
}

// Standard JSON-RPC error codes
const (
	// PARSE_ERROR indicates invalid JSON was received by the server.
	PARSE_ERROR = -32700

	// INVALID_REQUEST indicates the JSON sent is not a valid Request object.
	INVALID_REQUEST = -32600

	// METHOD_NOT_FOUND indicates the method does not exist/is not available.
	METHOD_NOT_FOUND = -32601

	// INVALID_PARAMS indicates invalid method parameter(s).
	INVALID_PARAMS = -32602

	// INTERNAL_ERROR indicates internal JSON-RPC error.
	INTERNAL_ERROR = -32603

	// REQUEST_INTERRUPTED indicates a request was cancelled or timed out.
	REQUEST_INTERRUPTED = -32800
)

// MCP error codes
const (
	// RESOURCE_NOT_FOUND indicates that the requested resource was not found.
	RESOURCE_NOT_FOUND = -32002

	// URL_ELICITATION_REQUIRED is the error code for when URL elicitation is required.
	URL_ELICITATION_REQUIRED = -32042
)

// EmptyResult represents a response that indicates success but carries no data.
type EmptyResult Result

// PingRequest represents a ping, issued by either the server or the client,
// to check that the other party is still alive. The receiver must promptly respond,
// or else may be disconnected.
type PingRequest struct {
	Request
	Header http.Header `json:"-"`
}
