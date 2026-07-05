// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package transport is a drop-in compatibility shim for
// github.com/mark3labs/mcp-go/client/transport. It provides the transport
// option types and error values that ToolHive references; the actual transport
// is driven by the official go-sdk from the client package.
//
// This package intentionally does not import the go-sdk: it only carries
// configuration and error types. The client package reads the exported
// accessors here to construct the underlying go-sdk transport.
package transport

import (
	"log/slog"
	"net/http"
	"time"
)

// Interface is the transport handle returned by client.GetTransport. It mirrors
// mcp-go's transport.Interface for the subset ToolHive uses (type-asserting to
// *StreamableHTTP and reading the session ID).
type Interface interface {
	// GetSessionId returns the transport-level MCP session ID, if any.
	GetSessionId() string
}

// StreamableHTTP holds Streamable HTTP transport configuration and, once
// connected, the live session ID. It is both the option target (mirroring
// mcp-go, whose options mutate the transport struct) and the handle returned by
// client.GetTransport.
type StreamableHTTP struct {
	endpoint            string
	httpClient          *http.Client
	headers             map[string]string
	timeout             time.Duration
	logger              *slog.Logger
	continuousListening bool
	sessionID           string
}

// NewStreamableHTTP creates a StreamableHTTP for the given endpoint and applies
// the supplied options. It is used by the client package.
func NewStreamableHTTP(endpoint string, opts ...StreamableHTTPCOption) *StreamableHTTP {
	s := &StreamableHTTP{endpoint: endpoint}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// GetSessionId returns the current MCP session ID (empty if not yet connected
// or if the transport is stateless).
func (s *StreamableHTTP) GetSessionId() string { return s.sessionID }

// SetSessionID records the live session ID. Used by the client package after
// the underlying go-sdk session is established.
func (s *StreamableHTTP) SetSessionID(id string) { s.sessionID = id }

// Endpoint returns the configured endpoint URL.
func (s *StreamableHTTP) Endpoint() string { return s.endpoint }

// HTTPClient returns the configured HTTP client, or nil to use the default.
func (s *StreamableHTTP) HTTPClient() *http.Client { return s.httpClient }

// Headers returns the configured static headers.
func (s *StreamableHTTP) Headers() map[string]string { return s.headers }

// Timeout returns the configured HTTP timeout (0 if unset).
func (s *StreamableHTTP) Timeout() time.Duration { return s.timeout }

// Logger returns the configured logger, if any.
func (s *StreamableHTTP) Logger() *slog.Logger { return s.logger }

// ContinuousListening reports whether a standalone SSE listening stream was
// requested.
func (s *StreamableHTTP) ContinuousListening() bool { return s.continuousListening }

// StreamableHTTPCOption configures a StreamableHTTP transport.
type StreamableHTTPCOption func(*StreamableHTTP)

// WithHTTPTimeout sets the HTTP timeout for the Streamable HTTP transport.
func WithHTTPTimeout(timeout time.Duration) StreamableHTTPCOption {
	return func(s *StreamableHTTP) { s.timeout = timeout }
}

// WithHTTPBasicClient sets a custom HTTP client for the Streamable HTTP transport.
func WithHTTPBasicClient(client *http.Client) StreamableHTTPCOption {
	return func(s *StreamableHTTP) { s.httpClient = client }
}

// WithHTTPHeaders sets static headers sent on each request.
func WithHTTPHeaders(headers map[string]string) StreamableHTTPCOption {
	return func(s *StreamableHTTP) { s.headers = headers }
}

// WithSession sets an initial session ID (for resuming a session).
func WithSession(sessionID string) StreamableHTTPCOption {
	return func(s *StreamableHTTP) { s.sessionID = sessionID }
}

// WithContinuousListening enables a standalone SSE stream for server-initiated
// messages.
func WithContinuousListening() StreamableHTTPCOption {
	return func(s *StreamableHTTP) { s.continuousListening = true }
}

// WithHTTPLogger sets a logger for the Streamable HTTP transport.
func WithHTTPLogger(logger *slog.Logger) StreamableHTTPCOption {
	return func(s *StreamableHTTP) { s.logger = logger }
}
