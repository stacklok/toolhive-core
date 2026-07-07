// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import "net/http"

// SSE holds SSE (Server-Sent Events) transport configuration. It is the option
// target for the SSE client, mirroring mcp-go's transport package.
type SSE struct {
	endpoint   string
	httpClient *http.Client
	headers    map[string]string
}

// NewSSE creates an SSE transport config for the given endpoint and applies the
// supplied options. Used by the client package.
func NewSSE(endpoint string, opts ...ClientOption) *SSE {
	s := &SSE{endpoint: endpoint}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Endpoint returns the configured endpoint URL.
func (s *SSE) Endpoint() string { return s.endpoint }

// HTTPClient returns the configured HTTP client, or nil to use the default.
func (s *SSE) HTTPClient() *http.Client { return s.httpClient }

// Headers returns the configured static headers.
func (s *SSE) Headers() map[string]string { return s.headers }

// ClientOption configures an SSE transport.
type ClientOption func(*SSE)

// WithHTTPClient sets a custom HTTP client for the SSE transport.
func WithHTTPClient(httpClient *http.Client) ClientOption {
	return func(s *SSE) { s.httpClient = httpClient }
}

// WithHeaders sets static headers for the SSE client.
func WithHeaders(headers map[string]string) ClientOption {
	return func(s *SSE) { s.headers = headers }
}
