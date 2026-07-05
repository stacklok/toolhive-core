// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- stdio -----------------------------------------------------------------

// StdioOption configures the stdio server (retained for API compatibility).
type StdioOption func(*stdioConfig)

type stdioConfig struct{}

// ServeStdio runs the MCP server over stdio until the context is done. It
// mirrors mcp-go's server.ServeStdio.
func ServeStdio(server *MCPServer, _ ...StdioOption) error {
	srv, err := server.buildServer("")
	if err != nil {
		return err
	}
	return srv.Run(context.Background(), &gosdk.StdioTransport{})
}

// --- Streamable HTTP -------------------------------------------------------

// HTTPContextFunc customizes the request context for HTTP transports.
type HTTPContextFunc func(ctx context.Context, r *http.Request) context.Context

// StreamableHTTPOption configures a StreamableHTTPServer.
type StreamableHTTPOption func(*StreamableHTTPServer)

// StreamableHTTPServer serves the MCP server over the Streamable HTTP transport.
// It implements http.Handler so it can be mounted on an http.ServeMux, and also
// offers Start/Shutdown for standalone use.
type StreamableHTTPServer struct {
	mcp          *MCPServer
	endpointPath string
	contextFunc  HTTPContextFunc
	sessionIDMgr SessionIdManager
	heartbeat    time.Duration

	once     sync.Once
	handler  http.Handler
	buildErr error
	httpSrv  *http.Server
}

// NewStreamableHTTPServer creates a Streamable HTTP server for the MCP server.
func NewStreamableHTTPServer(server *MCPServer, opts ...StreamableHTTPOption) *StreamableHTTPServer {
	s := &StreamableHTTPServer{mcp: server, endpointPath: "/mcp"}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithEndpointPath sets the HTTP path the server is mounted at.
func WithEndpointPath(endpointPath string) StreamableHTTPOption {
	return func(s *StreamableHTTPServer) { s.endpointPath = endpointPath }
}

// WithSessionIdManager supplies a session ID manager.
//
// NOTE: the go-sdk manages MCP session IDs internally; the supplied manager is
// retained for API compatibility but does not yet drive the SDK's ID lifecycle.
func WithSessionIdManager(manager SessionIdManager) StreamableHTTPOption {
	return func(s *StreamableHTTPServer) { s.sessionIDMgr = manager }
}

// WithHeartbeatInterval sets the keep-alive ping interval.
func WithHeartbeatInterval(interval time.Duration) StreamableHTTPOption {
	return func(s *StreamableHTTPServer) { s.heartbeat = interval }
}

// WithHTTPContextFunc installs a per-request context customizer.
func WithHTTPContextFunc(fn HTTPContextFunc) StreamableHTTPOption {
	return func(s *StreamableHTTPServer) { s.contextFunc = fn }
}

func (s *StreamableHTTPServer) build() {
	s.once.Do(func() {
		srv, err := s.mcp.buildServer("")
		if err != nil {
			s.buildErr = err
			return
		}
		opts := &gosdk.StreamableHTTPOptions{}
		s.handler = gosdk.NewStreamableHTTPHandler(func(*http.Request) *gosdk.Server { return srv }, opts)
	})
}

// ServeHTTP implements http.Handler.
func (s *StreamableHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.build()
	if s.buildErr != nil {
		http.Error(w, fmt.Sprintf("building server: %v", s.buildErr), http.StatusInternalServerError)
		return
	}
	if s.contextFunc != nil {
		r = r.WithContext(s.contextFunc(r.Context(), r))
	}
	s.handler.ServeHTTP(w, r)
}

// Start serves on addr until Shutdown is called.
func (s *StreamableHTTPServer) Start(addr string) error {
	mux := http.NewServeMux()
	mux.Handle(s.endpointPath, s)
	s.httpSrv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *StreamableHTTPServer) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}

// --- SSE -------------------------------------------------------------------

// SSEOption configures an SSEServer.
type SSEOption func(*SSEServer)

// SSEServer serves the MCP server over the (legacy) SSE transport.
type SSEServer struct {
	mcp             *MCPServer
	sseEndpoint     string
	messageEndpoint string

	once     sync.Once
	handler  http.Handler
	buildErr error
	httpSrv  *http.Server
}

// NewSSEServer creates an SSE server for the MCP server.
func NewSSEServer(server *MCPServer, opts ...SSEOption) *SSEServer {
	s := &SSEServer{mcp: server, sseEndpoint: "/sse", messageEndpoint: "/message"}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithSSEEndpoint sets the SSE endpoint path.
func WithSSEEndpoint(endpoint string) SSEOption {
	return func(s *SSEServer) { s.sseEndpoint = endpoint }
}

// WithMessageEndpoint sets the message endpoint path.
func WithMessageEndpoint(endpoint string) SSEOption {
	return func(s *SSEServer) { s.messageEndpoint = endpoint }
}

func (s *SSEServer) build() {
	s.once.Do(func() {
		srv, err := s.mcp.buildServer("")
		if err != nil {
			s.buildErr = err
			return
		}
		s.handler = gosdk.NewSSEHandler(func(*http.Request) *gosdk.Server { return srv }, nil)
	})
}

// ServeHTTP implements http.Handler.
func (s *SSEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.build()
	if s.buildErr != nil {
		http.Error(w, fmt.Sprintf("building server: %v", s.buildErr), http.StatusInternalServerError)
		return
	}
	s.handler.ServeHTTP(w, r)
}

// Start serves on addr until Shutdown is called.
func (s *SSEServer) Start(addr string) error {
	s.httpSrv = &http.Server{Addr: addr, Handler: s, ReadHeaderTimeout: 10 * time.Second}
	return s.httpSrv.ListenAndServe()
}

// Shutdown gracefully stops the HTTP server.
func (s *SSEServer) Shutdown(ctx context.Context) error {
	if s.httpSrv == nil {
		return nil
	}
	return s.httpSrv.Shutdown(ctx)
}
