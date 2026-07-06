// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// bothAcceptMediaTypes is the Accept header value the go-sdk Streamable HTTP and
// SSE handlers require on a POST. mcp-go's server ignored Accept entirely, so
// clients such as ToolHive's tests that POST with only Content-Type set (no
// Accept) must be tolerated; the shim injects this value when either required
// media type is absent to restore that leniency.
const bothAcceptMediaTypes = "application/json, text/event-stream"

// ensureAcceptMediaTypes restores mcp-go's Accept-header leniency: the go-sdk
// handlers reject a request whose Accept header does not advertise both
// application/json and text/event-stream. When either is missing this sets the
// Accept header to advertise both so the request is accepted, matching mcp-go.
func ensureAcceptMediaTypes(r *http.Request) {
	var jsonOK, streamOK bool
	for _, value := range r.Header.Values("Accept") {
		for _, part := range strings.Split(value, ",") {
			mediaType, _, err := mime.ParseMediaType(part)
			if err != nil {
				continue
			}
			switch mediaType {
			case "application/json", "application/*", "*/*":
				jsonOK = true
			}
			switch mediaType {
			case "text/event-stream", "text/*", "*/*":
				streamOK = true
			}
		}
	}
	if !jsonOK || !streamOK {
		r.Header.Set("Accept", bothAcceptMediaTypes)
	}
}

// --- stdio -----------------------------------------------------------------

// StdioOption configures the stdio server (retained for API compatibility).
type StdioOption func(*stdioConfig)

type stdioConfig struct{}

// ServeStdio runs the MCP server over stdio until the context is done. It
// mirrors mcp-go's server.ServeStdio.
func ServeStdio(server *MCPServer, _ ...StdioOption) error {
	srv, err := server.buildServer(nil)
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
		var gen func() string
		if s.sessionIDMgr != nil {
			gen = s.sessionIDMgr.Generate
		}
		// Validate the server configuration once up-front so a bad registration
		// surfaces as a clean 500 rather than a per-request nil.
		if _, err := s.mcp.buildServer(gen); err != nil {
			s.buildErr = err
			return
		}
		// JSONResponse makes the handler reply with application/json rather than
		// text/event-stream for request/response exchanges, matching mcp-go's
		// server so callers that json.Decode the response body keep working.
		opts := &gosdk.StreamableHTTPOptions{JSONResponse: true}
		// A fresh go-sdk server per client session lets each session carry its own
		// tool/resource overlay (mcp-go's per-session projection), synced by the
		// registration middleware buildServer installs.
		s.handler = gosdk.NewStreamableHTTPHandler(s.mcp.getServerFunc(gen), opts)
	})
}

// ServeHTTP implements http.Handler.
func (s *StreamableHTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.build()
	if s.buildErr != nil {
		http.Error(w, fmt.Sprintf("building server: %v", s.buildErr), http.StatusInternalServerError)
		return
	}
	ensureAcceptMediaTypes(r)
	if s.contextFunc != nil {
		r = r.WithContext(s.contextFunc(r.Context(), r))
	}
	// Record the request context so the dispatch middleware can bridge its values
	// into the handler running on go-sdk's detached session goroutine. Keyed by
	// the client-supplied session ID; the initialize request (no session ID yet)
	// carries no per-request values that the handler needs. This POST is handled
	// synchronously (JSONResponse), so the entry is valid for the handler's whole
	// lifetime and cleared when ServeHTTP returns.
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
		s.mcp.setPendingRequestContext(r.Context(), sid)
		defer s.mcp.clearPendingRequestContext(sid)
	}
	// DELETE terminates the session. mcp-go answered 200 and drove the supplied
	// SessionIdManager's Terminate; go-sdk answers 204 and manages its own session
	// map. Rewrite the status to 200 for compatibility and forward the termination
	// to the manager so ToolHive's session storage is cleaned up in lockstep.
	if r.Method == http.MethodDelete {
		rw := &statusRewriter{ResponseWriter: w, from: http.StatusNoContent, to: http.StatusOK}
		s.handler.ServeHTTP(rw, r)
		if s.sessionIDMgr != nil {
			if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
				_, _ = s.sessionIDMgr.Terminate(sid)
			}
		}
		return
	}
	s.handler.ServeHTTP(w, r)
}

// statusRewriter is an http.ResponseWriter that rewrites a single status code on
// WriteHeader (used to translate go-sdk's 204 DELETE response to mcp-go's 200).
type statusRewriter struct {
	http.ResponseWriter
	from, to int
}

func (s *statusRewriter) WriteHeader(code int) {
	if code == s.from {
		code = s.to
	}
	s.ResponseWriter.WriteHeader(code)
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
		if _, err := s.mcp.buildServer(nil); err != nil {
			s.buildErr = err
			return
		}
		s.handler = gosdk.NewSSEHandler(s.mcp.getServerFunc(nil), nil)
	})
}

// ServeHTTP implements http.Handler.
func (s *SSEServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.build()
	if s.buildErr != nil {
		http.Error(w, fmt.Sprintf("building server: %v", s.buildErr), http.StatusInternalServerError)
		return
	}
	ensureAcceptMediaTypes(r)
	// mcp-go advertised a distinct message endpoint for client POSTs, whereas
	// go-sdk derives the endpoint it advertises in the SSE "endpoint" event from
	// the SSE (GET) request's own path plus a sessionid query. Rewrite the GET
	// request path to the configured message endpoint so the advertised POST
	// target matches mcp-go's split-path model (and any middleware mounted on the
	// message path). The stream itself is already served on this connection, so
	// the path change only affects the advertised endpoint. POSTs are dispatched
	// by sessionid and are path-independent.
	if r.Method == http.MethodGet && s.messageEndpoint != "" && r.URL.Path != s.messageEndpoint {
		r = r.Clone(r.Context())
		r.URL.Path = s.messageEndpoint
	}
	s.handler.ServeHTTP(w, r)
}

// SSEHandler returns the http.Handler for the SSE (stream) endpoint. It mirrors
// mcp-go's SSEServer.SSEHandler, allowing the endpoint to be mounted on a custom
// router.
//
// go-sdk backing and limitation: the go-sdk serves SSE and message delivery
// through a single unified handler keyed off the request method and a session
// query parameter, whereas mcp-go splits them across two paths. Both SSEHandler
// and MessageHandler therefore return the same underlying go-sdk handler; when
// mounting them on separate paths, mount both under a common base path so the
// go-sdk handler can correlate the stream and its message posts.
func (s *SSEServer) SSEHandler() http.Handler {
	return http.HandlerFunc(s.ServeHTTP)
}

// MessageHandler returns the http.Handler for the message (POST) endpoint. See
// SSEHandler for the go-sdk backing and the shared-handler limitation.
func (s *SSEServer) MessageHandler() http.Handler {
	return http.HandlerFunc(s.ServeHTTP)
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
