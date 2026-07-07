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

	// rehydrated holds sessions that were created on another replica and
	// reconstructed here (see the rehydration path in ServeHTTP). Guarded by
	// rehydratedMu. These use a custom StreamableServerTransport (SSE responses)
	// rather than the go-sdk StreamableHTTPHandler, because the handler 404s any
	// session ID it did not create itself.
	rehydratedMu sync.Mutex
	rehydrated   map[string]*rehydratedSession
}

// rehydratedSession is a session reconstructed from cross-replica shared state
// (validated via the SessionIdManager) and served by a per-session go-sdk
// StreamableServerTransport.
type rehydratedSession struct {
	transport *gosdk.StreamableServerTransport
	session   *gosdk.ServerSession
}

// defaultRehydratedProtocolVersion is the MCP protocol version seeded into a
// rehydrated session when the request carries no MCP-Protocol-Version header. It
// matches a widely-supported spec revision; clients that resumed a session send
// the negotiated version header, which takes precedence.
const defaultRehydratedProtocolVersion = "2025-06-18"

// mcpProtocolVersionHeader is the HTTP header carrying the negotiated MCP
// protocol version on subsequent (post-initialize) requests.
const mcpProtocolVersionHeader = "MCP-Protocol-Version"

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
		sid := r.Header.Get("Mcp-Session-Id")
		s.deleteRehydrated(sid)
		s.mcp.forgetSession(sid)
		rw := &statusRewriter{ResponseWriter: w, from: http.StatusNoContent, to: http.StatusOK}
		s.handler.ServeHTTP(rw, r)
		if s.sessionIDMgr != nil && sid != "" {
			_, _ = s.sessionIDMgr.Terminate(sid)
		}
		return
	}

	// Cross-replica routing: a request carrying a session ID that was NOT
	// initialized on this instance (its initialize handshake happened on another
	// replica) cannot be served by the go-sdk StreamableHTTPHandler, which 404s
	// any session ID it did not create. Validate it against the shared
	// SessionIdManager and, if valid, rehydrate a local session for it.
	if sid := r.Header.Get("Mcp-Session-Id"); sid != "" && s.sessionIDMgr != nil && !s.mcp.isLocalSession(sid) {
		s.serveRehydrated(w, r, sid)
		return
	}

	s.handler.ServeHTTP(w, r)
}

// serveRehydrated routes a request for a session created on another replica.
// It validates the session ID against the shared SessionIdManager and serves it
// through a locally-reconstructed session, matching mcp-go's behavior where any
// replica sharing the manager's backing store accepts the session.
func (s *StreamableHTTPServer) serveRehydrated(w http.ResponseWriter, r *http.Request, sid string) {
	// Validate on EVERY request (as mcp-go does), not just on cache miss. This is
	// what implements lazy eviction: a session terminated on another replica is
	// marked terminated in the shared store, and the next request here must reject
	// it and drop any locally-cached reconstruction rather than serving it.
	isTerminated, err := s.sessionIDMgr.Validate(sid)
	if err != nil {
		s.deleteRehydrated(sid)
		http.Error(w, "Invalid session ID", http.StatusNotFound)
		return
	}
	if isTerminated {
		s.deleteRehydrated(sid)
		http.Error(w, "Session terminated", http.StatusNotFound)
		return
	}

	rt := s.getRehydrated(sid)
	if rt == nil {
		rt, err = s.rehydrate(r, sid)
		if err != nil {
			if s.mcp.logger != nil {
				s.mcp.logger.Error("rehydrating cross-replica session", "session_id", sid, "error", err)
			}
			http.Error(w, "failed to rehydrate session", http.StatusInternalServerError)
			return
		}
	}
	rt.transport.ServeHTTP(w, r)
}

// getRehydrated returns the reconstructed session for sid, or nil.
func (s *StreamableHTTPServer) getRehydrated(sid string) *rehydratedSession {
	s.rehydratedMu.Lock()
	defer s.rehydratedMu.Unlock()
	return s.rehydrated[sid]
}

// deleteRehydrated closes and drops a reconstructed session, if present.
func (s *StreamableHTTPServer) deleteRehydrated(sid string) {
	if sid == "" {
		return
	}
	s.rehydratedMu.Lock()
	rt := s.rehydrated[sid]
	delete(s.rehydrated, sid)
	s.rehydratedMu.Unlock()
	if rt != nil {
		_ = rt.session.Close()
	}
}

// rehydrate reconstructs a session that was created on another replica: it
// builds a fresh per-session go-sdk server (carrying this instance's tools plus
// the before-hook lazy-injection path), connects a StreamableServerTransport
// seeded with an already-initialized state (so it accepts non-initialize
// requests and can perform server->client calls such as elicitation), binds the
// clientSession so the before-hooks can reconcile the per-session overlay, and
// caches it keyed by session ID.
func (s *StreamableHTTPServer) rehydrate(r *http.Request, sid string) (*rehydratedSession, error) {
	s.rehydratedMu.Lock()
	defer s.rehydratedMu.Unlock()
	// Double-check under the lock in case a concurrent request rehydrated first.
	if rt, ok := s.rehydrated[sid]; ok {
		return rt, nil
	}

	srv, err := s.mcp.buildServer(nil)
	if err != nil {
		return nil, err
	}

	protocolVersion := r.Header.Get(mcpProtocolVersionHeader)
	if protocolVersion == "" {
		protocolVersion = defaultRehydratedProtocolVersion
	}

	transport := &gosdk.StreamableServerTransport{SessionID: sid, Stateless: false}
	state := &gosdk.ServerSessionState{
		InitializeParams: &gosdk.InitializeParams{
			ProtocolVersion: protocolVersion,
			// Seed the elicitation capability so a server->client elicitation on a
			// rehydrated session passes go-sdk's capability gate. A stateless
			// session cannot do this; this is what proves the rehydrated session is
			// a full, stateful session.
			Capabilities: &gosdk.ClientCapabilities{Elicitation: &gosdk.ElicitationCapabilities{}},
		},
		InitializedParams: &gosdk.InitializedParams{},
		LogLevel:          "info",
	}
	// Detach from the request context: this session outlives the request that
	// created it (subsequent requests on other HTTP connections reuse it).
	session, err := srv.Connect(context.WithoutCancel(r.Context()), transport, &gosdk.ServerSessionOptions{State: state})
	if err != nil {
		return nil, err
	}
	s.mcp.bindRehydratedSession(sid, session, srv)

	rt := &rehydratedSession{transport: transport, session: session}
	if s.rehydrated == nil {
		s.rehydrated = make(map[string]*rehydratedSession)
	}
	s.rehydrated[sid] = rt
	return rt, nil
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
