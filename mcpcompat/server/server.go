// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package server is a drop-in compatibility shim for
// github.com/mark3labs/mcp-go/server, reimplemented on top of the official
// github.com/modelcontextprotocol/go-sdk.
//
// It presents mcp-go's MCPServer API (NewMCPServer, AddTool, AddResource,
// AddPrompt, the ServerTool/ServerResource/ServerPrompt registration units, the
// Hooks and per-session interfaces, and the stdio/SSE/Streamable-HTTP
// transports) while delegating protocol handling to a go-sdk Server. Tools,
// resources and prompts registered here are converted to their go-sdk
// equivalents and served by the SDK.
//
// # Scope and status
//
// The global registration path (AddTool/AddResource/AddPrompt served over the
// stdio and HTTP transports) is fully functional and tested. The per-session
// interfaces (SessionWithTools, SessionWithResources, SessionIdManager) and the
// Hooks type are implemented for source compatibility, and per-session tool
// overlays are stored on the session objects. Wiring those overlays into
// go-sdk's live session lifecycle so that per-session tool *dispatch* matches
// mcp-go exactly (ToolHive's vMCP projection) is the one area that needs
// integration validation against ToolHive before this package can fully replace
// mcp-go for the vMCP server; see the notes on SessionWithTools.
//
// Stability: Alpha.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// ServerOption configures an MCPServer.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type ServerOption func(*MCPServer)

// ToolHandlerFunc handles a tool call. It mirrors mcp-go's type exactly.
type ToolHandlerFunc func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)

// ResourceHandlerFunc handles a resource read.
type ResourceHandlerFunc func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error)

// ResourceTemplateHandlerFunc handles a templated resource read.
type ResourceTemplateHandlerFunc func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error)

// PromptHandlerFunc handles a prompt get.
type PromptHandlerFunc func(ctx context.Context, request mcp.GetPromptRequest) (*mcp.GetPromptResult, error)

// NotificationHandlerFunc handles a client notification.
type NotificationHandlerFunc func(ctx context.Context, notification mcp.JSONRPCNotification)

// ServerTool pairs a tool with its handler.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type ServerTool struct {
	Tool    mcp.Tool
	Handler ToolHandlerFunc
}

// ServerResource pairs a resource with its handler.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type ServerResource struct {
	Resource mcp.Resource
	Handler  ResourceHandlerFunc
}

// ServerResourceTemplate pairs a resource template with its handler.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type ServerResourceTemplate struct {
	Template mcp.ResourceTemplate
	Handler  ResourceTemplateHandlerFunc
}

// ServerPrompt pairs a prompt with its handler.
//
//nolint:revive // name intentionally matches mcp-go for drop-in compatibility.
type ServerPrompt struct {
	Prompt  mcp.Prompt
	Handler PromptHandlerFunc
}

// MCPServer is an MCP server backed by the official go-sdk. It mirrors the
// subset of mcp-go's server.MCPServer that ToolHive uses.
type MCPServer struct {
	name    string
	version string
	logger  *slog.Logger
	hooks   *Hooks

	// capability flags (informational; go-sdk infers capabilities from
	// registered features, but these are retained for API compatibility).
	toolListChanged     bool
	resourceSubscribe   bool
	resourceListChanged bool
	promptListChanged   bool
	logging             bool

	mu                sync.RWMutex
	tools             map[string]ServerTool
	resources         map[string]ServerResource
	resourceTemplates map[string]ServerResourceTemplate
	prompts           map[string]ServerPrompt

	sessions sync.Map // sessionID -> *clientSession

	// pendingReqCtx maps an in-flight request's session ID to the HTTP request
	// context, so the dispatch middleware can bridge per-request context values
	// (identity, audit BackendInfo, telemetry) into the handler context. The
	// go-sdk processes messages on a detached session goroutine and does not
	// propagate the HTTP request context the way mcp-go did; this restores it.
	pendingReqCtx sync.Map // sessionID -> context.Context
}

// setPendingRequestContext records the HTTP request context for an in-flight
// request on the given session so the dispatch middleware can bridge its values.
func (s *MCPServer) setPendingRequestContext(ctx context.Context, sessionID string) {
	s.pendingReqCtx.Store(sessionID, ctx)
}

// pendingRequestContext returns the recorded HTTP request context for sessionID.
func (s *MCPServer) pendingRequestContext(sessionID string) context.Context {
	if v, ok := s.pendingReqCtx.Load(sessionID); ok {
		return v.(context.Context)
	}
	return nil
}

// clearPendingRequestContext drops the recorded HTTP request context.
func (s *MCPServer) clearPendingRequestContext(sessionID string) {
	s.pendingReqCtx.Delete(sessionID)
}

// valueBridgeContext bridges the originating HTTP request's context values into
// a handler running on go-sdk's detached session goroutine. Its lifecycle
// (Deadline/Done/Err) comes from the embedded handler context; Value lookups
// consult the per-request HTTP context (values) FIRST, then fall back to the
// handler context.
//
// The per-request context must take precedence because go-sdk uses the
// *initialize* request's context as the whole session's context. Without
// values-first ordering, request-scoped values that the HTTP middleware chain
// re-establishes per request (audit BackendInfo, identity, telemetry) would be
// shadowed by the stale copies frozen at initialize time. go-sdk's own internal
// context keys are absent from the raw HTTP request context, so they still
// resolve via the fallback.
type valueBridgeContext struct {
	context.Context
	values context.Context
}

func (c *valueBridgeContext) Value(key any) any {
	if v := c.values.Value(key); v != nil {
		return v
	}
	return c.Context.Value(key)
}

// NewMCPServer creates a new MCP server with the given name and version.
func NewMCPServer(name, version string, opts ...ServerOption) *MCPServer {
	s := &MCPServer{
		name:              name,
		version:           version,
		tools:             make(map[string]ServerTool),
		resources:         make(map[string]ServerResource),
		resourceTemplates: make(map[string]ServerResourceTemplate),
		prompts:           make(map[string]ServerPrompt),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// WithToolCapabilities declares tool support (listChanged notifications).
func WithToolCapabilities(listChanged bool) ServerOption {
	return func(s *MCPServer) { s.toolListChanged = listChanged }
}

// WithResourceCapabilities declares resource support.
func WithResourceCapabilities(subscribe, listChanged bool) ServerOption {
	return func(s *MCPServer) {
		s.resourceSubscribe = subscribe
		s.resourceListChanged = listChanged
	}
}

// WithPromptCapabilities declares prompt support.
func WithPromptCapabilities(listChanged bool) ServerOption {
	return func(s *MCPServer) { s.promptListChanged = listChanged }
}

// WithLogging enables logging capability.
func WithLogging() ServerOption {
	return func(s *MCPServer) { s.logging = true }
}

// WithLogger sets the server logger.
func WithLogger(logger *slog.Logger) ServerOption {
	return func(s *MCPServer) { s.logger = logger }
}

// WithHooks installs lifecycle hooks.
func WithHooks(hooks *Hooks) ServerOption {
	return func(s *MCPServer) { s.hooks = hooks }
}

// AddTool registers a tool and its handler.
func (s *MCPServer) AddTool(tool mcp.Tool, handler ToolHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools[tool.Name] = ServerTool{Tool: tool, Handler: handler}
}

// AddTools registers multiple tools.
func (s *MCPServer) AddTools(tools ...ServerTool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range tools {
		s.tools[t.Tool.Name] = t
	}
}

// SetTools replaces the tool set.
func (s *MCPServer) SetTools(tools ...ServerTool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tools = make(map[string]ServerTool, len(tools))
	for _, t := range tools {
		s.tools[t.Tool.Name] = t
	}
}

// DeleteTools removes tools by name.
func (s *MCPServer) DeleteTools(names ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range names {
		delete(s.tools, n)
	}
}

// AddResource registers a resource and its handler.
func (s *MCPServer) AddResource(resource mcp.Resource, handler ResourceHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.resources[resource.URI] = ServerResource{Resource: resource, Handler: handler}
}

// AddResourceTemplate registers a resource template and its handler.
func (s *MCPServer) AddResourceTemplate(template mcp.ResourceTemplate, handler ResourceTemplateHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	name := template.Name
	s.resourceTemplates[name] = ServerResourceTemplate{Template: template, Handler: handler}
}

// AddPrompt registers a prompt and its handler.
func (s *MCPServer) AddPrompt(prompt mcp.Prompt, handler PromptHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.prompts[prompt.Name] = ServerPrompt{Prompt: prompt, Handler: handler}
}

// buildServer constructs a go-sdk Server from the globally-registered features
// (AddTool/AddResource/AddPrompt).
//
// Per-session overlays (SessionWithTools/SessionWithResources) are NOT baked in
// here: the streamable/SSE transports call this once per new client session (via
// getServer) so each session gets its own go-sdk Server, and the registration
// middleware installed by this function syncs that session's overlay tools and
// resources onto its own server once the OnRegisterSession hooks have run. This
// mirrors mcp-go, whose per-session tools were dispatched per connection.
func (s *MCPServer) buildServer(genSessionID func() string) (*gosdk.Server, error) {
	s.mu.RLock()
	tools := make(map[string]ServerTool, len(s.tools))
	for k, v := range s.tools {
		tools[k] = v
	}
	resources := make(map[string]ServerResource, len(s.resources))
	for k, v := range s.resources {
		resources[k] = v
	}
	prompts := make(map[string]ServerPrompt, len(s.prompts))
	for k, v := range s.prompts {
		prompts[k] = v
	}
	s.mu.RUnlock()

	impl := &gosdk.Implementation{Name: s.name, Version: s.version}
	// srv is referenced by the InitializedHandler and registration middleware
	// closures below; it is assigned before either can fire (both run only while
	// serving a request, long after NewServer returns).
	var srv *gosdk.Server
	opts := &gosdk.ServerOptions{
		Logger: s.logger,
		InitializedHandler: func(ctx context.Context, req *gosdk.InitializedRequest) {
			if req == nil || req.Session == nil {
				return
			}
			s.registerAndSync(ctx, req.Session, srv)
		},
	}
	// When a SessionIdManager is supplied (WithSessionIdManager), drive the SDK's
	// session-ID generation through it: mcp-go called Generate() to mint the ID,
	// which is where ToolHive's manager creates the placeholder session record
	// that the OnRegisterSession hook later promotes via CreateSession. Without
	// this the SDK would mint its own ID and CreateSession would fail to find the
	// placeholder.
	if genSessionID != nil {
		opts.GetSessionID = genSessionID
	}
	srv = gosdk.NewServer(impl, opts)

	for _, st := range tools {
		gt, err := toGoSDKTool(st.Tool)
		if err != nil {
			return nil, fmt.Errorf("converting tool %q: %w", st.Tool.Name, err)
		}
		srv.AddTool(gt, s.wrapToolHandler(st.Handler))
	}
	for _, sr := range resources {
		gr := &gosdk.Resource{}
		if err := jsonConvert(sr.Resource, gr); err != nil {
			return nil, fmt.Errorf("converting resource %q: %w", sr.Resource.URI, err)
		}
		srv.AddResource(gr, s.wrapResourceHandler(sr.Handler))
	}
	for _, sp := range prompts {
		gp := &gosdk.Prompt{}
		if err := jsonConvert(sp.Prompt, gp); err != nil {
			return nil, fmt.Errorf("converting prompt %q: %w", sp.Prompt.Name, err)
		}
		srv.AddPrompt(gp, s.wrapPromptHandler(sp.Handler))
	}

	srv.AddReceivingMiddleware(s.sessionDispatchMiddleware(srv))
	return srv, nil
}

// sessionDispatchMiddleware wires mcp-go's per-session semantics onto a go-sdk
// server: it registers the session (firing OnRegisterSession) when the client
// initializes — mcp-go fired that hook on initialize, whereas go-sdk's
// InitializedHandler only fires on the later notifications/initialized — and it
// fires the before-list/before-call hooks so ToolHive's lazy per-session tool
// injection runs before the SDK enumerates or dispatches tools.
// getServerFunc returns a getServer callback for the go-sdk HTTP/SSE handlers,
// which invoke it once per new client session. genSessionID (may be nil) is the
// session-ID generator to install on each per-session server. On a build error
// it logs and returns nil, which the go-sdk handler surfaces as an HTTP 400.
func (s *MCPServer) getServerFunc(genSessionID func() string) func(*http.Request) *gosdk.Server {
	return func(*http.Request) *gosdk.Server {
		srv, err := s.buildServer(genSessionID)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("building per-session MCP server", "error", err)
			}
			return nil
		}
		return srv
	}
}

func (s *MCPServer) sessionDispatchMiddleware(srv *gosdk.Server) gosdk.Middleware {
	return func(next gosdk.MethodHandler) gosdk.MethodHandler {
		return func(ctx context.Context, method string, req gosdk.Request) (gosdk.Result, error) {
			ss, _ := req.GetSession().(*gosdk.ServerSession)
			if ss != nil {
				ctx = s.contextWithSession(ctx, ss)
				// Bridge the originating HTTP request's context values (identity,
				// audit BackendInfo, telemetry) into the handler context.
				if reqCtx := s.pendingRequestContext(ss.ID()); reqCtx != nil {
					ctx = &valueBridgeContext{Context: ctx, values: reqCtx}
				}
			}
			// Fire the before-hooks ahead of the SDK's own handling so a
			// hook that injects per-session tools does so before the SDK
			// enumerates (tools/list) or dispatches (tools/call) them.
			switch method {
			case string(mcp.MethodToolsList):
				if s.hooks != nil {
					s.hooks.beforeListTools(ctx, nil, &mcp.ListToolsRequest{})
				}
			case string(mcp.MethodToolsCall):
				if s.hooks != nil {
					s.hooks.beforeCallTool(ctx, nil, &mcp.CallToolRequest{})
				}
			}
			res, err := next(ctx, method, req)
			if err != nil && method == string(mcp.MethodToolsCall) {
				err = translateUnknownToolError(err, req)
			}
			if err == nil && method == string(mcp.MethodInitialize) && ss != nil {
				s.registerAndSync(ctx, ss, srv)
			}
			return res, err
		}
	}
}

func (s *MCPServer) wrapToolHandler(h ToolHandlerFunc) gosdk.ToolHandler {
	return func(ctx context.Context, req *gosdk.CallToolRequest) (res *gosdk.CallToolResult, err error) {
		// mcp-go recovered panics in handlers at the transport/session layer,
		// turning them into an error response. go-sdk runs handlers on a detached
		// session goroutine with no recovery, so an unrecovered panic crashes the
		// process. Recover here to preserve mcp-go's fault isolation.
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in tool handler %q: %v", req.Params.Name, r)
			}
		}()
		ctx = s.contextWithSession(ctx, req.Session)

		var args map[string]any
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return nil, fmt.Errorf("unmarshaling arguments: %w", err)
			}
		}
		mreq := mcp.CallToolRequest{}
		mreq.Params.Name = req.Params.Name
		mreq.Params.Arguments = args

		// Note: the before-call hook fires in sessionDispatchMiddleware, ahead of
		// the SDK's dispatch, so per-session tool injection happens before the SDK
		// resolves the tool. It is intentionally not fired again here.

		mres, err := h(ctx, mreq)
		if err != nil {
			return nil, err
		}
		out := &gosdk.CallToolResult{}
		if err := jsonConvert(mres, out); err != nil {
			return nil, fmt.Errorf("converting tool result: %w", err)
		}
		return out, nil
	}
}

func (s *MCPServer) wrapResourceHandler(h ResourceHandlerFunc) gosdk.ResourceHandler {
	return func(ctx context.Context, req *gosdk.ReadResourceRequest) (res *gosdk.ReadResourceResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in resource handler %q: %v", req.Params.URI, r)
			}
		}()
		ctx = s.contextWithSession(ctx, req.Session)
		mreq := mcp.ReadResourceRequest{}
		mreq.Params.URI = req.Params.URI
		contents, err := h(ctx, mreq)
		if err != nil {
			return nil, err
		}
		out := &gosdk.ReadResourceResult{}
		if err := jsonConvert(mcp.ReadResourceResult{Contents: contents}, out); err != nil {
			return nil, fmt.Errorf("converting resource result: %w", err)
		}
		return out, nil
	}
}

func (s *MCPServer) wrapPromptHandler(h PromptHandlerFunc) gosdk.PromptHandler {
	return func(ctx context.Context, req *gosdk.GetPromptRequest) (res *gosdk.GetPromptResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in prompt handler %q: %v", req.Params.Name, r)
			}
		}()
		ctx = s.contextWithSession(ctx, req.Session)
		mreq := mcp.GetPromptRequest{}
		mreq.Params.Name = req.Params.Name
		mreq.Params.Arguments = req.Params.Arguments
		mres, err := h(ctx, mreq)
		if err != nil {
			return nil, err
		}
		out := &gosdk.GetPromptResult{}
		if err := jsonConvert(mres, out); err != nil {
			return nil, fmt.Errorf("converting prompt result: %w", err)
		}
		return out, nil
	}
}

// toGoSDKTool converts an mcp-go-shaped Tool into a go-sdk Tool. Both marshal to
// the same MCP wire JSON (including the outputSchema derived from
// RawOutputSchema), so a JSON round-trip is a faithful conversion.
//
// go-sdk's AddTool panics unless InputSchema is a non-nil object schema, whereas
// mcp-go tolerated a missing/empty schema. Normalize to the empty object schema
// ({"type":"object"}) so tools with no declared input (common in ToolHive's
// per-session vMCP projection) register cleanly, matching mcp-go's leniency.
func toGoSDKTool(t mcp.Tool) (*gosdk.Tool, error) {
	out := &gosdk.Tool{}
	if err := jsonConvert(t, out); err != nil {
		return nil, err
	}
	out.InputSchema = normalizeObjectSchema(out.InputSchema)
	return out, nil
}

// normalizeObjectSchema ensures a JSON-schema value is a non-nil object schema
// suitable for go-sdk's AddTool. A nil schema, or one whose "type" is not
// "object", is replaced with the empty object schema.
func normalizeObjectSchema(schema any) any {
	if m, ok := schema.(map[string]any); ok {
		if m["type"] == "object" {
			return m
		}
	}
	return map[string]any{"type": "object"}
}

// translateUnknownToolError rewrites go-sdk's "unknown tool" error for a
// tools/call into mcp-go's `tool %q not found` wording, so callers (and tests)
// that matched mcp-go's message keep working. The JSON-RPC code (InvalidParams)
// is preserved.
func translateUnknownToolError(err error, req gosdk.Request) error {
	var jerr *jsonrpc.Error
	if !errors.As(err, &jerr) || !strings.Contains(jerr.Message, "unknown tool") {
		return err
	}
	name := ""
	if p, ok := req.GetParams().(*gosdk.CallToolParams); ok {
		name = p.Name
	}
	return &jsonrpc.Error{Code: jerr.Code, Message: fmt.Sprintf("tool %q not found", name)}
}

// jsonConvert marshals src and unmarshals it into dst.
func jsonConvert(src, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}
