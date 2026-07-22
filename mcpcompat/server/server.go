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
// The global registration path (AddTool/AddResource/AddResourceTemplate/
// AddPrompt served over the stdio and HTTP transports), the completion handler
// (WithCompletionHandler) and the resource subscribe/unsubscribe handlers
// (WithSubscribeHandlers) are functional and tested. The per-session interfaces
// (SessionWithTools, SessionWithResources, SessionWithResourceTemplates,
// SessionWithPrompts, SessionWithElicitation, SessionIdManager) and the Hooks
// type are implemented and wired: per-session
// tool/resource/resource-template/prompt overlays set via SetSessionTools/
// SetSessionResources/SetSessionResourceTemplates/SetSessionPrompts are
// reconciled onto the session's live go-sdk server (syncSessionTools/
// syncSessionResources/syncSessionResourceTemplates/syncSessionPrompts), and
// the before-list/before-call hooks fire ahead of SDK dispatch so ToolHive's
// lazy per-session tool injection runs first.
// Cross-replica session rehydration (Validate-driven lazy eviction) and the
// Streamable HTTP transports are functional. See the notes on SessionWithTools
// for the live-overlay reconciliation details.
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

// schemaTypeObject is the empty object JSON schema ("type":"object") that
// go-sdk's AddTool requires a tool input schema to carry. schemaTypeKey is the
// JSON-schema "type" property name.
const (
	schemaTypeKey    = "type"
	schemaTypeObject = "object"
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

// CompletionHandlerFunc handles a completion/complete request. It mirrors the
// handler shape ToolHive's vMCP aggregator installs via WithCompletionHandler.
type CompletionHandlerFunc func(ctx context.Context, request mcp.CompleteRequest) (*mcp.CompleteResult, error)

// SubscribeHandlerFunc handles a resources/subscribe or resources/unsubscribe
// request for a single resource URI.
type SubscribeHandlerFunc func(ctx context.Context, uri string) error

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

	// Capability flags set via WithToolCapabilities/WithResourceCapabilities/
	// WithPromptCapabilities. These are wired into the go-sdk ServerOptions in
	// buildServer (see ServerOptions.Capabilities): go-sdk otherwise infers
	// capabilities only from registered features, so a server that registers
	// tools per-session AFTER initialize (ToolHive's vMCP projection) would
	// advertise no tools capability at initialize time. The *Declared flags
	// record that the corresponding With*Capabilities option was invoked (mcp-go
	// advertises the capability whenever the option is used, regardless of the
	// sub-flag value); the sub-flags carry the ListChanged/Subscribe settings.
	toolsDeclared       bool
	toolListChanged     bool
	resourcesDeclared   bool
	resourceSubscribe   bool
	resourceListChanged bool
	promptsDeclared     bool
	promptListChanged   bool
	logging             bool

	// pageSize is the maximum number of items returned in a single page for
	// list methods (tools/list, resources/list, prompts/list). go-sdk defaults
	// to DefaultPageSize (1000) when zero; mcp-go returned everything in one
	// page. Setting it via WithPageSize lets aggregators with >1000 tools raise
	// (or otherwise configure) the page size so tools/list is not paginated.
	pageSize int

	// completionHandler, when set via WithCompletionHandler, answers
	// completion/complete requests. go-sdk auto-advertises the completions
	// capability when ServerOptions.CompletionHandler is non-nil.
	completionHandler CompletionHandlerFunc

	// subscribeHandler/unsubscribeHandler, when both set via
	// WithSubscribeHandlers, answer resources/subscribe and
	// resources/unsubscribe. go-sdk PANICS if only one of the two is set, so the
	// option requires both together (see WithSubscribeHandlers).
	subscribeHandler   SubscribeHandlerFunc
	unsubscribeHandler SubscribeHandlerFunc

	mu                sync.RWMutex
	tools             map[string]ServerTool
	resources         map[string]ServerResource
	resourceTemplates map[string]ServerResourceTemplate
	prompts           map[string]ServerPrompt

	// sessions holds every clientSession created on this instance, keyed by
	// sessionID. It is the registry consulted by contextWithSession / sessionFor
	// and SendNotificationToAllClients.
	//
	// KNOWN GAP (issue #156, finding 5): entries are only removed on the DELETE
	// path and on a Validate-failure/termination path (see forgetSession). A
	// session whose client vanishes, or that the go-sdk handler closes internally
	// (e.g. on a transport error), never has forgetSession called, so its entry
	// leaks for the process lifetime and SendNotificationToAllClients iterates
	// corpses. A reaping mechanism (e.g. a periodic sweep that drops entries
	// whose go-sdk ServerSession is closed, or a go-sdk close callback wired into
	// forgetSession) is needed; this is lower priority and tracked separately.
	// Do not over-engineer here without the upstream close hook.
	sessions sync.Map // sessionID -> *clientSession

	// localSessions records the IDs of sessions that were initialized on THIS
	// server instance (i.e. the initialize handshake was handled here by the
	// go-sdk StreamableHTTPHandler). The Streamable HTTP transport uses it to
	// decide, for a request carrying an existing session ID, whether the session
	// is local (route to the go-sdk handler, which owns its session map) or was
	// created on another replica (rehydrate; see StreamableHTTPServer). Populated
	// in registerAndSync (which only fires on this instance's initialize path).
	//
	// Shares the same unbounded-growth gap as sessions above (finding 5):
	// entries are dropped only via forgetSession (DELETE / Validate-termination),
	// not on a vanished client or an internal go-sdk close.
	localSessions sync.Map // sessionID -> struct{}

	// pendingReqCtx bridges per-request context values (identity, audit
	// BackendInfo, telemetry) into handlers running on go-sdk's session
	// goroutine. go-sdk does NOT propagate the per-POST HTTP request's context
	// into the receiving-middleware path for subsequent requests on an existing
	// session: messages published from servePOST are handled on the connection
	// goroutine whose context was captured at session-creation (initialize)
	// time, so request-scoped values added via WithHTTPContextFunc would
	// otherwise be lost.
	//
	// To avoid the per-session race where two concurrent POSTs on the same
	// session clobber each other's context (issue #156, item U3), entries are
	// keyed by a per-POST nonce rather than the session ID. ServeHTTP generates
	// a nonce, stores the request context under it, and sets it as the
	// X-MCP-Req-Nonce header; the dispatch middleware reads that header off the
	// per-request RequestExtra (req.GetExtra().Header, which go-sdk populates
	// from the POST's headers) to look up the correct context. Entries are
	// cleared when ServeHTTP returns.
	pendingReqCtx sync.Map // nonce -> context.Context
}

// reqNonceHeader is the HTTP header carrying the per-POST nonce that
// correlates a request's context (stored by ServeHTTP) with the handler
// invocation on go-sdk's session goroutine.
const reqNonceHeader = "X-MCP-Req-Nonce"

// setPendingRequestContext records the HTTP request context for an in-flight
// POST under the given nonce so the dispatch middleware can bridge its values.
func (s *MCPServer) setPendingRequestContext(ctx context.Context, nonce string) {
	s.pendingReqCtx.Store(nonce, ctx)
}

// pendingRequestContext returns the recorded HTTP request context for nonce.
func (s *MCPServer) pendingRequestContext(nonce string) context.Context {
	if v, ok := s.pendingReqCtx.Load(nonce); ok {
		return v.(context.Context)
	}
	return nil
}

// clearPendingRequestContext drops the recorded HTTP request context.
func (s *MCPServer) clearPendingRequestContext(nonce string) {
	s.pendingReqCtx.Delete(nonce)
}

// valueBridgeContext bridges the originating HTTP request's context values into
// a handler running on go-sdk's session goroutine. Its lifecycle
// (Deadline/Done/Err) comes from the embedded handler context; Value lookups
// consult the per-request HTTP context (values) FIRST, then fall back to the
// handler context.
//
// The per-request context takes precedence so request-scoped values that the
// HTTP middleware chain re-establishes per request (audit BackendInfo,
// identity, telemetry) are visible to the handler rather than shadowed by the
// copies frozen onto the session context at initialize time.
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

// serverCapabilities translates the mcp-go capability flags declared via
// WithToolCapabilities/WithResourceCapabilities/WithPromptCapabilities (and
// WithLogging) into a go-sdk ServerCapabilities value for ServerOptions. A
// capability declared via its option is advertised with its sub-flags
// (ListChanged/Subscribe); an undeclared capability is left nil so go-sdk's
// inference from registered features applies. See buildServer for why this
// mapping is required (per-session tool registration after initialize).
func (s *MCPServer) serverCapabilities() *gosdk.ServerCapabilities {
	caps := &gosdk.ServerCapabilities{}
	if s.toolsDeclared {
		caps.Tools = &gosdk.ToolCapabilities{ListChanged: s.toolListChanged}
	}
	if s.resourcesDeclared {
		caps.Resources = &gosdk.ResourceCapabilities{
			Subscribe:   s.resourceSubscribe,
			ListChanged: s.resourceListChanged,
		}
	}
	if s.promptsDeclared {
		caps.Prompts = &gosdk.PromptCapabilities{ListChanged: s.promptListChanged}
	}
	if s.logging {
		caps.Logging = &gosdk.LoggingCapabilities{}
	}
	return caps
}

// WithToolCapabilities declares tool support (listChanged notifications).
//
// Invoking this option advertises the tools capability in the initialize result
// regardless of whether any tools are registered at initialize time: vMCP
// registers tools per-session AFTER initialize, so without this the capability
// would be absent (go-sdk otherwise infers capabilities from registered
// features).
func WithToolCapabilities(listChanged bool) ServerOption {
	return func(s *MCPServer) { s.toolsDeclared = true; s.toolListChanged = listChanged }
}

// WithResourceCapabilities declares resource support.
//
// Invoking this option advertises the resources capability in the initialize
// result regardless of whether any resources are registered at initialize time
// (see WithToolCapabilities for the per-session registration rationale).
func WithResourceCapabilities(subscribe, listChanged bool) ServerOption {
	return func(s *MCPServer) {
		s.resourcesDeclared = true
		s.resourceSubscribe = subscribe
		s.resourceListChanged = listChanged
	}
}

// WithPromptCapabilities declares prompt support.
//
// Invoking this option advertises the prompts capability in the initialize
// result regardless of whether any prompts are registered at initialize time
// (see WithToolCapabilities for the per-session registration rationale).
func WithPromptCapabilities(listChanged bool) ServerOption {
	return func(s *MCPServer) { s.promptsDeclared = true; s.promptListChanged = listChanged }
}

// WithLogging enables logging capability.
func WithLogging() ServerOption {
	return func(s *MCPServer) { s.logging = true }
}

// WithCompletionHandler installs a handler for completion/complete requests.
// Setting it makes go-sdk auto-advertise the completions capability at
// initialize time (ServerOptions.CompletionHandler), so spec-compliant clients
// that gate completion on the capability will issue completion requests.
//
// The handler's context carries the ClientSession (bridged by the shim's
// dispatch middleware), so it can be recovered with ClientSessionFromContext
// for per-session completion.
func WithCompletionHandler(h CompletionHandlerFunc) ServerOption {
	return func(s *MCPServer) { s.completionHandler = h }
}

// WithSubscribeHandlers installs the resources/subscribe and
// resources/unsubscribe handlers. Both MUST be provided together: go-sdk panics
// during server construction if only one of ServerOptions.SubscribeHandler /
// UnsubscribeHandler is set, so passing a nil subscribe or unsubscribe is a
// programming error. If either is nil the option is a no-op (neither handler is
// wired), leaving go-sdk to reject subscribe/unsubscribe with -32601.
//
// This does NOT change the advertised resource capabilities: the consumer must
// still call WithResourceCapabilities(true, ...) to advertise subscribe support
// at initialize time.
func WithSubscribeHandlers(subscribe, unsubscribe SubscribeHandlerFunc) ServerOption {
	return func(s *MCPServer) {
		if subscribe == nil || unsubscribe == nil {
			return
		}
		s.subscribeHandler = subscribe
		s.unsubscribeHandler = unsubscribe
	}
}

// WithLogger sets the server logger.
func WithLogger(logger *slog.Logger) ServerOption {
	return func(s *MCPServer) { s.logger = logger }
}

// WithHooks installs lifecycle hooks.
func WithHooks(hooks *Hooks) ServerOption {
	return func(s *MCPServer) { s.hooks = hooks }
}

// WithPageSize configures the server's list pagination page size (the maximum
// number of items returned in a single tools/list, resources/list, or
// prompts/list response). A value of 0 leaves go-sdk's default
// (DefaultPageSize=1000) in place. mcp-go returned all items in one page;
// aggregators with more than 1000 tools must raise this to avoid pagination.
func WithPageSize(n int) ServerOption {
	return func(s *MCPServer) {
		if n < 0 {
			n = 0
		}
		s.pageSize = n
	}
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
// (AddTool/AddResource/AddResourceTemplate/AddPrompt) and wires the optional
// completion (WithCompletionHandler) and resource subscribe/unsubscribe
// (WithSubscribeHandlers) handlers.
//
// Per-session overlays (SessionWithTools/SessionWithResources/
// SessionWithResourceTemplates/SessionWithPrompts) are NOT baked in here: the
// streamable/SSE transports call
// this once per new client session (via getServer) so each session gets its own
// go-sdk Server, and the registration middleware installed by this function
// syncs that session's overlay tools, resources and prompts onto its own server
// once the OnRegisterSession hooks have run. This mirrors mcp-go, whose
// per-session tools were dispatched per connection.
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
	resourceTemplates := make(map[string]ServerResourceTemplate, len(s.resourceTemplates))
	for k, v := range s.resourceTemplates {
		resourceTemplates[k] = v
	}
	s.mu.RUnlock()

	impl := &gosdk.Implementation{Name: s.name, Version: s.version}
	// srv is referenced by the InitializedHandler and registration middleware
	// closures below; it is assigned before either can fire (both run only while
	// serving a request, long after NewServer returns).
	var srv *gosdk.Server
	opts := &gosdk.ServerOptions{
		Logger: s.logger,
		// PageSize configures list pagination. A zero value leaves go-sdk's
		// DefaultPageSize (1000) in place, preserving the pre-existing behavior
		// for callers that do not set WithPageSize.
		PageSize: s.pageSize,
		// KeepAlive is deliberately NOT set. go-sdk's KeepAlive is an active ping
		// request that evicts JSON-mode sessions without a connected standalone
		// SSE stream (incompatible with JSONResponse + JSON-only clients); the
		// shim's passive keep-alive lives in keepalive.go instead.
		InitializedHandler: func(ctx context.Context, req *gosdk.InitializedRequest) {
			if req == nil || req.Session == nil {
				return
			}
			s.registerAndSync(ctx, req.Session, srv)
		},
	}
	// Map the mcp-go capability flags to go-sdk's ServerCapabilities. go-sdk
	// otherwise infers capabilities solely from registered features (see
	// (*Server).capabilities): a server that registers tools per-session AFTER
	// initialize — ToolHive's vMCP projection, where go-sdk has zero tools at
	// initialize time — would advertise no tools capability, and spec-compliant
	// clients that gate tools/list on capabilities.tools would see no tools.
	// WithToolCapabilities/WithResourceCapabilities/WithPromptCapabilities
	// declare those capabilities up front, mirroring mcp-go. The non-deprecated
	// ServerOptions.Capabilities field is used (HasTools/HasResources/HasPrompts
	// exist but are deprecated). Setting a capability to a non-nil value forces
	// it to be advertised regardless of registered features; a nil entry leaves
	// go-sdk's inference (from registered features) in place.
	opts.Capabilities = s.serverCapabilities()
	// Wire the completion handler. go-sdk auto-advertises the completions
	// capability when ServerOptions.CompletionHandler is non-nil; the shim
	// converts the go-sdk request/result to and from the mcp-go-shaped types.
	if s.completionHandler != nil {
		opts.CompletionHandler = s.wrapCompletionHandler()
	}
	// Wire the resource subscribe/unsubscribe handlers (no-op unless both were
	// set via WithSubscribeHandlers).
	s.wireSubscribeHandlers(opts)
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

	if err := s.registerGlobalFeatures(srv, tools, resources, prompts, resourceTemplates); err != nil {
		return nil, err
	}

	srv.AddReceivingMiddleware(s.sessionDispatchMiddleware(srv))
	return srv, nil
}

// registerGlobalFeatures registers the globally-declared tools, resources,
// prompts and resource templates onto srv. go-sdk's AddTool/AddResource/
// AddPrompt/AddResourceTemplate panic on a malformed schema (e.g. a $ref or
// non-object type) or an invalid/non-absolute URI template, and buildServer runs
// inside sync.Once.Do in the transports' build(): a panic here would mark Once
// done while buildErr stays nil and handler stays nil, so every subsequent
// request nil-panics forever. addGlobalTool/addGlobalResourceTemplate recover
// such panics and convert them into an error so they flow into buildErr and
// properly poison the Once (issue #156, finding 2). This mirrors the per-session
// recover in addSessionTool (session.go).
func (s *MCPServer) registerGlobalFeatures(
	srv *gosdk.Server,
	tools map[string]ServerTool,
	resources map[string]ServerResource,
	prompts map[string]ServerPrompt,
	resourceTemplates map[string]ServerResourceTemplate,
) error {
	for _, st := range tools {
		gt, err := toGoSDKTool(st.Tool)
		if err != nil {
			return fmt.Errorf("converting tool %q: %w", st.Tool.Name, err)
		}
		if err := addGlobalTool(srv, gt, s.wrapToolHandler(st.Handler), st.Tool.Name); err != nil {
			return err
		}
	}
	for _, sr := range resources {
		gr := &gosdk.Resource{}
		if err := jsonConvert(sr.Resource, gr); err != nil {
			return fmt.Errorf("converting resource %q: %w", sr.Resource.URI, err)
		}
		srv.AddResource(gr, s.wrapResourceHandler(sr.Handler))
	}
	for _, sp := range prompts {
		gp := &gosdk.Prompt{}
		if err := jsonConvert(sp.Prompt, gp); err != nil {
			return fmt.Errorf("converting prompt %q: %w", sp.Prompt.Name, err)
		}
		srv.AddPrompt(gp, s.wrapPromptHandler(sp.Handler))
	}
	for _, srt := range resourceTemplates {
		grt := &gosdk.ResourceTemplate{}
		if err := jsonConvert(srt.Template, grt); err != nil {
			return fmt.Errorf("converting resource template %q: %w", srt.Template.Name, err)
		}
		h := s.wrapResourceHandler(ResourceHandlerFunc(srt.Handler))
		if err := addGlobalResourceTemplate(srv, grt, h, srt.Template.Name); err != nil {
			return err
		}
	}
	return nil
}

// addGlobalResourceTemplate registers a globally-declared resource template on a
// go-sdk server, recovering the panic go-sdk's AddResourceTemplate raises when
// the URI template is invalid or not absolute. It converts the panic into a
// returned error so buildServer surfaces a clean construction-time error
// (flowing into buildErr/sync.Once) rather than poisoning the once. Mirrors
// addGlobalTool.
func addGlobalResourceTemplate(
	srv *gosdk.Server, grt *gosdk.ResourceTemplate, h gosdk.ResourceHandler, name string,
) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf(
				"registering global resource template %q: go-sdk AddResourceTemplate rejected its URI template: %v",
				name, r)
		}
	}()
	srv.AddResourceTemplate(grt, h)
	return nil
}

// wireSubscribeHandlers installs the resource subscribe/unsubscribe handlers on
// the go-sdk ServerOptions. WithSubscribeHandlers only sets both together
// (go-sdk panics if exactly one of these is set), so they are wired as a pair
// here; if either is unset this is a no-op. The default WithResourceCapabilities
// is left untouched: advertising subscribe support is the consumer's opt-in.
func (s *MCPServer) wireSubscribeHandlers(opts *gosdk.ServerOptions) {
	if s.subscribeHandler == nil || s.unsubscribeHandler == nil {
		return
	}
	subscribe, unsubscribe := s.subscribeHandler, s.unsubscribeHandler
	opts.SubscribeHandler = func(ctx context.Context, req *gosdk.SubscribeRequest) error {
		uri := ""
		if req != nil && req.Params != nil {
			uri = req.Params.URI
		}
		return subscribe(ctx, uri)
	}
	opts.UnsubscribeHandler = func(ctx context.Context, req *gosdk.UnsubscribeRequest) error {
		uri := ""
		if req != nil && req.Params != nil {
			uri = req.Params.URI
		}
		return unsubscribe(ctx, uri)
	}
}

// wrapCompletionHandler adapts the shim's CompletionHandlerFunc to go-sdk's
// ServerOptions.CompletionHandler. It recovers handler panics (go-sdk runs
// handlers on a detached goroutine with no recovery) and converts the go-sdk
// request/result to and from the mcp-go-shaped completion types via JSON
// round-trips. The session is already bridged into ctx by the dispatch
// middleware, so no extra session plumbing is needed here.
func (s *MCPServer) wrapCompletionHandler() func(context.Context, *gosdk.CompleteRequest) (*gosdk.CompleteResult, error) {
	return func(ctx context.Context, req *gosdk.CompleteRequest) (res *gosdk.CompleteResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in completion handler: %v", r)
			}
		}()
		mreq := mcp.CompleteRequest{}
		if req != nil && req.Params != nil {
			if err := jsonConvert(req.Params, &mreq.Params); err != nil {
				return nil, fmt.Errorf("converting completion request: %w", err)
			}
		}
		mres, err := s.completionHandler(ctx, mreq)
		if err != nil {
			return nil, err
		}
		out := &gosdk.CompleteResult{}
		if err := jsonConvert(mres, out); err != nil {
			return nil, fmt.Errorf("converting completion result: %w", err)
		}
		return out, nil
	}
}

// addGlobalTool registers a globally-declared tool on a go-sdk server, recovering
// the panic go-sdk's AddTool raises when a tool's input schema is non-nil but not
// top-level type:"object" (e.g. $ref, oneOf, boolean). It converts the panic
// into a returned error so buildServer surfaces a clean construction-time error
// (flowing into buildErr/sync.Once) rather than poisoning the server's once with
// a nil-handler-nil-error state. Mirrors addSessionTool (session.go), which
// recovers and skips for per-session overlays.
func addGlobalTool(srv *gosdk.Server, gt *gosdk.Tool, h gosdk.ToolHandler, name string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("registering global tool %q: go-sdk AddTool rejected its input schema: %v", name, r)
		}
	}()
	srv.AddTool(gt, h)
	return nil
}

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

// sessionDispatchMiddleware wires mcp-go's per-session semantics onto a go-sdk
// server: it registers the session (firing OnRegisterSession) when the client
// initializes — mcp-go fired that hook on initialize, whereas go-sdk's
// InitializedHandler only fires on the later notifications/initialized — and it
// fires the before-list/before-call hooks so ToolHive's lazy per-session tool
// injection runs before the SDK enumerates or dispatches tools.
func (s *MCPServer) sessionDispatchMiddleware(srv *gosdk.Server) gosdk.Middleware {
	return func(next gosdk.MethodHandler) gosdk.MethodHandler {
		return func(ctx context.Context, method string, req gosdk.Request) (gosdk.Result, error) {
			ss, _ := req.GetSession().(*gosdk.ServerSession)
			if ss != nil {
				ctx = s.contextWithSession(ctx, ss)
			}
			// Bridge the originating HTTP request's context values (identity,
			// audit BackendInfo, telemetry) into the handler context. go-sdk
			// does not propagate the per-POST request context into the handler
			// for existing sessions, so ServeHTTP stored it keyed by a per-POST
			// nonce (X-MCP-Req-Nonce). The nonce is read off the per-request
			// RequestExtra.Header — which go-sdk populates from the POST's
			// headers — so concurrent POSTs on the same session each resolve
			// their OWN context (issue #156, item U3: per-request, not per
			// session).
			if re := req.GetExtra(); re != nil {
				if nonce := re.Header.Get(reqNonceHeader); nonce != "" {
					if reqCtx := s.pendingRequestContext(nonce); reqCtx != nil {
						ctx = &valueBridgeContext{Context: ctx, values: reqCtx}
					}
				}
			}
			// Fire the before-hooks ahead of the SDK's own handling so a
			// hook that injects per-session tools does so before the SDK
			// enumerates (tools/list) or dispatches (tools/call) them. The
			// hook's request object is populated from req.GetParams(); see
			// fireBeforeHooks for the extraction and fallback behavior.
			s.fireBeforeHooks(ctx, method, req)
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

// fireBeforeHooks fires the before-list-tools / before-call-tool hooks ahead of
// the SDK's own handling so a hook that injects per-session tools does so before
// the SDK enumerates (tools/list) or dispatches (tools/call) them.
//
// The hook's request object is populated from req.GetParams() so a hook that
// reads the tool name/args/cursor (any future hook) sees the actual request
// rather than an empty value, matching mcp-go (whose hooks fired with the parsed
// request). The go-sdk hands the params via req.GetParams(): a
// *CallToolParamsRaw for tools/call (carrying Name and raw Arguments) and a
// *ListToolsParams for tools/list (carrying Cursor). If extraction fails (batch,
// unexpected type), the hook receives the empty request and a Debug log is
// emitted — dispatch is never broken by a hook-parameter extraction failure.
func (s *MCPServer) fireBeforeHooks(ctx context.Context, method string, req gosdk.Request) {
	if s.hooks == nil {
		return
	}
	switch method {
	case string(mcp.MethodToolsList):
		listReq := &mcp.ListToolsRequest{}
		if p, ok := req.GetParams().(*gosdk.ListToolsParams); ok && p != nil {
			listReq.Params.Cursor = mcp.Cursor(p.Cursor)
		} else if s.logger != nil {
			s.logger.Debug("before-list-tools hook: params not *ListToolsParams; hook receives empty request",
				"method", method)
		}
		s.hooks.beforeListTools(ctx, nil, listReq)
	case string(mcp.MethodToolsCall):
		callReq := &mcp.CallToolRequest{}
		if p, ok := req.GetParams().(*gosdk.CallToolParamsRaw); ok && p != nil {
			callReq.Params.Name = p.Name
			if len(p.Arguments) > 0 {
				var args map[string]any
				if err := json.Unmarshal(p.Arguments, &args); err != nil {
					if s.logger != nil {
						s.logger.Debug("before-call-tool hook: unmarshaling arguments failed; hook receives name only",
							"tool", p.Name, "error", err)
					}
				} else {
					callReq.Params.Arguments = args
				}
			}
		} else if s.logger != nil {
			s.logger.Debug("before-call-tool hook: params not *CallToolParamsRaw; hook receives empty request",
				"method", method)
		}
		s.hooks.beforeCallTool(ctx, nil, callReq)
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
		// Preserve the request _meta so ToolHive can propagate metadata through
		// vMCP to backends. go-sdk's Meta is map[string]any; mcp-go's *Meta has a
		// custom (un)marshaler, so convert via JSON.
		if len(req.Params.Meta) > 0 {
			meta := &mcp.Meta{}
			if err := jsonConvert(req.Params.Meta, meta); err != nil {
				return nil, fmt.Errorf("converting call meta: %w", err)
			}
			mreq.Params.Meta = meta
		}

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
// mcp-go passed RawInputSchema through verbatim, tolerating a missing/empty
// schema. go-sdk's AddTool panics unless InputSchema is non-nil (see
// normalizeObjectSchema), so a nil/empty schema is normalized to the empty
// object schema ({"type":"object"}). All other schemas pass through verbatim,
// matching mcp-go's behavior; go-sdk's AddTool may still panic on a non-object
// schema, which the per-session registration path recovers from (see
// normalizeObjectSchema and MCPServer.addSessionTool).
func toGoSDKTool(t mcp.Tool) (*gosdk.Tool, error) {
	out := &gosdk.Tool{}
	if err := jsonConvert(t, out); err != nil {
		return nil, err
	}
	out.InputSchema = normalizeObjectSchema(out.InputSchema)
	return out, nil
}

// normalizeObjectSchema ensures a tool input schema is suitable for go-sdk's
// AddTool, which panics on a nil InputSchema and (v1.6.1) unless the schema's
// top-level "type" is literally "object". The following are normalized to
// {"type":"object"} (preserving any existing fields): a nil schema, an empty
// map, an empty string, a map whose "type" is the empty string (the value
// mcp-go's ToolInputSchema marshals to when no type is declared), and a map
// with NO "type" key (or type:"") that DOES carry "properties" or "required" —
// a spec-loose but common shape ({"properties":...}) that mcp-go served
// verbatim and callable. Forcing type:"object" here makes such schemas callable
// under go-sdk, matching mcp-go. Truly non-object schemas ($ref, oneOf, a
// boolean schema, type:"string", type:["object","null"], etc.) pass through
// verbatim; go-sdk's AddTool will panic on them at registration time, which the
// registration paths recover from (addGlobalTool for globals surfaces a clean
// construction error; addSessionTool skips the offending per-session tool).
func normalizeObjectSchema(schema any) any {
	switch s := schema.(type) {
	case nil:
		return map[string]any{schemaTypeKey: schemaTypeObject}
	case map[string]any:
		if len(s) == 0 {
			return map[string]any{schemaTypeKey: schemaTypeObject}
		}
		// mcp-go's ToolInputSchema always marshals a "type" field, even when
		// unset (it serializes as ""). An empty type string is the sentinel for
		// "no schema declared"; normalize it to "object" so AddTool accepts the
		// tool (matching mcp-go's leniency for tools with no declared input).
		// A missing type key with properties/required is a spec-loose but common
		// object shape ({"properties":...}) that mcp-go served verbatim and
		// callable; add type:"object" so go-sdk's AddTool accepts it. A missing
		// type key WITHOUT properties/required (e.g. {$ref}, {oneOf}, {title})
		// passes through verbatim — it is not a "no schema declared" sentinel.
		// A non-string type value (e.g. ["object","null"]) also passes through.
		t, hasType := s[schemaTypeKey]
		typeStr, typeIsStr := t.(string)
		if hasType && typeIsStr && typeStr == "" {
			// Empty-string type: mcp-go's "no schema declared" sentinel.
			if _, hasProps := s["properties"]; hasProps {
				return withTypeObject(s)
			}
			if _, hasReq := s["required"]; hasReq {
				return withTypeObject(s)
			}
			return map[string]any{schemaTypeKey: schemaTypeObject}
		}
		if !hasType {
			// No type key: only normalize if it looks like an object schema.
			if _, hasProps := s["properties"]; hasProps {
				return withTypeObject(s)
			}
			if _, hasReq := s["required"]; hasReq {
				return withTypeObject(s)
			}
		}
		return s
	case string:
		if s == "" {
			return map[string]any{schemaTypeKey: schemaTypeObject}
		}
		return s
	default:
		return s
	}
}

// withTypeObject returns a copy of s with the top-level "type" set to "object",
// preserving all other fields. Used for spec-loose object schemas whose type
// was omitted or empty.
func withTypeObject(s map[string]any) map[string]any {
	cpy := make(map[string]any, len(s)+1)
	for k, v := range s {
		cpy[k] = v
	}
	cpy[schemaTypeKey] = schemaTypeObject
	return cpy
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
	if p, ok := req.GetParams().(*gosdk.CallToolParamsRaw); ok && p != nil {
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
