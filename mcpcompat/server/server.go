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
	"fmt"
	"log/slog"
	"sync"

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

// buildServer constructs a go-sdk Server from the registered features, merging
// in any per-session tool/resource overlays for the given session (sessionID
// may be empty for the global server).
func (s *MCPServer) buildServer(sessionID string) (*gosdk.Server, error) {
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

	if sessionID != "" {
		if cs, ok := s.sessions.Load(sessionID); ok {
			sess := cs.(*clientSession)
			for k, v := range sess.GetSessionTools() {
				tools[k] = v
			}
			for k, v := range sess.GetSessionResources() {
				resources[k] = v
			}
		}
	}

	impl := &gosdk.Implementation{Name: s.name, Version: s.version}
	srv := gosdk.NewServer(impl, &gosdk.ServerOptions{
		Logger:             s.logger,
		InitializedHandler: s.onInitialized,
	})

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
	return srv, nil
}

func (s *MCPServer) wrapToolHandler(h ToolHandlerFunc) gosdk.ToolHandler {
	return func(ctx context.Context, req *gosdk.CallToolRequest) (*gosdk.CallToolResult, error) {
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

		if s.hooks != nil {
			s.hooks.beforeCallTool(ctx, req.Params.Name, &mreq)
		}

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
	return func(ctx context.Context, req *gosdk.ReadResourceRequest) (*gosdk.ReadResourceResult, error) {
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
	return func(ctx context.Context, req *gosdk.GetPromptRequest) (*gosdk.GetPromptResult, error) {
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
func toGoSDKTool(t mcp.Tool) (*gosdk.Tool, error) {
	out := &gosdk.Tool{}
	if err := jsonConvert(t, out); err != nil {
		return nil, err
	}
	return out, nil
}

// jsonConvert marshals src and unmarshals it into dst.
func jsonConvert(src, dst any) error {
	b, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, dst)
}
