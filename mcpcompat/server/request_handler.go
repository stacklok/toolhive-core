// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"fmt"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// WithContext stores the given ClientSession in the returned context so that
// handlers (and ClientSessionFromContext) can recover it. It mirrors mcp-go's
// server.MCPServer.WithContext, which ToolHive uses to associate a session with
// a request context (e.g. for per-session tool injection).
func (*MCPServer) WithContext(ctx context.Context, session ClientSession) context.Context {
	return context.WithValue(ctx, sessionContextKey{}, session)
}

// HandleMessage processes a single incoming JSON-RPC message and returns the
// appropriate JSON-RPC response (or nil for notifications and server-directed
// responses). It mirrors mcp-go's server.MCPServer.HandleMessage.
//
// go-sdk backing and limitation: the go-sdk drives its own JSON-RPC loop over a
// Transport and does not expose a public "handle one raw message" entrypoint.
// This shim therefore dispatches the message directly against the tools,
// resources, prompts and their handlers registered on this MCPServer — the same
// registration state the go-sdk server is built from — so behavior matches
// mcp-go for the methods ToolHive exercises: initialize, ping, tools/list,
// tools/call, resources/list, resources/templates/list, resources/read,
// prompts/list and prompts/get, plus notifications (which return nil).
// Capability-gated extras that ToolHive does not use over this path (logging
// setLevel, subscribe/unsubscribe, completion, tasks) return METHOD_NOT_FOUND.
func (s *MCPServer) HandleMessage(ctx context.Context, message json.RawMessage) mcp.JSONRPCMessage {
	var base struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
		ID      any    `json:"id,omitempty"`
		Result  any    `json:"result,omitempty"`
	}
	if err := json.Unmarshal(message, &base); err != nil {
		return errorResponse(nil, mcp.PARSE_ERROR, "Failed to parse message")
	}
	if base.JSONRPC != mcp.JSONRPC_VERSION {
		return errorResponse(base.ID, mcp.INVALID_REQUEST, "Invalid JSON-RPC version")
	}
	// Notifications (no id) are handled and produce no response.
	if base.ID == nil {
		return nil
	}
	// A message carrying a result is a response to a server-initiated request.
	if base.Result != nil {
		return nil
	}
	return s.dispatch(ctx, base.Method, base.ID, message)
}

//nolint:gocyclo // faithful 1:1 mirror of mcp-go's method dispatch switch.
func (s *MCPServer) dispatch(ctx context.Context, method string, id any, message json.RawMessage) mcp.JSONRPCMessage {
	switch method {
	case string(mcp.MethodInitialize):
		return successResponse(id, s.handleInitialize())
	case string(mcp.MethodPing):
		return successResponse(id, mcp.EmptyResult{})
	case string(mcp.MethodToolsList):
		return successResponse(id, s.handleListTools())
	case string(mcp.MethodToolsCall):
		return s.handleToolCall(ctx, id, message)
	case string(mcp.MethodResourcesList):
		return successResponse(id, s.handleListResources())
	case string(mcp.MethodResourcesTemplatesList):
		return successResponse(id, s.handleListResourceTemplates())
	case string(mcp.MethodResourcesRead):
		return s.handleReadResource(ctx, id, message)
	case string(mcp.MethodPromptsList):
		return successResponse(id, s.handleListPrompts())
	case string(mcp.MethodPromptsGet):
		return s.handleGetPrompt(ctx, id, message)
	default:
		return errorResponse(id, mcp.METHOD_NOT_FOUND, fmt.Sprintf("Method %s not found", method))
	}
}

func (s *MCPServer) handleInitialize() mcp.InitializeResult {
	return mcp.InitializeResult{
		ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		ServerInfo:      mcp.Implementation{Name: s.name, Version: s.version},
		Capabilities:    s.buildCapabilities(),
	}
}

// buildCapabilities derives a ServerCapabilities value from the registered
// features and declared capability flags.
func (s *MCPServer) buildCapabilities() mcp.ServerCapabilities {
	s.mu.RLock()
	nTools := len(s.tools)
	nResources := len(s.resources) + len(s.resourceTemplates)
	nPrompts := len(s.prompts)
	s.mu.RUnlock()

	const listChangedKey = "listChanged"
	caps := map[string]any{}
	if nTools > 0 || s.toolListChanged {
		caps["tools"] = map[string]any{listChangedKey: s.toolListChanged}
	}
	if nResources > 0 || s.resourceListChanged || s.resourceSubscribe {
		caps["resources"] = map[string]any{
			listChangedKey: s.resourceListChanged,
			"subscribe":    s.resourceSubscribe,
		}
	}
	if nPrompts > 0 || s.promptListChanged {
		caps["prompts"] = map[string]any{listChangedKey: s.promptListChanged}
	}
	if s.logging {
		caps["logging"] = map[string]any{}
	}

	var out mcp.ServerCapabilities
	// jsonConvert cannot fail for these plain maps.
	_ = jsonConvert(caps, &out)
	return out
}

func (s *MCPServer) handleListTools() mcp.ListToolsResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := mcp.ListToolsResult{Tools: make([]mcp.Tool, 0, len(s.tools))}
	for _, st := range s.tools {
		result.Tools = append(result.Tools, st.Tool)
	}
	return result
}

func (s *MCPServer) handleToolCall(ctx context.Context, id any, message json.RawMessage) mcp.JSONRPCMessage {
	var req mcp.CallToolRequest
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_REQUEST, err.Error())
	}
	s.mu.RLock()
	st, ok := s.tools[req.Params.Name]
	s.mu.RUnlock()
	if !ok {
		return errorResponse(id, mcp.INVALID_PARAMS, fmt.Sprintf("tool %q not found", req.Params.Name))
	}
	res, err := st.Handler(ctx, req)
	if err != nil {
		return errorResponse(id, mcp.INTERNAL_ERROR, err.Error())
	}
	return successResponse(id, res)
}

func (s *MCPServer) handleListResources() mcp.ListResourcesResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := mcp.ListResourcesResult{Resources: make([]mcp.Resource, 0, len(s.resources))}
	for _, sr := range s.resources {
		result.Resources = append(result.Resources, sr.Resource)
	}
	return result
}

func (s *MCPServer) handleListResourceTemplates() mcp.ListResourceTemplatesResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := mcp.ListResourceTemplatesResult{
		ResourceTemplates: make([]mcp.ResourceTemplate, 0, len(s.resourceTemplates)),
	}
	for _, sr := range s.resourceTemplates {
		result.ResourceTemplates = append(result.ResourceTemplates, sr.Template)
	}
	return result
}

func (s *MCPServer) handleReadResource(ctx context.Context, id any, message json.RawMessage) mcp.JSONRPCMessage {
	var req mcp.ReadResourceRequest
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_REQUEST, err.Error())
	}
	s.mu.RLock()
	sr, ok := s.resources[req.Params.URI]
	s.mu.RUnlock()
	if !ok {
		return errorResponse(id, mcp.RESOURCE_NOT_FOUND, fmt.Sprintf("resource %q not found", req.Params.URI))
	}
	contents, err := sr.Handler(ctx, req)
	if err != nil {
		return errorResponse(id, mcp.INTERNAL_ERROR, err.Error())
	}
	return successResponse(id, mcp.ReadResourceResult{Contents: contents})
}

func (s *MCPServer) handleListPrompts() mcp.ListPromptsResult {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := mcp.ListPromptsResult{Prompts: make([]mcp.Prompt, 0, len(s.prompts))}
	for _, sp := range s.prompts {
		result.Prompts = append(result.Prompts, sp.Prompt)
	}
	return result
}

func (s *MCPServer) handleGetPrompt(ctx context.Context, id any, message json.RawMessage) mcp.JSONRPCMessage {
	var req mcp.GetPromptRequest
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_REQUEST, err.Error())
	}
	s.mu.RLock()
	sp, ok := s.prompts[req.Params.Name]
	s.mu.RUnlock()
	if !ok {
		return errorResponse(id, mcp.INVALID_PARAMS, fmt.Sprintf("prompt %q not found", req.Params.Name))
	}
	res, err := sp.Handler(ctx, req)
	if err != nil {
		return errorResponse(id, mcp.INTERNAL_ERROR, err.Error())
	}
	return successResponse(id, res)
}

// successResponse builds a JSON-RPC success response mirroring mcp-go.
func successResponse(id, result any) mcp.JSONRPCMessage {
	return mcp.NewJSONRPCResultResponse(mcp.NewRequestId(id), result)
}

// errorResponse builds a JSON-RPC error response mirroring mcp-go.
func errorResponse(id any, code int, message string) mcp.JSONRPCMessage {
	return mcp.JSONRPCError{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      mcp.NewRequestId(id),
		Error:   mcp.NewJSONRPCErrorDetails(code, message, nil),
	}
}
