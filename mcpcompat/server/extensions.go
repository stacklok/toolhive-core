// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/stacklok/toolhive-core/mcpcompat/internal/rawmsg"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// CustomMethodHandlerFunc handles a custom (non-standard) JSON-RPC request,
// such as a method an MCP extension defines (for example skills/list).
//
// params is the request's params object exactly as the client sent it,
// including any _meta member, or nil when the request carried no params. The
// returned result must be a JSON object; nil stands for the empty object. The
// shim does not interpret either value, so a handler can proxy a request to
// another MCP server unchanged.
//
// To answer with a specific JSON-RPC error code, return a
// *jsonrpc.Error (github.com/modelcontextprotocol/go-sdk/jsonrpc); any other
// error is reported to the client as an internal error.
type CustomMethodHandlerFunc func(ctx context.Context, params json.RawMessage) (json.RawMessage, error)

// WithExtension declares an MCP extension in the initialize result, under
// capabilities.extensions[name] with the given settings. A nil settings map is
// advertised as the empty object, as the extensions capability requires.
// Declaring the same name twice keeps the later settings.
//
// Declaring an extension does not serve its methods: register each with
// WithCustomMethod. The settings map is copied, so the caller may reuse it.
func WithExtension(name string, settings map[string]any) ServerOption {
	return func(s *MCPServer) {
		if s.extensions == nil {
			s.extensions = make(map[string]map[string]any)
		}
		s.extensions[name] = maps.Clone(settings)
	}
}

// WithCustomMethod registers handler for the custom JSON-RPC method named
// method, such as an extension's skills/list. Custom methods run through the
// same session binding, request-context bridging and call gate as the standard
// methods, so the handler sees the caller's identity in ctx.
//
// method must not name a standard MCP method and handler must not be nil;
// either mistake fails the server build, so the first request (or ServeStdio)
// reports it rather than the method silently answering method-not-found.
// Registering the same method twice keeps the later handler.
//
// LIMITATION: a session rehydrated on a replica other than the one that
// initialized it (StreamableHTTPServer with a shared SessionIdManager) answers
// custom methods with HTTP 400. go-sdk v1.8.0's Streamable HTTP transport
// checks a request's method against the server's custom methods only when its
// own handler connected the session, and rehydration connects through the
// public Server.Connect. Sessions served by the replica that initialized them,
// stateless servers and the stdio bridge are unaffected.
func WithCustomMethod(method string, handler CustomMethodHandlerFunc) ServerOption {
	return func(s *MCPServer) {
		if s.customMethods == nil {
			s.customMethods = make(map[string]CustomMethodHandlerFunc)
		}
		s.customMethods[method] = handler
	}
}

// addExtensions advertises the extensions declared via WithExtension on caps.
// Each per-session server gets its own copy of the settings so go-sdk, which
// requires settings to be left unmodified after AddExtension, never shares a
// map across servers.
func (s *MCPServer) addExtensions(caps *gosdk.ServerCapabilities) {
	for name, settings := range s.extensions {
		caps.AddExtension(name, maps.Clone(settings))
	}
}

// registerCustomMethods registers the methods declared via WithCustomMethod on
// srv. go-sdk refuses a method that shadows a standard one; that error, and a
// nil handler, are returned so buildServer fails loudly.
func (s *MCPServer) registerCustomMethods(srv *gosdk.Server) error {
	for method, handler := range s.customMethods {
		if handler == nil {
			return fmt.Errorf("custom method %q has a nil handler", method)
		}
		if err := gosdk.AddReceivingCustomMethod(srv, method, wrapCustomMethod(handler)); err != nil {
			return fmt.Errorf("registering custom method %q: %w", method, err)
		}
	}
	return nil
}

// wrapCustomMethod adapts a CustomMethodHandlerFunc to go-sdk's typed custom
// method handler, carrying params and result as undecoded JSON objects.
func wrapCustomMethod(
	h CustomMethodHandlerFunc,
) func(context.Context, *gosdk.ServerSession, *rawmsg.Params) (*rawmsg.Result, error) {
	return func(ctx context.Context, _ *gosdk.ServerSession, p *rawmsg.Params) (*rawmsg.Result, error) {
		params, err := customParams(p)
		if err != nil {
			return nil, err
		}
		out, err := h(ctx, params)
		if err != nil {
			return nil, err
		}
		res, err := rawmsg.NewResult(out)
		if err != nil {
			return nil, fmt.Errorf("custom method result: %w", err)
		}
		return res, nil
	}
}

// customParams returns the request params handed to a custom method handler:
// nil when the request carried none, otherwise the object as received.
func customParams(p *rawmsg.Params) (json.RawMessage, error) {
	if p == nil {
		return nil, nil
	}
	return p.Raw()
}

// handleCustomMethod answers a custom method on the stdio HandleMessage path,
// which dispatches without a go-sdk server. It reports false when method is
// not a registered custom method.
func (s *MCPServer) handleCustomMethod(
	ctx context.Context, method string, id any, message json.RawMessage,
) (mcp.JSONRPCMessage, bool) {
	handler, ok := s.customMethods[method]
	if !ok || handler == nil {
		return nil, false
	}
	var req struct {
		Params json.RawMessage `json:"params"`
	}
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_PARAMS, err.Error()), true
	}
	if string(req.Params) == "null" {
		req.Params = nil
	}
	out, err := handler(ctx, req.Params)
	if err != nil {
		// Mirror go-sdk: a *jsonrpc.Error keeps its code and message, any other
		// error is an internal error carrying the error text.
		var wireErr *jsonrpc.Error
		if errors.As(err, &wireErr) {
			return errorResponse(id, int(wireErr.Code), wireErr.Message), true
		}
		return errorResponse(id, mcp.INTERNAL_ERROR, err.Error()), true
	}
	if len(out) == 0 {
		out = json.RawMessage("{}")
	}
	return successResponse(id, out), true
}
