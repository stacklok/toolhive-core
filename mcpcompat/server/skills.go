// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// ListSkillsHandlerFunc handles a skills/list request.
type ListSkillsHandlerFunc func(ctx context.Context, request mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error)

// GetSkillHandlerFunc handles a skills/get request. To answer a URI that names
// no skill the server serves, return a *jsonrpc.Error
// (github.com/modelcontextprotocol/go-sdk/jsonrpc) with code
// jsonrpc.CodeInvalidParams, as the extension requires; any other error is
// reported to the client as an internal error.
type GetSkillHandlerFunc func(ctx context.Context, request mcp.GetSkillRequest) (*mcp.GetSkillResult, error)

// ReadDirectoryHandlerFunc handles a resources/directory/read request. To
// answer a URI that does not exist or is not a directory, return a
// *jsonrpc.Error with code jsonrpc.CodeInvalidParams, as the extension
// requires; any other error is reported to the client as an internal error.
type ReadDirectoryHandlerFunc func(ctx context.Context, request mcp.ReadDirectoryRequest) (*mcp.ReadDirectoryResult, error)

// WithSkillsHandlers serves the Skills extension (SEP-2640): it declares
// io.modelcontextprotocol/skills in the initialize result and answers
// skills/list and skills/get with the given handlers. mcp-go has no
// equivalent. The extension requires both methods, so both handlers MUST be
// provided; a nil handler fails the server build, so the first request (or
// ServeStdio) reports it instead of the server advertising a method it cannot
// answer. The skills' files are served as ordinary resources, so the consumer
// must also declare WithResourceCapabilities, as the extension requires.
//
// The extension is declared with no settings unless WithDirectoryReadHandler
// is also given, which adds directoryRead.
//
// The handlers see the same session binding, request-context bridging and
// call gate as the standard methods, so they can authorize by caller identity.
//
// LIMITATIONS, both from go-sdk v1.8.0 serving these as custom methods, and
// both also apply to resources/directory/read:
//   - A session rehydrated on a replica other than the one that initialized it
//     (StreamableHTTPServer with a shared SessionIdManager) answers the
//     methods with HTTP 400. go-sdk's Streamable HTTP transport checks a
//     request's method against the server's custom methods only when its own
//     handler connected the session; rehydration connects through the public
//     Server.Connect. Sessions served by the replica that initialized them,
//     stateless servers and the stdio bridge are unaffected.
//   - On a 2026-07-28 session the results carry neither resultType nor the
//     list-caching attributes (ttlMs, cacheScope): go-sdk stamps those only on
//     its own result types.
func WithSkillsHandlers(list ListSkillsHandlerFunc, get GetSkillHandlerFunc) ServerOption {
	return func(s *MCPServer) {
		s.skillsDeclared = true
		s.listSkills = list
		s.getSkill = get
	}
}

// WithDirectoryReadHandler serves the Skills extension's optional
// resources/directory/read method with h and declares directoryRead: true in
// the extension's settings. It requires WithSkillsHandlers, since the setting
// lives in that extension's declaration; without it, or with a nil h, the
// server build fails.
//
// A server declaring directoryRead must answer the method for every directory
// within the skill namespaces it serves as individual files; the method may
// also serve any other directory resource, under any scheme.
func WithDirectoryReadHandler(h ReadDirectoryHandlerFunc) ServerOption {
	return func(s *MCPServer) {
		s.directoryReadDeclared = true
		s.readDirectory = h
	}
}

// The go-sdk wire forms of the extension's messages. go-sdk's custom methods
// need params and results that implement its sealed Params and Result
// interfaces, which only embedding ParamsBase/ResultBase achieves; the shim
// converts between these and the mcp-go-shaped types via JSON round-trips, as
// it does for every other method. The client package declares the same forms
// for sending.
type (
	sdkListSkillsParams struct {
		gosdk.ParamsBase
		Cursor string `json:"cursor,omitempty"`
	}
	sdkListSkillsResult struct {
		gosdk.ResultBase
		Skills     []mcp.Skill `json:"skills"`
		NextCursor string      `json:"nextCursor,omitempty"`
	}
	sdkGetSkillParams struct {
		gosdk.ParamsBase
		URI string `json:"uri"`
	}
	sdkGetSkillResult struct {
		gosdk.ResultBase
		Skill mcp.Skill `json:"skill"`
	}
	sdkReadDirectoryParams struct {
		gosdk.ParamsBase
		URI    string `json:"uri"`
		Cursor string `json:"cursor,omitempty"`
	}
	sdkReadDirectoryResult struct {
		gosdk.ResultBase
		Resources  []mcp.Resource `json:"resources"`
		NextCursor string         `json:"nextCursor,omitempty"`
	}
)

// skillsExtension returns the settings the Skills extension is advertised
// with, and whether it is declared at all. A misconfigured extension (see
// validateSkills) is not advertised, so the stdio bridge, which has no build
// step to fail, never declares methods it will not answer.
func (s *MCPServer) skillsExtension() (map[string]any, bool) {
	if !s.skillsDeclared || s.validateSkills() != nil {
		return nil, false
	}
	if s.directoryReadDeclared {
		return map[string]any{mcp.SkillsSettingDirectoryRead: true}, true
	}
	return map[string]any{}, true
}

// validateSkills reports a misconfigured Skills extension: a missing handler,
// or directory reads without the extension that declares them.
func (s *MCPServer) validateSkills() error {
	if s.directoryReadDeclared && (!s.skillsDeclared || s.readDirectory == nil) {
		return errors.New("WithDirectoryReadHandler: requires WithSkillsHandlers and a non-nil handler")
	}
	if s.skillsDeclared && (s.listSkills == nil || s.getSkill == nil) {
		return errors.New("WithSkillsHandlers: both the skills/list and skills/get handlers are required")
	}
	return nil
}

// registerSkills registers the extension's methods on srv when it was
// declared via WithSkillsHandlers.
func (s *MCPServer) registerSkills(srv *gosdk.Server) error {
	if err := s.validateSkills(); err != nil {
		return err
	}
	if !s.skillsDeclared {
		return nil
	}
	if err := gosdk.AddReceivingCustomMethod(srv, string(mcp.MethodSkillsList),
		adaptSkillsMethod[sdkListSkillsParams, *sdkListSkillsParams, sdkListSkillsResult](
			mcp.MethodSkillsList, s.listSkills)); err != nil {
		return fmt.Errorf("registering %s: %w", mcp.MethodSkillsList, err)
	}
	if err := gosdk.AddReceivingCustomMethod(srv, string(mcp.MethodSkillsGet),
		adaptSkillsMethod[sdkGetSkillParams, *sdkGetSkillParams, sdkGetSkillResult](
			mcp.MethodSkillsGet, s.getSkill)); err != nil {
		return fmt.Errorf("registering %s: %w", mcp.MethodSkillsGet, err)
	}
	if s.directoryReadDeclared {
		if err := gosdk.AddReceivingCustomMethod(srv, string(mcp.MethodResourcesDirectoryRead),
			adaptSkillsMethod[sdkReadDirectoryParams, *sdkReadDirectoryParams, sdkReadDirectoryResult](
				mcp.MethodResourcesDirectoryRead, s.readDirectory)); err != nil {
			return fmt.Errorf("registering %s: %w", mcp.MethodResourcesDirectoryRead, err)
		}
	}
	return nil
}

// adaptSkillsMethod adapts an extension method handler, written against the
// mcp-go-shaped request and result types, to go-sdk's custom method handler
// over the wire form P (params) and R (result). Like wrapCompletionHandler, it
// recovers handler panics (go-sdk runs handlers on a detached goroutine with
// no recovery) and converts via JSON round-trips.
func adaptSkillsMethod[PT any, P interface {
	*PT
	gosdk.Params
}, RT, MReq, MRes any](
	method mcp.MCPMethod, handler func(context.Context, MReq) (*MRes, error),
) func(context.Context, *gosdk.ServerSession, P) (*RT, error) {
	return func(ctx context.Context, _ *gosdk.ServerSession, p P) (res *RT, err error) {
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in %s handler: %v", method, r)
			}
		}()
		var mreq MReq
		envelope := struct {
			Method string `json:"method"`
			Params P      `json:"params,omitempty"`
		}{Method: string(method), Params: p}
		if err := jsonConvert(envelope, &mreq); err != nil {
			return nil, fmt.Errorf("converting %s request: %w", method, err)
		}
		mres, err := handler(ctx, mreq)
		if err != nil {
			return nil, err
		}
		if mres == nil {
			return nil, errNoResult(method)
		}
		out := new(RT)
		if err := jsonConvert(mres, out); err != nil {
			return nil, fmt.Errorf("converting %s result: %w", method, err)
		}
		return out, nil
	}
}

// errNoResult reports a handler that returned neither a result nor an error,
// which no method of the extension allows.
func errNoResult(method mcp.MCPMethod) error {
	return fmt.Errorf("%s handler returned no result", method)
}

// dispatchSkills answers the extension's methods on the stdio HandleMessage
// path, which dispatches without a go-sdk server. It reports false when method
// is not one of them or the server does not serve it.
func (s *MCPServer) dispatchSkills(
	ctx context.Context, method string, id any, message json.RawMessage,
) (mcp.JSONRPCMessage, bool) {
	if s.validateSkills() != nil {
		return nil, false
	}
	switch {
	case method == string(mcp.MethodSkillsList) && s.skillsDeclared:
		return handleStdioSkillsMethod(ctx, mcp.MethodSkillsList, id, message, s.listSkills), true
	case method == string(mcp.MethodSkillsGet) && s.skillsDeclared:
		return handleStdioSkillsMethod(ctx, mcp.MethodSkillsGet, id, message, s.getSkill), true
	case method == string(mcp.MethodResourcesDirectoryRead) && s.directoryReadDeclared:
		return handleStdioSkillsMethod(ctx, mcp.MethodResourcesDirectoryRead, id, message, s.readDirectory), true
	default:
		return nil, false
	}
}

// handleStdioSkillsMethod decodes message into the handler's request type and
// calls it, answering as adaptSkillsMethod does on the go-sdk path: a handler
// panic or a nil result is an internal error, a *jsonrpc.Error keeps its code
// and message, and any other error is an internal error carrying the error
// text. Unlike the bridge's other handlers, it recovers panics, so a
// panicking skills handler fails the request on both serving paths alike.
func handleStdioSkillsMethod[MReq, MRes any](
	ctx context.Context, method mcp.MCPMethod, id any, message json.RawMessage,
	handler func(context.Context, MReq) (*MRes, error),
) (resp mcp.JSONRPCMessage) {
	var req MReq
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_PARAMS, err.Error())
	}
	defer func() {
		if r := recover(); r != nil {
			resp = errorResponse(id, mcp.INTERNAL_ERROR, fmt.Sprintf("panic recovered in %s handler: %v", method, r))
		}
	}()
	res, err := handler(ctx, req)
	if err == nil && res == nil {
		err = errNoResult(method)
	}
	if err != nil {
		var wireErr *jsonrpc.Error
		if errors.As(err, &wireErr) {
			return errorResponse(id, int(wireErr.Code), wireErr.Message)
		}
		return errorResponse(id, mcp.INTERNAL_ERROR, err.Error())
	}
	return successResponse(id, res)
}
