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

// WithSkillsHandlers serves the Skills extension (SEP-2640): it declares
// io.modelcontextprotocol/skills in the initialize result and answers
// skills/list and skills/get with the given handlers. mcp-go has no
// equivalent. The extension requires both methods, so both handlers MUST be
// provided; a nil handler fails the server build, so the first request (or
// ServeStdio) reports it instead of the server advertising a method it cannot
// answer. The skills' files are served as ordinary resources, so the consumer
// must also declare WithResourceCapabilities, as the extension requires.
//
// The extension is declared with no settings: resources/directory/read is not
// served, so directoryRead is never advertised.
//
// The handlers see the same session binding, request-context bridging and
// call gate as the standard methods, so they can authorize by caller identity.
//
// LIMITATIONS, both from go-sdk v1.8.0 serving these as custom methods:
//   - A session rehydrated on a replica other than the one that initialized it
//     (StreamableHTTPServer with a shared SessionIdManager) answers both
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

// The go-sdk wire forms of the skills messages. go-sdk's custom methods need
// params and results that implement its sealed Params and Result interfaces,
// which only embedding ParamsBase/ResultBase achieves; the shim converts
// between these and the mcp-go-shaped types via JSON round-trips, as it does
// for every other method. The client package declares the same forms for
// sending.
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
)

// skillsExtension returns the settings the Skills extension is advertised
// with, and whether it is declared at all.
func (s *MCPServer) skillsExtension() (map[string]any, bool) {
	if !s.skillsDeclared {
		return nil, false
	}
	return map[string]any{}, true
}

// registerSkills registers skills/list and skills/get on srv when the
// extension was declared via WithSkillsHandlers.
func (s *MCPServer) registerSkills(srv *gosdk.Server) error {
	if !s.skillsDeclared {
		return nil
	}
	if s.listSkills == nil || s.getSkill == nil {
		return errors.New("WithSkillsHandlers: both the skills/list and skills/get handlers are required")
	}
	if err := gosdk.AddReceivingCustomMethod(srv, string(mcp.MethodSkillsList), s.wrapListSkills()); err != nil {
		return fmt.Errorf("registering %s: %w", mcp.MethodSkillsList, err)
	}
	if err := gosdk.AddReceivingCustomMethod(srv, string(mcp.MethodSkillsGet), s.wrapGetSkill()); err != nil {
		return fmt.Errorf("registering %s: %w", mcp.MethodSkillsGet, err)
	}
	return nil
}

// wrapListSkills adapts the skills/list handler to go-sdk. Like
// wrapCompletionHandler, it recovers handler panics (go-sdk runs handlers on a
// detached goroutine with no recovery) and converts via JSON round-trips.
func (s *MCPServer) wrapListSkills() func(
	context.Context, *gosdk.ServerSession, *sdkListSkillsParams,
) (*sdkListSkillsResult, error) {
	return func(ctx context.Context, _ *gosdk.ServerSession, p *sdkListSkillsParams) (res *sdkListSkillsResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in skills/list handler: %v", r)
			}
		}()
		mreq := mcp.ListSkillsRequest{}
		mreq.Method = string(mcp.MethodSkillsList)
		if p != nil {
			if err := jsonConvert(p, &mreq.Params); err != nil {
				return nil, fmt.Errorf("converting skills/list request: %w", err)
			}
		}
		mres, err := s.listSkills(ctx, mreq)
		if err != nil {
			return nil, err
		}
		out := &sdkListSkillsResult{}
		if err := jsonConvert(mres, out); err != nil {
			return nil, fmt.Errorf("converting skills/list result: %w", err)
		}
		return out, nil
	}
}

// wrapGetSkill adapts the skills/get handler to go-sdk; see wrapListSkills.
func (s *MCPServer) wrapGetSkill() func(
	context.Context, *gosdk.ServerSession, *sdkGetSkillParams,
) (*sdkGetSkillResult, error) {
	return func(ctx context.Context, _ *gosdk.ServerSession, p *sdkGetSkillParams) (res *sdkGetSkillResult, err error) {
		defer func() {
			if r := recover(); r != nil {
				res, err = nil, fmt.Errorf("panic recovered in skills/get handler: %v", r)
			}
		}()
		mreq := mcp.GetSkillRequest{}
		mreq.Method = string(mcp.MethodSkillsGet)
		if p != nil {
			if err := jsonConvert(p, &mreq.Params); err != nil {
				return nil, fmt.Errorf("converting skills/get request: %w", err)
			}
		}
		mres, err := s.getSkill(ctx, mreq)
		if err != nil {
			return nil, err
		}
		out := &sdkGetSkillResult{}
		if err := jsonConvert(mres, out); err != nil {
			return nil, fmt.Errorf("converting skills/get result: %w", err)
		}
		return out, nil
	}
}

// handleListSkills answers skills/list on the stdio HandleMessage path.
func (s *MCPServer) handleListSkills(ctx context.Context, id any, message json.RawMessage) mcp.JSONRPCMessage {
	if s.listSkills == nil {
		return errorResponse(id, mcp.METHOD_NOT_FOUND, fmt.Sprintf("Method %s not found", mcp.MethodSkillsList))
	}
	var req mcp.ListSkillsRequest
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_PARAMS, err.Error())
	}
	res, err := s.listSkills(ctx, req)
	if err != nil {
		return skillsErrorResponse(id, err)
	}
	return successResponse(id, res)
}

// handleGetSkill answers skills/get on the stdio HandleMessage path.
func (s *MCPServer) handleGetSkill(ctx context.Context, id any, message json.RawMessage) mcp.JSONRPCMessage {
	if s.getSkill == nil {
		return errorResponse(id, mcp.METHOD_NOT_FOUND, fmt.Sprintf("Method %s not found", mcp.MethodSkillsGet))
	}
	var req mcp.GetSkillRequest
	if err := json.Unmarshal(message, &req); err != nil {
		return errorResponse(id, mcp.INVALID_PARAMS, err.Error())
	}
	res, err := s.getSkill(ctx, req)
	if err != nil {
		return skillsErrorResponse(id, err)
	}
	return successResponse(id, res)
}

// skillsErrorResponse mirrors go-sdk's error mapping on the stdio path: a
// *jsonrpc.Error keeps its code and message, any other error is an internal
// error carrying the error text.
func skillsErrorResponse(id any, err error) mcp.JSONRPCMessage {
	var wireErr *jsonrpc.Error
	if errors.As(err, &wireErr) {
		return errorResponse(id, int(wireErr.Code), wireErr.Message)
	}
	return errorResponse(id, mcp.INTERNAL_ERROR, err.Error())
}
