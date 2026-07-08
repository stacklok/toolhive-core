// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// ErrNoActiveSession is returned when an elicitation is requested outside a
// session's request context (no ClientSession in ctx). It mirrors mcp-go's
// server.ErrNoActiveSession.
var ErrNoActiveSession = errors.New("no active session")

// ErrElicitationNotSupported is returned when the session in scope does not
// support elicitation (it does not implement SessionWithElicitation, or its
// bound go-sdk ServerSession is unavailable). It mirrors mcp-go's
// server.ErrElicitationNotSupported.
var ErrElicitationNotSupported = errors.New("session does not support elicitation")

// SessionWithElicitation is a ClientSession that can send elicitation requests
// to the client. It mirrors mcp-go's server.SessionWithElicitation so callers
// that type-assert against it (as mcp-go's RequestElicitation does) keep
// working; the shim's clientSession implements it.
type SessionWithElicitation interface {
	ClientSession
	RequestElicitation(ctx context.Context, request mcp.ElicitationRequest) (*mcp.ElicitationResult, error)
}

// RequestElicitation sends an elicitation/create request to the client bound to
// the session in ctx (the session a tool/prompt/resource handler is running
// under) and returns the user's response. The client must have declared the
// elicitation capability during initialization; otherwise the go-sdk rejects
// the call with "client does not support elicitation".
//
// Under the shim's Streamable HTTP transport the server replies with
// application/json (JSONResponse is on by design so ToolHive callers that
// json.Decode the body keep working). The go-sdk therefore routes a
// server->client elicitation request made during request handling to the
// standalone SSE stream (the "" stream) rather than the request's response.
// The client MUST hold an open standalone SSE stream for the elicitation to be
// delivered and answered: configure the shim client with
// transport.WithContinuousListening() (the default is DisableStandaloneSSE:
// true, under which elicitation cannot complete). See the build() doc comment
// in transports.go.
//
// It mirrors mcp-go's server.MCPServer.RequestElicitation.
func (*MCPServer) RequestElicitation(ctx context.Context, request mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	session := ClientSessionFromContext(ctx)
	if session == nil {
		return nil, ErrNoActiveSession
	}
	es, ok := session.(SessionWithElicitation)
	if !ok {
		return nil, ErrElicitationNotSupported
	}
	if err := request.Params.Validate(); err != nil {
		// mcp-go returns this validation error unwrapped; mirror that for parity.
		return nil, err
	}
	return es.RequestElicitation(ctx, request)
}

// RequestElicitation sends an elicitation/create request to the client over the
// bound go-sdk ServerSession. It converts the mcp-go-shaped ElicitationRequest
// to the go-sdk's ElicitParams, calls ServerSession.Elicit, and converts the
// result back. If no go-sdk session is bound yet it returns
// ErrElicitationNotSupported.
//
// The go-sdk's Elicit enforces the capability gate (the client must have
// declared Elicitation at initialize), infers the mode from the params when
// unset, and validates an accepted result against the requested schema; those
// behaviors are delegated to the SDK rather than reimplemented here.
func (c *clientSession) RequestElicitation(ctx context.Context, request mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	ss := c.goSession.Load()
	if ss == nil {
		return nil, ErrElicitationNotSupported
	}
	params := &gosdk.ElicitParams{}
	if err := jsonConvert(request.Params, params); err != nil {
		return nil, fmt.Errorf("converting elicitation params: %w", err)
	}
	res, err := ss.Elicit(ctx, params)
	if err != nil {
		return nil, err
	}
	out := &mcp.ElicitationResult{}
	if err := jsonConvert(res, out); err != nil {
		return nil, fmt.Errorf("converting elicitation result: %w", err)
	}
	return out, nil
}
