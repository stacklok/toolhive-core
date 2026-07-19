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

// ErrSamplingNotSupported is returned when the session in scope does not
// support sampling (it does not implement SessionWithSampling, or its bound
// go-sdk ServerSession is unavailable). It mirrors mcp-go's
// server.RequestSampling error string ("session does not support sampling").
var ErrSamplingNotSupported = errors.New("session does not support sampling")

// SessionWithSampling is a ClientSession that can send sampling
// (sampling/createMessage) requests to the client. It mirrors mcp-go's
// server.SessionWithSampling so callers that type-assert against it (as
// mcp-go's RequestSampling does) keep working; the shim's clientSession
// implements it.
type SessionWithSampling interface {
	ClientSession
	RequestSampling(ctx context.Context, request mcp.CreateMessageRequest) (*mcp.CreateMessageResult, error)
}

// Compile-time assertion that the concrete session implements SessionWithSampling.
var _ SessionWithSampling = (*clientSession)(nil)

// RequestSampling sends a sampling/createMessage request to the client bound to
// the session in ctx (the session a tool/prompt/resource handler is running
// under) and returns the sampled message. The client must have declared the
// sampling capability during initialization; otherwise the go-sdk rejects the
// call.
//
// Under the shim's Streamable HTTP transport the server replies with
// application/json (JSONResponse is on by design), so the go-sdk routes a
// server->client sampling request made during request handling to the
// standalone SSE stream rather than the request's response. The client MUST
// hold an open standalone SSE stream for the sampling request to be delivered
// and answered: configure the shim client with
// transport.WithContinuousListening(). This is the same delivery contract as
// elicitation; see RequestElicitation and the build() doc comment in
// transports.go.
//
// It mirrors mcp-go's server.MCPServer.RequestSampling.
func (*MCPServer) RequestSampling(
	ctx context.Context, request mcp.CreateMessageRequest,
) (*mcp.CreateMessageResult, error) {
	session := ClientSessionFromContext(ctx)
	if session == nil {
		return nil, ErrNoActiveSession
	}
	ss, ok := session.(SessionWithSampling)
	if !ok {
		return nil, ErrSamplingNotSupported
	}
	return ss.RequestSampling(ctx, request)
}

// RequestSampling sends a sampling/createMessage request to the client over the
// bound go-sdk ServerSession. It converts the mcp-go-shaped CreateMessageParams
// to the go-sdk's CreateMessageParams, calls ServerSession.CreateMessage, and
// converts the result back. If no go-sdk session is bound yet it returns
// ErrSamplingNotSupported.
//
// The go-sdk's CreateMessage enforces the capability gate (the client must have
// declared Sampling at initialize) and down-converts a multi-content result to
// single content; those behaviors are delegated to the SDK rather than
// reimplemented here.
func (c *clientSession) RequestSampling(
	ctx context.Context, request mcp.CreateMessageRequest,
) (*mcp.CreateMessageResult, error) {
	ss := c.goSession.Load()
	if ss == nil {
		return nil, ErrSamplingNotSupported
	}
	params := &gosdk.CreateMessageParams{}
	if err := jsonConvert(request.CreateMessageParams, params); err != nil {
		return nil, fmt.Errorf("converting sampling params: %w", err)
	}
	res, err := ss.CreateMessage(ctx, params)
	if err != nil {
		return nil, err
	}
	out := &mcp.CreateMessageResult{}
	if err := jsonConvert(res, out); err != nil {
		return nil, fmt.Errorf("converting sampling result: %w", err)
	}
	return out, nil
}
