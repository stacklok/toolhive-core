// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"fmt"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// RequestElicitation sends a server->client elicitation request on the session
// associated with ctx and returns the user's response. It mirrors mcp-go's
// (*MCPServer).RequestElicitation.
func (*MCPServer) RequestElicitation(ctx context.Context, request mcp.ElicitationRequest) (*mcp.ElicitationResult, error) {
	cs, ok := ClientSessionFromContext(ctx).(*clientSession)
	if !ok || cs == nil {
		return nil, fmt.Errorf("no active session in context for elicitation")
	}
	ss := cs.goSession.Load()
	if ss == nil {
		return nil, fmt.Errorf("no server session available for elicitation")
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
