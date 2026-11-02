// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"maps"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// SessionWithClientCapabilities is a ClientSession that can report the
// capabilities its client declared in the initialize request. A handler
// reaches it by type-asserting the session ClientSessionFromContext returns.
//
// It exists so an embedding server can check what a client supports before
// sending a server->client request. For example, it can confirm the client
// declared elicitation.url before sending a URL-mode elicitation, which the
// MCP spec forbids for clients that did not declare it.
type SessionWithClientCapabilities interface {
	ClientSession
	// DeclaredClientCapabilities returns the capabilities the client declared
	// at initialize, and known=true, when this instance saw that initialize.
	//
	// known is false when the declared capabilities are not available, and
	// the returned capabilities are then the zero value. Callers must treat
	// that as "unknown", not as "declared nothing". This happens in three
	// cases: on a session rehydrated from another replica, whose
	// initialize-time state is reconstructed and seeded rather than declared;
	// on a stateless request, which has no initialize handshake; and before
	// initialize has completed.
	DeclaredClientCapabilities() (caps mcp.ClientCapabilities, known bool)
}

// DeclaredClientCapabilities implements SessionWithClientCapabilities. It
// reads the bound go-sdk session's InitializeParams, but only if that session
// is the one this instance saw initialize on (initializedOn). A rehydrated
// session's InitializeParams are seeded by StreamableHTTPServer.rehydrate,
// including a placeholder elicitation capability. Reporting them as declared
// would lead consumers to send elicitation modes the client never declared.
func (c *clientSession) DeclaredClientCapabilities() (mcp.ClientCapabilities, bool) {
	ss := c.goSession.Load()
	if ss == nil || c.initializedOn.Load() != ss {
		return mcp.ClientCapabilities{}, false
	}
	params := ss.InitializeParams()
	if params == nil {
		return mcp.ClientCapabilities{}, false
	}
	return fromGoSDKClientCapabilities(params.Capabilities), true
}

// fromGoSDKClientCapabilities translates go-sdk client capabilities into the
// mcp-go-shaped mcpcompat type. It maps fields one by one instead of using a
// JSON round-trip (jsonConvert). go-sdk's deprecated Roots field is a
// non-pointer struct that always serializes as "roots":{}, so a round-trip
// would report roots as declared for every client. Presence of roots is read
// from RootsV2 instead, which go-sdk sets only when the client sent roots.
//
// Tasks has no go-sdk counterpart and is always nil. A nil input (a client
// that sent no capabilities object) yields the zero value.
func fromGoSDKClientCapabilities(in *gosdk.ClientCapabilities) mcp.ClientCapabilities {
	var out mcp.ClientCapabilities
	if in == nil {
		return out
	}
	out.Experimental = maps.Clone(in.Experimental)
	out.Extensions = maps.Clone(in.Extensions)
	if in.RootsV2 != nil {
		out.Roots = &struct {
			ListChanged bool `json:"listChanged,omitempty"`
		}{ListChanged: in.RootsV2.ListChanged}
	}
	if in.Sampling != nil { //nolint:staticcheck // deprecated in go-sdk but still part of the declared capabilities
		out.Sampling = &mcp.SamplingCapability{}
		if in.Sampling.Context != nil { //nolint:staticcheck // see above
			out.Sampling.Context = &struct{}{}
		}
		if in.Sampling.Tools != nil { //nolint:staticcheck // see above
			out.Sampling.Tools = &struct{}{}
		}
	}
	if in.Elicitation != nil {
		out.Elicitation = &mcp.ElicitationCapability{}
		if in.Elicitation.Form != nil {
			out.Elicitation.Form = &struct{}{}
		}
		if in.Elicitation.URL != nil {
			out.Elicitation.URL = &struct{}{}
		}
	}
	return out
}
