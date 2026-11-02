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
//
// This is a shim-only extension with no mcp-go counterpart of the same shape.
// The closest mcp-go interface is server.SessionWithClientInfo, whose
// GetClientCapabilities has no way to say the capabilities are unknown, and
// which also has setters. This interface is read-only and returns an explicit
// known flag, so a caller can tell "declared nothing" from "not observed".
type SessionWithClientCapabilities interface {
	ClientSession
	// DeclaredClientCapabilities returns the capabilities the client declared
	// at initialize, and known=true, when this instance saw that initialize.
	//
	// known is false when the declared capabilities are not available, and
	// the returned capabilities are then the zero value. Callers must treat
	// that as "unknown", not as "declared nothing". This happens:
	//   - on a rehydrated session, reconstructed from shared state either on
	//     another replica or after this instance reaped the original, whose
	//     initialize-time state is seeded rather than declared;
	//   - on a stateless request, which has no initialize handshake;
	//   - on every SSE and stdio session, which have no session ID and so are
	//     never registered as having seen initialize;
	//   - before initialize has completed.
	//
	// The returned Experimental and Extensions maps are copies, but their
	// nested values are shared with the session's state and must be treated
	// as read-only.
	DeclaredClientCapabilities() (caps mcp.ClientCapabilities, known bool)
}

// DeclaredClientCapabilities implements SessionWithClientCapabilities. It
// reads the bound go-sdk session's InitializeParams, but only if that session
// is the one this instance saw initialize on (initializedOn). A rehydrated
// session, whether it came from another replica or from this instance after
// it reaped the original, has InitializeParams seeded by
// StreamableHTTPServer.rehydrate, including a placeholder elicitation
// capability. Reporting them as declared would lead consumers to send
// elicitation modes the client never declared.
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
	// Sampling (like RootsV2) is deprecated in go-sdk but still carries what
	// the client declared.
	if in.Sampling != nil {
		out.Sampling = &mcp.SamplingCapability{}
		if in.Sampling.Context != nil {
			out.Sampling.Context = &struct{}{}
		}
		if in.Sampling.Tools != nil {
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
