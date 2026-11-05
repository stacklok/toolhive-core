// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// SessionWithProtocolVersion is a ClientSession that can report the MCP
// protocol version negotiated at initialize. A handler reaches it by
// type-asserting the session ClientSessionFromContext returns.
//
// It exists so an embedding server can follow version-gated MCP rules. For
// example, it can send a -32042 URLElicitationRequiredError only on a session
// that negotiated 2025-11-25, since that error and URL-mode elicitation do not
// exist in older revisions.
//
// This is a shim-only extension with no mcp-go counterpart. It sits beside
// SessionWithClientCapabilities and uses the same known semantics.
type SessionWithProtocolVersion interface {
	ClientSession
	// NegotiatedProtocolVersion returns the protocol version the server
	// answered the client's initialize request with, and known=true, when
	// this instance saw that initialize. This is go-sdk's negotiation result,
	// not the version the client requested: a client that requests a version
	// the server does not support for initialize gets the server's choice.
	//
	// known is false, and version is empty, when the negotiated version is
	// not available. Callers must treat that as "unknown" and fall back to
	// behavior that is safe for every revision. This happens:
	//   - on a rehydrated session, reconstructed from shared state either on
	//     another replica or after this instance reaped the original, whose
	//     version is seeded from the MCP-Protocol-Version header or defaulted;
	//   - on a stateless request, which has no initialize handshake;
	//   - on every SSE and stdio session, which have no session ID and so are
	//     never registered as having seen initialize;
	//   - before initialize has completed.
	//
	// Under protocol version 2026-07-28 the version is carried with each
	// request rather than negotiated at initialize, and is not reflected here.
	NegotiatedProtocolVersion() (version string, known bool)
}

// negotiatedProtocolVersion records the version go-sdk answered initialize
// with, together with the go-sdk session that answered it.
type negotiatedProtocolVersion struct {
	on      *gosdk.ServerSession
	version string
}

// NegotiatedProtocolVersion implements SessionWithProtocolVersion. The
// recorded version is reported only while the go-sdk session it was recorded
// on is the one currently bound, for the same reason DeclaredClientCapabilities
// compares initializedOn: a session ID re-bound to a rehydrated go-sdk session
// carries a seeded version, not a negotiated one.
func (c *clientSession) NegotiatedProtocolVersion() (string, bool) {
	n := c.negotiated.Load()
	if n == nil || n.version == "" || c.goSession.Load() != n.on {
		return "", false
	}
	return n.version, true
}

// recordNegotiatedProtocolVersion stores the protocol version from a
// successful initialize result on the session's ClientSession. It reads the
// version off go-sdk's InitializeResult instead of recomputing the
// negotiation, so it always matches what the client was told.
//
// The caller must not call it for a stateless dispatch. A session with no ID
// (stateless temp sessions, SSE, stdio) is skipped, because binding it would
// create the shared sessionFor("") entry contextWithSession warns about.
func (s *MCPServer) recordNegotiatedProtocolVersion(ss *gosdk.ServerSession, res gosdk.Result) {
	ir, ok := res.(*gosdk.InitializeResult)
	if !ok || ir == nil || ss == nil || ss.ID() == "" {
		return
	}
	s.bindSession(ss.ID(), ss).negotiated.Store(&negotiatedProtocolVersion{on: ss, version: ir.ProtocolVersion})
}
