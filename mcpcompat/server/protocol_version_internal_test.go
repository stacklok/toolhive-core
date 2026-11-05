// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"testing"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testNegotiatedVersion = "2025-11-25"
	testSessionID         = "sess"
)

func TestNegotiatedProtocolVersion_UnknownStates(t *testing.T) {
	t.Parallel()

	sameSession := &gosdk.ServerSession{}

	tests := []struct {
		name       string
		bound      *gosdk.ServerSession
		negotiated *negotiatedProtocolVersion
	}{
		{name: "no bound session"},
		{name: "bound session never negotiated", bound: &gosdk.ServerSession{}},
		{
			name:       "negotiated on a different session",
			bound:      &gosdk.ServerSession{},
			negotiated: &negotiatedProtocolVersion{on: &gosdk.ServerSession{}, version: testNegotiatedVersion},
		},
		{
			name:       "negotiated with an empty version",
			bound:      sameSession,
			negotiated: &negotiatedProtocolVersion{on: sameSession},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := newClientSession(testSessionID)
			t.Cleanup(func() { close(cs.notifCh) })
			if tc.bound != nil {
				cs.goSession.Store(tc.bound)
			}
			if tc.negotiated != nil {
				cs.negotiated.Store(tc.negotiated)
			}
			version, known := cs.NegotiatedProtocolVersion()
			assert.False(t, known)
			assert.Empty(t, version)
		})
	}
}

// idTransport gives the connections of a wrapped transport a fixed session
// ID, which go-sdk's ServerSession.ID reads off the connection. The in-memory
// transport has none of its own.
type idTransport struct {
	gosdk.Transport
	id string
}

func (t idTransport) Connect(ctx context.Context) (gosdk.Connection, error) {
	c, err := t.Transport.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return idConn{Connection: c, id: t.id}, nil
}

type idConn struct {
	gosdk.Connection
	id string
}

func (c idConn) SessionID() string { return c.id }

// connectSeededSession returns a live go-sdk session carrying the given ID and
// seeded initialize state, the way StreamableHTTPServer.rehydrate builds one.
func connectSeededSession(t *testing.T, id string) *gosdk.ServerSession {
	t.Helper()
	ctx := context.Background()
	_, st := gosdk.NewInMemoryTransports()
	state := &gosdk.ServerSessionState{
		InitializeParams:  &gosdk.InitializeParams{ProtocolVersion: "2025-06-18"},
		InitializedParams: &gosdk.InitializedParams{},
	}
	srv := gosdk.NewServer(&gosdk.Implementation{Name: "x", Version: "1"}, nil)
	ss, err := srv.Connect(ctx, idTransport{Transport: st, id: id}, &gosdk.ServerSessionOptions{State: state})
	require.NoError(t, err)
	t.Cleanup(func() { _ = ss.Close() })
	require.Equal(t, id, ss.ID())
	return ss
}

// TestNegotiatedProtocolVersion_UnknownWhenReboundToSeededSession pins the
// pointer comparison: the entry for a session ID survives being bound to a
// newer go-sdk session (see bindSession), and the version recorded on the
// older one must not be reported for the newer one.
func TestNegotiatedProtocolVersion_UnknownWhenReboundToSeededSession(t *testing.T) {
	t.Parallel()
	s := NewMCPServer("rebind", "1.0.0")

	original := connectSeededSession(t, testSessionID)
	s.recordNegotiatedProtocolVersion(original, &gosdk.InitializeResult{ProtocolVersion: testNegotiatedVersion})
	cs := s.bindSession(testSessionID, original)
	version, known := cs.NegotiatedProtocolVersion()
	require.True(t, known, "the version must be known on the session that answered initialize")
	require.Equal(t, testNegotiatedVersion, version)

	seeded := connectSeededSession(t, testSessionID)
	require.Same(t, cs, s.bindSession(testSessionID, seeded), "re-binding must reuse the entry")
	version, known = cs.NegotiatedProtocolVersion()
	assert.False(t, known, "the version recorded on the older session must not be reported for the newer one")
	assert.Empty(t, version)
}

func TestRecordNegotiatedProtocolVersion_Skips(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		id   string
		res  gosdk.Result
	}{
		{name: "not an initialize result", id: testSessionID, res: &gosdk.CallToolResult{}},
		{name: "typed-nil initialize result", id: testSessionID, res: (*gosdk.InitializeResult)(nil)},
		{name: "nil result", id: testSessionID},
		// A session with no ID must not create the shared sessionFor("") entry.
		{name: "session without an ID", res: &gosdk.InitializeResult{ProtocolVersion: testNegotiatedVersion}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := NewMCPServer("skip", "1.0.0")
			ss := connectSeededSession(t, tc.id)
			s.recordNegotiatedProtocolVersion(ss, tc.res)
			_, ok := s.sessions.Load(tc.id)
			assert.False(t, ok, "no session entry may be created")
		})
	}

	t.Run("nil session", func(t *testing.T) {
		t.Parallel()
		s := NewMCPServer("skip", "1.0.0")
		s.recordNegotiatedProtocolVersion(nil, &gosdk.InitializeResult{ProtocolVersion: testNegotiatedVersion})
		count := 0
		s.sessions.Range(func(_, _ any) bool { count++; return true })
		assert.Zero(t, count, "no session entry may be created")
	})
}
