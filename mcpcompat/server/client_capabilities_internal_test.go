// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

func TestFromGoSDKClientCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   *gosdk.ClientCapabilities
		want mcp.ClientCapabilities
	}{
		{
			name: "nil capabilities",
			in:   nil,
			want: mcp.ClientCapabilities{},
		},
		{
			name: "empty capabilities",
			in:   &gosdk.ClientCapabilities{},
			want: mcp.ClientCapabilities{},
		},
		{
			// The deprecated non-pointer Roots field is populated but RootsV2
			// is nil: roots were not declared and must not be reported.
			name: "legacy roots field alone is not presence",
			in: &gosdk.ClientCapabilities{
				Roots: struct {
					ListChanged bool `json:"listChanged,omitempty"`
				}{ListChanged: true},
			},
			want: mcp.ClientCapabilities{},
		},
		{
			name: "roots via RootsV2",
			in:   &gosdk.ClientCapabilities{RootsV2: &gosdk.RootCapabilities{ListChanged: true}},
			want: mcp.ClientCapabilities{Roots: &struct {
				ListChanged bool `json:"listChanged,omitempty"`
			}{ListChanged: true}},
		},
		{
			// Presence keys on the RootsV2 pointer, not on ListChanged: a
			// client that sent "roots":{} still declared roots.
			name: "roots via RootsV2 without listChanged",
			in:   &gosdk.ClientCapabilities{RootsV2: &gosdk.RootCapabilities{}},
			want: mcp.ClientCapabilities{Roots: &struct {
				ListChanged bool `json:"listChanged,omitempty"`
			}{}},
		},
		{
			name: "sampling with context and tools",
			in: &gosdk.ClientCapabilities{Sampling: &gosdk.SamplingCapabilities{
				Context: &gosdk.SamplingContextCapabilities{},
				Tools:   &gosdk.SamplingToolsCapabilities{},
			}},
			want: mcp.ClientCapabilities{Sampling: &mcp.SamplingCapability{
				Context: &struct{}{},
				Tools:   &struct{}{},
			}},
		},
		{
			name: "empty elicitation",
			in:   &gosdk.ClientCapabilities{Elicitation: &gosdk.ElicitationCapabilities{}},
			want: mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapability{}},
		},
		{
			name: "form and url elicitation",
			in: &gosdk.ClientCapabilities{Elicitation: &gosdk.ElicitationCapabilities{
				Form: &gosdk.FormElicitationCapabilities{},
				URL:  &gosdk.URLElicitationCapabilities{},
			}},
			want: mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapability{
				Form: &struct{}{},
				URL:  &struct{}{},
			}},
		},
		{
			name: "experimental and extensions",
			in: &gosdk.ClientCapabilities{
				Experimental: map[string]any{"x": map[string]any{}},
				Extensions:   map[string]any{"io.example/ext": map[string]any{"k": "v"}},
			},
			want: mcp.ClientCapabilities{
				Experimental: map[string]any{"x": map[string]any{}},
				Extensions:   map[string]any{"io.example/ext": map[string]any{"k": "v"}},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, fromGoSDKClientCapabilities(tc.in))
		})
	}
}

// TestFromGoSDKClientCapabilities_ClonesMaps checks that the returned
// Experimental and Extensions maps are independent top-level copies, so a
// caller adding or deleting keys does not change the go-sdk session's state.
// Nested values are shared by design (the clone is shallow).
func TestFromGoSDKClientCapabilities_ClonesMaps(t *testing.T) {
	t.Parallel()

	in := &gosdk.ClientCapabilities{
		Experimental: map[string]any{"x": "1"},
		Extensions:   map[string]any{"ext": "2"},
	}
	out := fromGoSDKClientCapabilities(in)

	out.Experimental["added"] = true
	delete(out.Experimental, "x")
	out.Extensions["added"] = true
	delete(out.Extensions, "ext")

	assert.Equal(t, map[string]any{"x": "1"}, in.Experimental)
	assert.Equal(t, map[string]any{"ext": "2"}, in.Extensions)
}

// TestDeclaredClientCapabilities_UnknownStates covers the known=false paths
// that do not need a live transport: no bound go-sdk session, a bound
// session that differs from the one initialize was observed on, and a
// matching session whose InitializeParams are not set.
func TestDeclaredClientCapabilities_UnknownStates(t *testing.T) {
	t.Parallel()

	sameSession := &gosdk.ServerSession{}

	tests := []struct {
		name   string
		bound  *gosdk.ServerSession
		initOn *gosdk.ServerSession
	}{
		{name: "no bound session"},
		{name: "initialize observed on a different session", bound: &gosdk.ServerSession{}, initOn: &gosdk.ServerSession{}},
		{name: "bound session never observed initialize", bound: &gosdk.ServerSession{}},
		{name: "initialize observed but params missing", bound: sameSession, initOn: sameSession},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cs := newClientSession("sid")
			t.Cleanup(func() { close(cs.notifCh) })
			if tc.bound != nil {
				cs.goSession.Store(tc.bound)
			}
			if tc.initOn != nil {
				cs.initializedOn.Store(tc.initOn)
			}
			caps, known := cs.DeclaredClientCapabilities()
			assert.False(t, known)
			assert.Equal(t, mcp.ClientCapabilities{}, caps)
		})
	}
}

// capsSeen is what the probe tool saw from inside its handler.
type capsSeen struct {
	implements bool
	caps       mcp.ClientCapabilities
	known      bool
}

// TestDeclaredClientCapabilities_UnknownAfterReapAndRehydrate covers the case
// the initializedOn comparison exists for, end to end on one instance: a
// session that saw initialize reports its declared capabilities, and once the
// session is gone and the same session ID is rehydrated here from the shared
// store, the rehydrated session's seeded capabilities read as unknown.
//
// Closing the bound go-sdk session is what the idle reaper does when a session
// times out; doing it directly keeps the test independent of timers.
func TestDeclaredClientCapabilities_UnknownAfterReapAndRehydrate(t *testing.T) {
	t.Parallel()

	seen := make(chan capsSeen, 4)
	srv := NewMCPServer("reap-caps", "1.0.0")
	srv.AddTool(mcp.NewTool("probe", mcp.WithDescription("records declared caps")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var obs capsSeen
			if swc, ok := ClientSessionFromContext(ctx).(SessionWithClientCapabilities); ok {
				obs.implements = true
				obs.caps, obs.known = swc.DeclaredClientCapabilities()
			}
			seen <- obs
			return mcp.NewToolResultText("ok"), nil
		})
	hs := NewStreamableHTTPServer(srv, WithSessionIdManager(newReapManager(nil)))
	ts := httptest.NewServer(hs)
	t.Cleanup(ts.Close)

	probe := func(sid string) capsSeen {
		t.Helper()
		status, _ := reapPost(t, ts, sid,
			`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe","arguments":{}}}`)
		require.Equal(t, http.StatusOK, status)
		select {
		case obs := <-seen:
			return obs
		case <-time.After(5 * time.Second):
			require.Fail(t, "probe tool handler did not run")
			return capsSeen{}
		}
	}

	status, sid := reapPost(t, ts, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
		`{"protocolVersion":"2025-06-18","capabilities":{"elicitation":{"url":{}}},`+
		`"clientInfo":{"name":"c","version":"1"}}}`)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, sid)
	reapPost(t, ts, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	before := probe(sid)
	require.True(t, before.implements, "session must implement SessionWithClientCapabilities")
	require.True(t, before.known, "capabilities must be known on a session that saw initialize")
	require.NotNil(t, before.caps.Elicitation)
	require.NotNil(t, before.caps.Elicitation.URL, "the declared elicitation.url must be reported")

	require.NoError(t, boundSession(t, srv, sid).Close())
	waitForWithin(t, reapDeadline, func() bool { return !registered(srv, sid) && !srv.isLocalSession(sid) },
		"the closed session must be forgotten")
	require.Nil(t, hs.getRehydrated(sid), "the session must not be rehydrated before the next request")

	after := probe(sid)
	require.NotNil(t, hs.getRehydrated(sid), "the returning client must be served by a rehydrated session")
	require.True(t, after.implements, "session must implement SessionWithClientCapabilities")
	assert.False(t, after.known, "a rehydrated session's seeded capabilities must not be reported as declared")
	assert.Equal(t, mcp.ClientCapabilities{}, after.caps, "unknown capabilities must be the zero value")
}

// TestDeclaredClientCapabilities_UnknownWhenReboundToSeededSession pins the
// pointer comparison itself. The entry for a session ID survives being bound
// to a newer go-sdk session (see bindSession), and the newer session's
// InitializeParams are non-nil but seeded, not declared. Both sessions here
// carry real InitializeParams, so only comparing initializedOn with the bound
// session, not a nil check, can report the seeded capabilities as unknown.
func TestDeclaredClientCapabilities_UnknownWhenReboundToSeededSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMCPServer("rebind", "1.0.0")
	connect := func(caps *gosdk.ClientCapabilities) *gosdk.ServerSession {
		t.Helper()
		_, st := gosdk.NewInMemoryTransports()
		state := &gosdk.ServerSessionState{
			InitializeParams:  &gosdk.InitializeParams{ProtocolVersion: "2025-06-18", Capabilities: caps},
			InitializedParams: &gosdk.InitializedParams{},
		}
		ss, err := gosdk.NewServer(&gosdk.Implementation{Name: "x", Version: "1"}, nil).
			Connect(ctx, st, &gosdk.ServerSessionOptions{State: state})
		require.NoError(t, err)
		t.Cleanup(func() { _ = ss.Close() })
		return ss
	}

	declared := connect(&gosdk.ClientCapabilities{
		Elicitation: &gosdk.ElicitationCapabilities{URL: &gosdk.URLElicitationCapabilities{}},
	})
	cs := s.bindSession("sess", declared)
	cs.initializedOn.Store(declared)
	caps, known := cs.DeclaredClientCapabilities()
	require.True(t, known, "capabilities must be known on the session that saw initialize")
	require.NotNil(t, caps.Elicitation)
	require.NotNil(t, caps.Elicitation.URL)

	seeded := connect(&gosdk.ClientCapabilities{Elicitation: &gosdk.ElicitationCapabilities{}})
	require.Same(t, cs, s.bindSession("sess", seeded), "re-binding must reuse the entry")
	caps, known = cs.DeclaredClientCapabilities()
	assert.False(t, known, "the seeded capabilities of the newer session must not be reported as declared")
	assert.Equal(t, mcp.ClientCapabilities{}, caps)
}
