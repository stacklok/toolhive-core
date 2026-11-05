// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// versionObservation is what the version probe tool saw from inside its
// handler.
type versionObservation struct {
	implements bool
	version    string
	known      bool
}

// versionProbe registers a "probe" tool that records the result of
// NegotiatedProtocolVersion for the session in the handler's context.
type versionProbe struct {
	mu   sync.Mutex
	seen *versionObservation
}

func (p *versionProbe) register(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("probe", mcp.WithDescription("records negotiated version")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			obs := &versionObservation{}
			if swv, ok := server.ClientSessionFromContext(ctx).(server.SessionWithProtocolVersion); ok {
				obs.implements = true
				obs.version, obs.known = swv.NegotiatedProtocolVersion()
			}
			p.mu.Lock()
			p.seen = obs
			p.mu.Unlock()
			return mcp.NewToolResultText("ok"), nil
		})
}

func (p *versionProbe) observation(t *testing.T) versionObservation {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	require.NotNil(t, p.seen, "probe tool handler did not run")
	return *p.seen
}

// initSessionWithVersion runs the initialize handshake against url, requesting
// protocolVersion, and returns the assigned session ID and the version the
// server answered with.
func initSessionWithVersion(t *testing.T, url, protocolVersion string) (sid, answered string) {
	t.Helper()
	return initSessionRaw(t, url, protocolVersion, "{}")
}

func TestClientSession_NegotiatedProtocolVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// connect runs initialize against url, then calls the probe tool, and
		// returns the protocol version the server answered initialize with.
		connect func(t *testing.T, url string) string
		// want is the expected version; empty skips the exact check.
		want string
		// notWant is a version that must not be reported.
		notWant string
	}{
		{
			name: "go-sdk client",
			connect: func(t *testing.T, url string) string {
				t.Helper()
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				gc := gosdk.NewClient(&gosdk.Implementation{Name: "test", Version: "1.0"}, nil)
				sess, err := gc.Connect(ctx, &gosdk.StreamableClientTransport{Endpoint: url}, nil)
				require.NoError(t, err)
				defer func() { _ = sess.Close() }()
				_, err = sess.CallTool(ctx, &gosdk.CallToolParams{Name: "probe", Arguments: map[string]any{}})
				require.NoError(t, err)
				return sess.InitializeResult().ProtocolVersion
			},
			// Tracks go-sdk's latest protocol revision; update on a go-sdk
			// upgrade that adds one.
			want: "2025-11-25",
		},
		{
			name: "client requests 2025-06-18",
			connect: func(t *testing.T, url string) string {
				t.Helper()
				sid, answered := initSessionWithVersion(t, url, "2025-06-18")
				callProbe(t, url, sid)
				return answered
			},
			want: "2025-06-18",
		},
		{
			// A version the server does not support for initialize gets the
			// server's choice, which is what must be reported, not the
			// requested version.
			name: "client requests an unsupported version",
			connect: func(t *testing.T, url string) string {
				t.Helper()
				sid, answered := initSessionWithVersion(t, url, "2099-01-01")
				callProbe(t, url, sid)
				return answered
			},
			notWant: "2099-01-01",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			probe := &versionProbe{}
			mcpSrv := server.NewMCPServer("version", "1.0.0")
			probe.register(mcpSrv)
			ts := httptest.NewServer(server.NewStreamableHTTPServer(mcpSrv))
			defer ts.Close()

			answered := tc.connect(t, ts.URL)

			obs := probe.observation(t)
			require.True(t, obs.implements, "session must implement SessionWithProtocolVersion")
			require.True(t, obs.known, "the version must be known on a session that saw initialize")
			require.NotEmpty(t, obs.version, "a known version must not be empty")
			if tc.want != "" {
				assert.Equal(t, tc.want, obs.version, "negotiated protocol version")
			}
			if tc.notWant != "" {
				assert.NotEqual(t, tc.notWant, obs.version, "must report the negotiated version, not the requested one")
			}
			assert.Equal(t, answered, obs.version, "must match the version the client was told at initialize")
		})
	}
}

func TestClientSession_NegotiatedProtocolVersion_UnknownWhenNotObserved(t *testing.T) {
	t.Parallel()

	t.Run("rehydrated session", func(t *testing.T) {
		t.Parallel()
		mgr := newSharedSessionManager()

		// Replica A sees initialize.
		srvA := server.NewMCPServer("A", "1.0.0")
		tsA := httptest.NewServer(server.NewStreamableHTTPServer(srvA, server.WithSessionIdManager(mgr)))
		defer tsA.Close()

		// Replica B serves the same session through rehydration only, with a
		// version seeded from the MCP-Protocol-Version header.
		probe := &versionProbe{}
		srvB := server.NewMCPServer("B", "1.0.0")
		probe.register(srvB)
		tsB := httptest.NewServer(server.NewStreamableHTTPServer(srvB, server.WithSessionIdManager(mgr)))
		defer tsB.Close()

		sid, _ := initSessionWithVersion(t, tsA.URL, "2025-06-18")
		callProbe(t, tsB.URL, sid)

		obs := probe.observation(t)
		require.True(t, obs.implements, "session must implement SessionWithProtocolVersion")
		assert.False(t, obs.known, "a rehydrated session's seeded version must not be reported as negotiated")
		assert.Empty(t, obs.version, "an unknown version must be empty")
	})

	t.Run("stateless request", func(t *testing.T) {
		t.Parallel()
		probe := &versionProbe{}
		mcpSrv := server.NewMCPServer("stateless", "1.0.0")
		probe.register(mcpSrv)
		ts := httptest.NewServer(server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(true)))
		defer ts.Close()

		callProbe(t, ts.URL, "")

		obs := probe.observation(t)
		require.True(t, obs.implements, "session must implement SessionWithProtocolVersion")
		assert.False(t, obs.known, "a stateless request has no initialize, so the version is unknown")
		assert.Empty(t, obs.version, "an unknown version must be empty")
	})
}

// TestClientSession_NegotiatedProtocolVersion_KnownInRegisterHook pins that
// the version is recorded before OnRegisterSession hooks run, so a hook can
// read it on the session it is handed.
func TestClientSession_NegotiatedProtocolVersion_KnownInRegisterHook(t *testing.T) {
	t.Parallel()

	seen := make(chan versionObservation, 1)
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, s server.ClientSession) {
		var obs versionObservation
		if swv, ok := s.(server.SessionWithProtocolVersion); ok {
			obs.implements = true
			obs.version, obs.known = swv.NegotiatedProtocolVersion()
		}
		seen <- obs
	})
	mcpSrv := server.NewMCPServer("hook", "1.0.0", server.WithHooks(hooks))
	ts := httptest.NewServer(server.NewStreamableHTTPServer(mcpSrv))
	defer ts.Close()

	_, answered := initSessionWithVersion(t, ts.URL, "2025-06-18")

	select {
	case obs := <-seen:
		require.True(t, obs.implements, "session must implement SessionWithProtocolVersion")
		require.True(t, obs.known, "the version must be known by the time OnRegisterSession runs")
		assert.Equal(t, "2025-06-18", obs.version)
		assert.Equal(t, answered, obs.version, "must match the version the client was told at initialize")
	case <-time.After(5 * time.Second):
		require.Fail(t, "OnRegisterSession hook did not run")
	}
}
