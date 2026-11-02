// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// capsObservation is what the probe tool saw from inside its handler.
type capsObservation struct {
	implements bool
	caps       mcp.ClientCapabilities
	known      bool
}

// capsProbe registers a "probe" tool that records the result of
// DeclaredClientCapabilities for the session in the handler's context.
type capsProbe struct {
	mu   sync.Mutex
	seen *capsObservation
}

func (p *capsProbe) register(s *server.MCPServer) {
	s.AddTool(mcp.NewTool("probe", mcp.WithDescription("records declared caps")),
		func(ctx context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			obs := &capsObservation{}
			if swc, ok := server.ClientSessionFromContext(ctx).(server.SessionWithClientCapabilities); ok {
				obs.implements = true
				obs.caps, obs.known = swc.DeclaredClientCapabilities()
			}
			p.mu.Lock()
			p.seen = obs
			p.mu.Unlock()
			return mcp.NewToolResultText("ok"), nil
		})
}

func (p *capsProbe) observation(t *testing.T) capsObservation {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	require.NotNil(t, p.seen, "probe tool handler did not run")
	return *p.seen
}

// initSessionWithCaps runs the initialize handshake against url, declaring
// capsJSON as the client capabilities, and returns the assigned session ID.
func initSessionWithCaps(t *testing.T, url, capsJSON string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := fmt.Sprintf(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
		`{"protocolVersion":"2025-06-18","capabilities":%s,"clientInfo":{"name":"test","version":"1.0"}}}`, capsJSON)
	resp := postRPC(ctx, t, url, "", body)
	sid := resp.Header.Get("Mcp-Session-Id")
	r := readFirstResult(t, resp)
	require.Nil(t, r.Error, "initialize should not error")
	require.NotEmpty(t, sid, "initialize must assign a session ID")
	nresp := postRPC(ctx, t, url, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	_ = nresp.Body.Close()
	return sid
}

// callProbe invokes the probe tool against url on the given session.
func callProbe(t *testing.T, url, sessionID string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp := postRPC(ctx, t, url, sessionID,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"probe","arguments":{}}}`)
	require.Equal(t, http.StatusOK, resp.StatusCode)
	r := readFirstResult(t, resp)
	require.Nil(t, r.Error, "tools/call probe should not error")
}

func TestClientSession_DeclaredCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		capsJSON        string
		wantElicitation bool
		wantForm        bool
		wantURL         bool
		wantRoots       bool
		wantListChanged bool
		wantSampling    bool
	}{
		{
			name:     "no elicitation",
			capsJSON: `{}`,
		},
		{
			name:            "empty elicitation object",
			capsJSON:        `{"elicitation":{}}`,
			wantElicitation: true,
		},
		{
			name:            "url elicitation",
			capsJSON:        `{"elicitation":{"url":{}}}`,
			wantElicitation: true,
			wantURL:         true,
		},
		{
			name:            "form and url elicitation",
			capsJSON:        `{"elicitation":{"form":{},"url":{}}}`,
			wantElicitation: true,
			wantForm:        true,
			wantURL:         true,
		},
		{
			name:      "roots without listChanged",
			capsJSON:  `{"roots":{}}`,
			wantRoots: true,
		},
		{
			name:            "roots and sampling without elicitation",
			capsJSON:        `{"roots":{"listChanged":true},"sampling":{}}`,
			wantRoots:       true,
			wantListChanged: true,
			wantSampling:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			probe := &capsProbe{}
			mcpSrv := server.NewMCPServer("caps", "1.0.0")
			probe.register(mcpSrv)
			ts := httptest.NewServer(server.NewStreamableHTTPServer(mcpSrv))
			defer ts.Close()

			sid := initSessionWithCaps(t, ts.URL, tc.capsJSON)
			callProbe(t, ts.URL, sid)

			obs := probe.observation(t)
			require.True(t, obs.implements, "session must implement SessionWithClientCapabilities")
			require.True(t, obs.known, "capabilities must be known on a session that saw initialize")

			el := obs.caps.Elicitation
			require.Equal(t, tc.wantElicitation, el != nil, "elicitation presence")
			if el != nil {
				assert.Equal(t, tc.wantForm, el.Form != nil, "elicitation.form presence")
				assert.Equal(t, tc.wantURL, el.URL != nil, "elicitation.url presence")
			}
			assert.Equal(t, tc.wantRoots, obs.caps.Roots != nil, "roots presence")
			if tc.wantRoots && obs.caps.Roots != nil {
				assert.Equal(t, tc.wantListChanged, obs.caps.Roots.ListChanged, "roots.listChanged")
			}
			assert.Equal(t, tc.wantSampling, obs.caps.Sampling != nil, "sampling presence")
		})
	}
}

func TestClientSession_DeclaredCapabilities_UnknownWhenNotObserved(t *testing.T) {
	t.Parallel()

	t.Run("rehydrated session", func(t *testing.T) {
		t.Parallel()
		mgr := newSharedSessionManager()

		// Replica A sees initialize, with the client declaring URL elicitation.
		srvA := server.NewMCPServer("A", "1.0.0")
		tsA := httptest.NewServer(server.NewStreamableHTTPServer(srvA, server.WithSessionIdManager(mgr)))
		defer tsA.Close()

		// Replica B serves the same session through rehydration only.
		probe := &capsProbe{}
		srvB := server.NewMCPServer("B", "1.0.0")
		probe.register(srvB)
		tsB := httptest.NewServer(server.NewStreamableHTTPServer(srvB, server.WithSessionIdManager(mgr)))
		defer tsB.Close()

		sid := initSessionWithCaps(t, tsA.URL, `{"elicitation":{"url":{}}}`)
		callProbe(t, tsB.URL, sid)

		obs := probe.observation(t)
		require.True(t, obs.implements, "session must implement SessionWithClientCapabilities")
		assert.False(t, obs.known, "a rehydrated session's seeded capabilities must not be reported as declared")
		assert.Equal(t, mcp.ClientCapabilities{}, obs.caps, "unknown capabilities must be the zero value")
	})

	t.Run("stateless request", func(t *testing.T) {
		t.Parallel()
		probe := &capsProbe{}
		mcpSrv := server.NewMCPServer("stateless", "1.0.0")
		probe.register(mcpSrv)
		ts := httptest.NewServer(server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(true)))
		defer ts.Close()

		callProbe(t, ts.URL, "")

		obs := probe.observation(t)
		require.True(t, obs.implements, "session must implement SessionWithClientCapabilities")
		assert.False(t, obs.known, "a stateless request has no initialize, so capabilities are unknown")
		assert.Equal(t, mcp.ClientCapabilities{}, obs.caps, "unknown capabilities must be the zero value")
	})
}
