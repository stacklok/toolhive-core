// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// countingSessionManager is a minimal SessionIdManager test double that
// counts Generate and Terminate calls. It stands in for ToolHive's real
// SessionIdManager implementations (see sharedSessionManager in
// rehydration_test.go) but is deliberately trivial: this test only needs to
// observe how many session IDs go-sdk mints and how many it actually
// terminates during a single client Initialize+Close, not cross-replica
// sharing.
//
// Validate is intentionally NOT counted as part of the leak tripwire below:
// the shim only calls Validate with a session ID the CLIENT sends back on a
// later request, and the client never learns the discover-probe's session ID
// (go-sdk only echoes the Mcp-Session-Id response header on the initialize
// response, mcp/streamable.go:1660, not on discover). So Validate is never
// invoked with the orphaned probe ID either — it cannot make the orphan more
// or less observable than the Generate/Terminate delta already does.
type countingSessionManager struct {
	generateCalls  atomic.Int64
	terminateCalls atomic.Int64
}

func (m *countingSessionManager) Generate() string {
	m.generateCalls.Add(1)
	return uuid.NewString()
}

func (*countingSessionManager) Validate(string) (bool, error) { return false, nil }

func (m *countingSessionManager) Terminate(sessionID string) (bool, error) {
	if sessionID != "" {
		m.terminateCalls.Add(1)
	}
	return false, nil
}

// TestDiscoverFallback_ExtraSessionOnStatefulServer pins a real session leak
// introduced by the go-sdk v1.7 bump, verified by reading the go-sdk v1.7.0-
// pre.3 source (not merely inferred from behavior):
//
//  1. (*gosdk.Client).Connect is now "Modern-first": per SEP-2575 it always
//     sends server/discover first, because the client's default protocol
//     version is now the SDK's latest (2026-07-28).
//  2. This shim's servers are stateful (WithStateless is out of scope for
//     this PR; see PR2), so go-sdk's stateful StreamableHTTPHandler routes
//     the session-less discover POST through its normal new-session path: it
//     mints a session ID via SessionIdManager.Generate and dispatches the
//     RPC to the SAME server.discover handler a stateless server would use.
//  3. That handler UNCONDITIONALLY sets state, defeating go-sdk's own
//     cleanup guard: server.discover calls
//     req.Session.updateState(func(s *ServerSessionState) { s.InitializeParams
//     = init }) (mcp/server.go:898-902). go-sdk's per-request cleanup
//     (mcp/streamable.go:733-735) only closes an abandoned session
//     `if session.InitializeParams() == nil` (its #578 fix) — but the
//     discover handler just set InitializeParams, so that guard never
//     fires. go-sdk does NOT close the discover-probe session.
//  4. With StreamableHTTPOptions.SessionTimeout unset (this shim never sets
//     it — and must not, see WithSessionIdManager's doc; a timeout would
//     reap legitimate idle sessions too), go-sdk never reaps it either: the
//     probe session lives in go-sdk's internal session map for the process
//     lifetime.
//  5. The client never learns the probe's session ID (go-sdk only echoes the
//     Mcp-Session-Id response header on an initialize response, not on
//     discover — mcp/streamable.go:1660), so it cannot terminate the probe
//     it never asked for; it re-mints via a brand-new POST for the legacy
//     initialize, which mints a SECOND session ID and completes normally.
//  6. At the ToolHive layer, this shim wires SessionIdManager.Generate as
//     go-sdk's session-ID source (build, transports.go), so the discover
//     probe's Generate call also creates a ToolHive-side placeholder session
//     record. OnRegisterSession only fires once initialize actually succeeds
//     (discover ≠ initialize), so that placeholder is never promoted, and
//     because the client never learns the probe's ID it never sends the
//     DELETE that would call Terminate for it — the placeholder is orphaned
//     alongside the go-sdk session.
//
// Both leaks are availability/resource-exhaustion concerns (a session record
// per Modern-first Connect attempt against a stateful server, forever), not
// confidentiality: OnRegisterSession never fired, so no identity or tool
// overlay is ever bound to the orphan.
//
// KNOWN TRANSITIONAL: fixed when PR2's stateless backend path lands (no
// discover probe against a stateless server needs the new-session path) or
// go-sdk starts closing/timing-out discover-only sessions. Tracks the #5911
// unexported-version-pin gap.
func TestDiscoverFallback_ExtraSessionOnStatefulServer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	mgr := &countingSessionManager{}
	var registeredSessions atomic.Int64
	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, _ server.ClientSession) {
		registeredSessions.Add(1)
	})

	srv := server.NewMCPServer("discover-fallback-server", testClientVersion, server.WithHooks(hooks))
	srv.AddTool(
		mcp.NewTool("greet", mcp.WithDescription("greets")),
		func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("hello"), nil
		},
	)

	httpSrv := server.NewStreamableHTTPServer(srv, server.WithSessionIdManager(mgr))
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	initRes, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	// Despite go-sdk v1.7 defaulting to the discover-first Connect, a stateful
	// server must still negotiate down to the shim-owned legacy constant.
	assert.Equal(t, mcp.LATEST_PROTOCOL_VERSION, initRes.ProtocolVersion)

	// Generate/Terminate counts are asserted together below, after Close, so
	// the tripwire also captures the client's DELETE behavior.

	// Only the session that actually completed initialize is registered with
	// the shim; the discover probe's session is never promoted.
	assert.EqualValues(t, 1, registeredSessions.Load(),
		"only the legacy-initialize session should reach OnRegisterSession")

	tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
	require.NoError(t, err)
	require.Len(t, tools.Tools, 1)
	assert.Equal(t, "greet", tools.Tools[0].Name)

	// Close explicitly (rather than relying solely on the t.Cleanup below) so
	// the DELETE the client sends for the ONE session ID it knows about
	// (the legacy-initialize session) is observed before we assert the
	// tripwire below. Close is idempotent, so the t.Cleanup call is still
	// safe as a belt-and-braces teardown.
	require.NoError(t, c.Close())

	// Strengthened leak tripwire (black-box, via the shim's own
	// SessionIdManager seam — go-sdk's session map is unexported and not
	// otherwise observable from here): Generate was called twice (discover
	// probe + legacy initialize), but Terminate was called only ONCE,
	// because the client only ever learns and DELETEs the legacy-initialize
	// session's ID. The discover probe's minted ID is never terminated, on
	// either side (go-sdk's own session AND this shim's placeholder record
	// for it) — that is the orphan this test guards against.
	assert.EqualValues(t, 2, mgr.generateCalls.Load(),
		"go-sdk v1.7's discover-then-fallback Connect must mint exactly two session IDs "+
			"against a stateful server: one abandoned by the failed discover probe, "+
			"one for the legacy initialize that actually succeeds")
	assert.EqualValues(t, 1, mgr.terminateCalls.Load(),
		"only the legacy-initialize session's ID is ever DELETEd by the client, "+
			"because it never learns the discover probe's session ID")
	assert.EqualValues(t, 1, mgr.generateCalls.Load()-mgr.terminateCalls.Load(),
		"exactly one Generate call must be left with no matching Terminate: the orphaned "+
			"discover-probe placeholder record. If this assertion starts failing because "+
			"the delta went to zero, either upstream go-sdk started closing/reaping "+
			"discover-only sessions, or PR2's stateless backend path eliminated the probe's "+
			"new-session route — update this test (and its doc comment) to match the fix "+
			"instead of loosening the assertion.")
}
