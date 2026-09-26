// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// reapDeadline bounds how long these tests wait for a reap that is due. It spans
// several idle timeouts so a slow, heavily loaded runner does not fail a correct
// test; each wait ends as soon as the reap is observed.
const reapDeadline = 10 * time.Second

// reapPost sends one raw JSON-RPC POST to ts, optionally on an existing
// session, and returns the HTTP status and the Mcp-Session-Id response header.
// Raw HTTP is used deliberately: the shim client sends DELETE on Close, and
// these tests need clients that simply stop talking. Requests go through the
// server's own client rather than http.DefaultClient, whose idle connections
// every parallel test's httptest.Server.Close drops.
func reapPost(t *testing.T, ts *httptest.Server, sid, body string) (int, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, strings.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if sid != "" {
		req.Header.Set("Mcp-Session-Id", sid)
		req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	}
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Mcp-Session-Id")
}

// reapInit performs the initialize handshake and returns the session ID.
func reapInit(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	status, sid := reapPost(t, ts, "", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":`+
		`{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"c","version":"1"}}}`)
	require.Equal(t, http.StatusOK, status)
	require.NotEmpty(t, sid)
	reapPost(t, ts, sid, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	return sid
}

// reapPing sends a ping on sid and returns the HTTP status.
func reapPing(t *testing.T, ts *httptest.Server, sid string) int {
	t.Helper()
	status, _ := reapPost(t, ts, sid, `{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	return status
}

// registered reports whether the shim still holds an entry for sid.
func registered(s *MCPServer, sid string) bool {
	_, ok := s.sessions.Load(sid)
	return ok
}

// reapManager is a minimal shared SessionIdManager standing in for a
// cross-replica store. A terminated session is reported as terminated, together
// with terminatedErr, so both ways a manager can report termination are
// covered.
type reapManager struct {
	mu            sync.Mutex
	valid         map[string]bool
	terminated    map[string]bool
	terminatedErr error
}

func newReapManager(terminatedErr error) *reapManager {
	return &reapManager{valid: map[string]bool{}, terminated: map[string]bool{}, terminatedErr: terminatedErr}
}

func (m *reapManager) Generate() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := uuid.NewString()
	m.valid[id] = true
	return id
}

func (m *reapManager) Validate(id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.terminated[id] {
		return true, m.terminatedErr
	}
	if !m.valid[id] {
		return false, fmt.Errorf("session %q not found", id)
	}
	return false, nil
}

func (m *reapManager) Terminate(id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.valid, id)
	m.terminated[id] = true
	return false, nil
}

// boundSession returns the go-sdk session the shim has bound to sid.
func boundSession(t *testing.T, s *MCPServer, sid string) *gosdk.ServerSession {
	t.Helper()
	ss := goSessionOf(s, sid)
	require.NotNil(t, ss, "session %q must be registered", sid)
	return ss
}

// goSessionOf returns the go-sdk session bound to sid, or nil when the shim
// holds no entry for it.
func goSessionOf(s *MCPServer, sid string) *gosdk.ServerSession {
	v, ok := s.sessions.Load(sid)
	if !ok {
		return nil
	}
	return v.(*clientSession).goSession.Load()
}

// liveTimeout is the idle timeout of the tests that keep a session alive by
// pinging it. The pings arrive every liveTimeout/5, and a ping proves liveness
// only when it followed the previous one by less than liveTimeout/2: a longer
// gap is a stall of the runner (this package's tests run in parallel, under
// -race on CI) during which the timeout may have fired legitimately, so such a
// round is skipped rather than turned into a failure.
const liveTimeout = time.Second

// closedWhenEnded returns a channel that is closed once ss has ended.
func closedWhenEnded(ss *gosdk.ServerSession) <-chan struct{} {
	ended := make(chan struct{})
	go func() {
		_ = ss.Wait()
		close(ended)
	}()
	return ended
}

// TestSessionIdleTimeout_ReapsAbandonedSession verifies that a session whose
// client stops talking without sending DELETE is closed after the idle timeout
// and that the shim drops its entry, so the session no longer pins memory.
func TestSessionIdleTimeout_ReapsAbandonedSession(t *testing.T) {
	t.Parallel()
	srv := NewMCPServer("reap", "1.0.0")
	ts := httptest.NewServer(NewStreamableHTTPServer(srv, WithSessionIdleTimeout(time.Second)))
	t.Cleanup(ts.Close)

	sid := reapInit(t, ts)
	require.True(t, registered(srv, sid))
	require.True(t, srv.isLocalSession(sid))

	waitForWithin(t, reapDeadline, func() bool { return !registered(srv, sid) && !srv.isLocalSession(sid) },
		"abandoned session must be forgotten after the idle timeout")
	// The go-sdk handler drops the session from its own map just after the
	// session ends, so a request racing that step can still reach it.
	waitForWithin(t, reapDeadline, func() bool { return reapPing(t, ts, sid) == http.StatusNotFound },
		"a reaped session must no longer be served")
}

// TestSessionIdleTimeout_ActiveSessionIsKept verifies that requests arriving
// within the idle timeout keep a session alive well past the timeout, and that
// it is reaped once they stop.
func TestSessionIdleTimeout_ActiveSessionIsKept(t *testing.T) {
	t.Parallel()
	const timeout = liveTimeout
	srv := NewMCPServer("reap", "1.0.0")
	ts := httptest.NewServer(NewStreamableHTTPServer(srv, WithSessionIdleTimeout(timeout)))
	t.Cleanup(ts.Close)

	sid := reapInit(t, ts)
	prev := boundSession(t, srv, sid)
	last := time.Now()
	checked := 0
	for deadline := time.Now().Add(3 * timeout); time.Now().Before(deadline); {
		time.Sleep(timeout / 5)
		status := reapPing(t, ts, sid)
		gap := time.Since(last)
		last = time.Now()
		if gap >= timeout/2 {
			t.Logf("%v between pings, skipping the liveness check for this round", gap)
			if status != http.StatusOK {
				// The stall let the timeout reap the session; go on with a fresh one.
				sid = reapInit(t, ts)
				last = time.Now()
			}
			prev = goSessionOf(srv, sid)
			continue
		}
		require.Equal(t, http.StatusOK, status, "an active session must be served")
		cur := goSessionOf(srv, sid)
		if prev != nil {
			require.Same(t, prev, cur, "an active session must not be reaped")
			checked++
		}
		prev = cur
	}
	require.Positive(t, checked, "no ping followed the previous one within half the idle timeout")

	waitForWithin(t, reapDeadline, func() bool { return !registered(srv, sid) },
		"the session must be reaped once it goes idle")
}

// TestValidateTermination_ClosesLocalSession verifies that when the
// SessionIdManager reports a local session terminated, the shim rejects the
// request, drops its entry, and closes the go-sdk session (which releases its
// per-session go-sdk server) without waiting for an idle timeout, whether the
// manager reports the termination with an error or without one.
func TestValidateTermination_ClosesLocalSession(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		terminatedErr error
	}{
		{name: "terminated without error"},
		{name: "terminated with error", terminatedErr: errors.New("session terminated")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			mgr := newReapManager(tc.terminatedErr)
			srv := NewMCPServer("reap", "1.0.0")
			ts := httptest.NewServer(NewStreamableHTTPServer(srv, WithSessionIdManager(mgr)))
			t.Cleanup(ts.Close)

			sid := reapInit(t, ts)
			ended := closedWhenEnded(boundSession(t, srv, sid))

			_, _ = mgr.Terminate(sid)
			assert.Equal(t, http.StatusNotFound, reapPing(t, ts, sid),
				"a session the manager reports terminated must no longer be served")
			// The entry can reappear for an instant: notifications/initialized
			// was acknowledged before the session goroutine dispatched it, and a
			// dispatch that lands after the termination registers the session
			// again until the watcher of the closing go-sdk session drops it.
			waitFor(t, func() bool { return !registered(srv, sid) && !srv.isLocalSession(sid) },
				"the shim must drop the entry and local marker of a terminated session")
			requireClosed(t, ended, "the go-sdk session must be closed once the manager reports it terminated")
		})
	}
}

// TestSessionIdleTimeout_DeleteStillForgetsImmediately verifies that DELETE
// keeps releasing a session at once when an idle timeout is configured.
func TestSessionIdleTimeout_DeleteStillForgetsImmediately(t *testing.T) {
	t.Parallel()
	srv := NewMCPServer("reap", "1.0.0")
	ts := httptest.NewServer(NewStreamableHTTPServer(srv, WithSessionIdleTimeout(time.Minute)))
	t.Cleanup(ts.Close)

	sid := reapInit(t, ts)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodDelete, ts.URL, nil)
	require.NoError(t, err)
	req.Header.Set("Mcp-Session-Id", sid)
	resp, err := ts.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	// See TestValidateTermination_ClosesLocalSession for why this polls.
	waitFor(t, func() bool { return !registered(srv, sid) && !srv.isLocalSession(sid) },
		"DELETE must forget the session without waiting for the timeout")
}

// TestSessionIdleTimeout_ZeroKeepsSessionsUntilDelete pins the default: with no
// idle timeout configured, an idle session stays registered and served.
func TestSessionIdleTimeout_ZeroKeepsSessionsUntilDelete(t *testing.T) {
	t.Parallel()
	srv := NewMCPServer("reap", "1.0.0")
	ts := httptest.NewServer(NewStreamableHTTPServer(srv))
	t.Cleanup(ts.Close)

	sid := reapInit(t, ts)
	time.Sleep(300 * time.Millisecond)
	assert.True(t, registered(srv, sid))
	assert.Equal(t, http.StatusOK, reapPing(t, ts, sid))
}

// TestSessionIdleTimeout_ReapsRehydratedSession verifies that a session
// rehydrated from another replica is reaped by the same rule, and that a client
// returning afterwards is rehydrated again while the shared store still
// validates the session.
func TestSessionIdleTimeout_ReapsRehydratedSession(t *testing.T) {
	t.Parallel()
	const timeout = time.Second
	mgr := newReapManager(nil)

	srvA := NewMCPServer("A", "1.0.0")
	tsA := httptest.NewServer(NewStreamableHTTPServer(srvA,
		WithSessionIdManager(mgr), WithSessionIdleTimeout(timeout)))
	t.Cleanup(tsA.Close)

	srvB := NewMCPServer("B", "1.0.0")
	hsB := NewStreamableHTTPServer(srvB, WithSessionIdManager(mgr), WithSessionIdleTimeout(timeout))
	tsB := httptest.NewServer(hsB)
	t.Cleanup(tsB.Close)

	sid := reapInit(t, tsA)
	require.Equal(t, http.StatusOK, reapPing(t, tsB, sid))
	require.NotNil(t, hsB.getRehydrated(sid), "replica B must have rehydrated the session")
	require.True(t, registered(srvB, sid))

	waitForWithin(t, reapDeadline, func() bool { return hsB.getRehydrated(sid) == nil && !registered(srvB, sid) },
		"the rehydrated session must be reaped on replica B")
	waitForWithin(t, reapDeadline, func() bool { return !registered(srvA, sid) },
		"the idle session must be reaped on replica A")

	assert.Equal(t, http.StatusOK, reapPing(t, tsB, sid),
		"a returning client is rehydrated while the shared store still validates the session")
	assert.True(t, registered(srvB, sid))
}

// TestSessionIdleTimeout_ActiveRehydratedSessionIsKept verifies that requests
// keep a rehydrated session alive past the idle timeout: the replica serves
// them from the same reconstruction instead of reaping it between requests and
// rehydrating it again. It is reaped once the requests stop.
func TestSessionIdleTimeout_ActiveRehydratedSessionIsKept(t *testing.T) {
	t.Parallel()
	const timeout = liveTimeout
	mgr := newReapManager(nil)

	srvA := NewMCPServer("A", "1.0.0")
	tsA := httptest.NewServer(NewStreamableHTTPServer(srvA, WithSessionIdManager(mgr)))
	t.Cleanup(tsA.Close)

	srvB := NewMCPServer("B", "1.0.0")
	hsB := NewStreamableHTTPServer(srvB, WithSessionIdManager(mgr), WithSessionIdleTimeout(timeout))
	tsB := httptest.NewServer(hsB)
	t.Cleanup(tsB.Close)

	sid := reapInit(t, tsA)
	require.Equal(t, http.StatusOK, reapPing(t, tsB, sid))
	prev := hsB.getRehydrated(sid)
	require.NotNil(t, prev, "replica B must have rehydrated the session")
	last := time.Now()
	checked := 0
	for deadline := time.Now().Add(3 * timeout); time.Now().Before(deadline); {
		time.Sleep(timeout / 5)
		// A returning client is always served: after a stall that let the
		// timeout reap the session, this ping rehydrates it again.
		require.Equal(t, http.StatusOK, reapPing(t, tsB, sid), "an active session must be served")
		gap := time.Since(last)
		last = time.Now()
		cur := hsB.getRehydrated(sid)
		if prev != nil && gap < timeout/2 {
			require.Same(t, prev, cur, "an active rehydrated session must not be reaped")
			checked++
		} else {
			t.Logf("%v between pings, skipping the liveness check for this round", gap)
		}
		prev = cur
	}
	require.Positive(t, checked, "no ping followed the previous one within half the idle timeout")

	waitForWithin(t, reapDeadline, func() bool { return hsB.getRehydrated(sid) == nil && !registered(srvB, sid) },
		"the rehydrated session must be reaped once it goes idle")
}

// TestIdleTimer verifies the idle countdown used for rehydrated sessions: it
// fires once after the timeout, is paused while any POST is in flight, restarts
// when the last POST ends, and is inert once stopped or when disabled.
func TestIdleTimer(t *testing.T) {
	t.Parallel()
	const timeout = 500 * time.Millisecond
	tests := []struct {
		name      string
		timeout   time.Duration
		steps     func(it *idleTimer)
		wantFired bool
	}{
		{
			name:      "fires once when idle",
			timeout:   timeout,
			steps:     func(*idleTimer) {},
			wantFired: true,
		},
		{
			name:    "paused while a POST is in flight",
			timeout: timeout,
			steps:   func(it *idleTimer) { it.beginPOST() },
		},
		{
			name:    "paused until the last overlapping POST ends",
			timeout: timeout,
			steps: func(it *idleTimer) {
				it.beginPOST()
				it.beginPOST()
				it.endPOST()
			},
		},
		{
			name:    "restarts when the last POST ends",
			timeout: timeout,
			steps: func(it *idleTimer) {
				it.beginPOST()
				time.Sleep(2 * timeout)
				it.endPOST()
			},
			wantFired: true,
		},
		{
			name:    "stop cancels the countdown",
			timeout: timeout,
			steps:   func(it *idleTimer) { it.stop() },
		},
		{
			name:    "calls after stop are inert",
			timeout: timeout,
			steps: func(it *idleTimer) {
				it.stop()
				it.stop()
				it.beginPOST()
				it.endPOST()
			},
		},
		{
			name: "disabled when the timeout is not positive",
			steps: func(it *idleTimer) {
				it.beginPOST()
				it.endPOST()
				it.stop()
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var mu sync.Mutex
			fired := 0
			count := func() int {
				mu.Lock()
				defer mu.Unlock()
				return fired
			}
			it := newIdleTimer(tc.timeout, func() {
				mu.Lock()
				defer mu.Unlock()
				fired++
			})
			if tc.timeout <= 0 {
				require.Nil(t, it, "a non-positive timeout must disable the countdown")
			}

			tc.steps(it)
			if tc.wantFired {
				waitForWithin(t, reapDeadline, func() bool { return count() > 0 }, "the countdown must fire")
			}
			time.Sleep(3 * timeout)
			want := 0
			if tc.wantFired {
				want = 1
			}
			assert.Equal(t, want, count())
		})
	}
}

// TestForgetWhenClosed_KeepsEntryReboundToNewerSession verifies that the entry
// of a session the go-sdk closed on its own is dropped, but not when the entry
// was meanwhile bound to a newer go-sdk session for the same ID.
func TestForgetWhenClosed_KeepsEntryReboundToNewerSession(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := NewMCPServer("reap", "1.0.0")
	connect := func() *gosdk.ServerSession {
		_, st := gosdk.NewInMemoryTransports()
		ss, err := gosdk.NewServer(&gosdk.Implementation{Name: "x", Version: "1"}, nil).Connect(ctx, st, nil)
		require.NoError(t, err)
		return ss
	}

	first, second := connect(), connect()
	cs := s.bindSession("sess", first)
	require.Same(t, cs, s.bindSession("sess", second), "re-binding must reuse the entry")

	require.NoError(t, first.Close())
	time.Sleep(50 * time.Millisecond)
	require.True(t, registered(s, "sess"), "closing a superseded session must not drop the re-bound entry")

	require.NoError(t, second.Close())
	// Observe the removal under sessionsMu, which forgetSessionLocked holds
	// while it also closes the notification channel, so the send below is
	// ordered after that close.
	waitFor(t, func() bool {
		s.sessionsMu.Lock()
		defer s.sessionsMu.Unlock()
		return !registered(s, "sess")
	}, "closing the bound session must drop the entry")
	assert.Panics(t, func() { cs.notifCh <- mcp.JSONRPCNotification{} },
		"the entry's notification channel must be closed so its drain goroutine exits")
}
