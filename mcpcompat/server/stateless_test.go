// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// TestStateless_BasicRequestResponse verifies the happy path for MCP
// 2026-07-28 stateless serving: a POST with no Mcp-Session-Id is answered
// (200, application/json) directly, with no Mcp-Session-Id in the response
// either — there is no session to hand a client an ID for.
func TestStateless_BasicRequestResponse(t *testing.T) {
	t.Parallel()

	mcpSrv := server.NewMCPServer("stateless", "1.0.0")
	addGreetTool(mcpSrv)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(true))
	ts := httptest.NewServer(s)
	// t.Cleanup, not defer: the subtests below call t.Parallel() and so pause
	// until this function returns, resuming afterward — a plain defer would
	// close ts before they run. Cleanup runs only once every subtest completes.
	t.Cleanup(ts.Close)

	t.Run("tools/list", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp := postRPC(ctx, t, ts.URL, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"),
			"stateless responses must still reply application/json (JSONResponse mode)")
		assert.Empty(t, resp.Header.Get("Mcp-Session-Id"), "a stateless response must never carry a session ID")
		r := readFirstResult(t, resp)
		require.Nil(t, r.Error, "tools/list should not error")
		var res struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		}
		require.NoError(t, json.Unmarshal(r.Result, &res))
		names := make([]string, 0, len(res.Tools))
		for _, tl := range res.Tools {
			names = append(names, tl.Name)
		}
		assert.Contains(t, names, "greet")
	})

	t.Run("tools/call", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		body := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"greet","arguments":{}}}`
		resp := postRPC(ctx, t, ts.URL, "", body)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.True(t, strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json"))
		assert.Empty(t, resp.Header.Get("Mcp-Session-Id"))
		r := readFirstResult(t, resp)
		require.Nil(t, r.Error, "tools/call should not error")
		var res struct {
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		}
		require.NoError(t, json.Unmarshal(r.Result, &res))
		require.NotEmpty(t, res.Content)
		assert.Equal(t, "hello", res.Content[0].Text)
	})
}

// TestStateless_ListAndDiscoverCacheScopePrivate verifies the fix for the
// cacheScope cross-identity hazard: go-sdk's setDefaultCacheableValues stamps
// every list/discover result's IN-BODY Cacheable.CacheScope with "public",
// with no awareness that, under stateless serving, that same result is
// produced by the shim's per-identity before-hook projection
// (sessionDispatchMiddleware). sessionDispatchMiddleware must rewrite that
// hint to "private" before the response is serialized, so an MCP-aware cache
// never treats one identity's projected list/discover result as shareable with
// another identity. See TestStateful_ListToolsCacheScopePrivate for the same
// guarantee on the stateful path.
func TestStateless_ListAndDiscoverCacheScopePrivate(t *testing.T) {
	t.Parallel()

	const resourceURI = "file:///r"
	mcpSrv := server.NewMCPServer("stateless-cachescope", "1.0.0")
	addGreetTool(mcpSrv)
	mcpSrv.AddResource(
		mcp.Resource{URI: resourceURI, Name: "r", MIMEType: "text/plain"},
		func(context.Context, mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: resourceURI, MIMEType: "text/plain", Text: "hi"},
			}, nil
		},
	)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(true))
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	t.Run("tools/list", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		resp := postRPC(ctx, t, ts.URL, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
		r := readFirstResult(t, resp)
		require.Nil(t, r.Error, "tools/list should not error")
		var res struct {
			CacheScope string `json:"cacheScope"`
		}
		require.NoError(t, json.Unmarshal(r.Result, &res))
		assert.Equal(t, "private", res.CacheScope,
			"a stateless tools/list result is per-identity projected and must never be marked cacheScope:public")
	})

	t.Run("server/discover", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// server/discover is only recognized when the request's _meta carries
		// io.modelcontextprotocol/protocolVersion:"2026-07-28" (SEP-2575's
		// per-request new-protocol signal; see go-sdk's ServerSession.handle),
		// so this is sent via a raw request rather than postRPC: postRPC always
		// sets Mcp-Protocol-Version: 2025-06-18, which go-sdk rejects as
		// mismatched against a 2026-07-28 _meta on the very same request.
		body := `{"jsonrpc":"2.0","id":2,"method":"server/discover","params":{"_meta":{` +
			`"io.modelcontextprotocol/protocolVersion":"2026-07-28",` +
			`"io.modelcontextprotocol/clientInfo":{"name":"test","version":"1.0"},` +
			`"io.modelcontextprotocol/clientCapabilities":{}}}}`
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", bothAcceptMediaTypesForTest)
		req.Header.Set("MCP-Protocol-Version", "2026-07-28")
		// 2026-07-28's standard-headers requirement (SEP-2575) mandates an
		// Mcp-Method header mirroring the body's method for any request once
		// Mcp-Protocol-Version >= 2026-07-28.
		req.Header.Set("Mcp-Method", "server/discover")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		r := readFirstResult(t, resp)
		require.Nil(t, r.Error, "server/discover should not error")
		var res struct {
			CacheScope string `json:"cacheScope"`
		}
		require.NoError(t, json.Unmarshal(r.Result, &res))
		assert.Equal(t, "private", res.CacheScope,
			"a stateless server/discover result must never be marked cacheScope:public")
	})

	t.Run("resources/read", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		// resources/read runs its handler with the caller's bridged identity and
		// can return per-identity content, so its go-sdk-default cacheScope:"public"
		// hint is the same cross-identity cache-leak risk as a projected list.
		resp := postRPC(ctx, t, ts.URL, "",
			`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"file:///r"}}`)
		r := readFirstResult(t, resp)
		require.Nil(t, r.Error, "resources/read should not error")
		var res struct {
			CacheScope string `json:"cacheScope"`
		}
		require.NoError(t, json.Unmarshal(r.Result, &res))
		assert.Equal(t, "private", res.CacheScope,
			"a stateless resources/read result is served per-identity and must never be marked cacheScope:public")
	})
}

// TestStateful_ListToolsCacheScopePrivate pins that the rewrite is NOT
// stateless-only. A stateful server is per-identity projected at least as much
// as a stateless one: registerAndSync installs the SessionWithTools/Resources/
// ResourceTemplates/Prompts overlays onto that session's own go-sdk server
// (syncSession*), and that path runs only when !stateless — stateless projects
// tools alone. The identity bridge in sessionDispatchMiddleware is likewise not
// gated on serving mode. So go-sdk's default cacheScope:"public" is just as
// wrong here, and must be narrowed to "private" on this path too.
func TestStateful_ListToolsCacheScopePrivate(t *testing.T) {
	t.Parallel()

	mcpSrv := server.NewMCPServer("stateful-cachescope", "1.0.0")
	addGreetTool(mcpSrv)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(false))
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	sid := initSession(t, ts.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp := postRPC(ctx, t, ts.URL, sid, `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`)
	r := readFirstResult(t, resp)
	require.Nil(t, r.Error, "tools/list should not error")
	var res struct {
		CacheScope string `json:"cacheScope"`
	}
	require.NoError(t, json.Unmarshal(r.Result, &res))
	assert.Equal(t, "private", res.CacheScope,
		"a stateful tools/list result carries this session's tool overlay and must never be marked cacheScope:public")
}

// TestStateless_GETAndDELETENotAllowed verifies that a stateless server has no
// stream to open and no session to terminate, so go-sdk answers both GET and
// DELETE with 405, carrying the RFC 9110-mandated Allow header.
func TestStateless_GETAndDELETENotAllowed(t *testing.T) {
	t.Parallel()

	mcpSrv := server.NewMCPServer("stateless", "1.0.0")
	addGreetTool(mcpSrv)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(true))
	ts := httptest.NewServer(s)
	// t.Cleanup, not defer: see TestStateless_BasicRequestResponse.
	t.Cleanup(ts.Close)

	tests := []struct {
		name   string
		method string
	}{
		{name: "GET", method: http.MethodGet},
		{name: "DELETE", method: http.MethodDelete},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, tt.method, ts.URL, nil)
			require.NoError(t, err)
			req.Header.Set("Accept", bothAcceptMediaTypesForTest)
			if tt.method == http.MethodDelete {
				// A stale/foreign session ID must not change the outcome: the
				// stateless short-circuit skips DELETE handling entirely.
				req.Header.Set("Mcp-Session-Id", "some-stale-id")
			}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer func() { _ = resp.Body.Close() }()
			assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
			assert.Equal(t, "POST", resp.Header.Get("Allow"),
				"RFC 9110 section 15.5.6 requires an Allow header on 405")
		})
	}
}

// bothAcceptMediaTypesForTest mirrors the Accept header value the go-sdk
// Streamable HTTP handler requires.
const bothAcceptMediaTypesForTest = "application/json, text/event-stream"

// identityCtxKey is the context key the isolation test's HTTPContextFunc uses
// to stash the caller's identity, read back by the before-list-tools hook.
type identityCtxKey struct{}

// identityHeader carries the test caller's identity into WithHTTPContextFunc.
const identityHeader = "X-Test-Identity"

// TestStateless_Isolation is the load-bearing security regression for this PR:
// under go-sdk's stateless mode, every POST gets a temp session with
// ID()=="". Before the fix, contextWithSession keyed the shared s.sessions
// registry by "" (sessionFor("") -> LoadOrStore), so every concurrent
// stateless request — regardless of caller identity — collapsed onto ONE
// clientSession, meaning identity A's per-session tool overlay was visible to
// (and clobbered by) identity B's concurrent request. This test drives many
// concurrent identities and asserts each only ever sees its OWN
// identity-scoped tool.
func TestStateless_Isolation(t *testing.T) {
	t.Parallel()

	hooks := &server.Hooks{}
	hooks.AddBeforeListTools(func(ctx context.Context, _ any, _ *mcp.ListToolsRequest) {
		identity, _ := ctx.Value(identityCtxKey{}).(string)
		sess := server.ClientSessionFromContext(ctx)
		if sess == nil {
			return
		}
		swt, ok := sess.(server.SessionWithTools)
		if !ok {
			return
		}
		toolName := "only_" + identity
		swt.SetSessionTools(map[string]server.ServerTool{
			toolName: {
				Tool: mcp.NewTool(toolName, mcp.WithDescription("identity-scoped tool")),
				Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("ok"), nil
				},
			},
		})
	})

	// No global tools: every tool observed must have come from the per-request
	// overlay the hook above installs.
	mcpSrv := server.NewMCPServer("iso", "1.0.0", server.WithHooks(hooks), server.WithToolCapabilities(false))
	s := server.NewStreamableHTTPServer(
		mcpSrv,
		server.WithStateless(true),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, identityCtxKey{}, r.Header.Get(identityHeader))
		}),
	)
	ts := httptest.NewServer(s)
	defer ts.Close()

	const goroutines = 50
	const iterations = 100

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		identity, other := "A", "B"
		if g%2 == 1 {
			identity, other = "B", "A"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				names, err := statelessListToolNames(ts.URL, identity)
				if err != nil {
					errCh <- fmt.Errorf("identity %s: %w", identity, err)
					return
				}
				if !containsName(names, "only_"+identity) {
					errCh <- fmt.Errorf("identity %s: response missing its own tool only_%s (got %v)",
						identity, identity, names)
					return
				}
				if containsName(names, "only_"+other) {
					errCh <- fmt.Errorf("CROSS-IDENTITY LEAK: identity %s observed only_%s (got %v)",
						identity, other, names)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// TestStateless_Isolation_SharedClientSuppliedSessionID is a second angle on
// the same isolation guarantee as TestStateless_Isolation, but with every
// concurrent request carrying the SAME (stale/attacker-chosen)
// Mcp-Session-Id header. This is the header shape go-sdk's (off-by-default)
// allowsessionsinstateless=1 MCPGODEBUG compatibility flag would carry through
// to the go-sdk ServerSession's ID() on a legacy (<2026-07-28) stateless POST
// — see bindSessionForDispatch (server.go) for why a non-empty ss.ID() must
// not, by itself, be trusted to route into the shared session registry under
// stateless. This test cannot toggle that env var (read once at process
// init; see TestBindSessionForDispatch_StatelessForcesEphemeralRegardlessOfSessionID
// for the direct unit-level proof), but it pins the observable, end-to-end
// behavior: even with every request presenting the identical session id
// header, each identity only ever sees its own per-request tool overlay.
func TestStateless_Isolation_SharedClientSuppliedSessionID(t *testing.T) {
	t.Parallel()

	hooks := &server.Hooks{}
	hooks.AddBeforeListTools(func(ctx context.Context, _ any, _ *mcp.ListToolsRequest) {
		identity, _ := ctx.Value(identityCtxKey{}).(string)
		sess := server.ClientSessionFromContext(ctx)
		if sess == nil {
			return
		}
		swt, ok := sess.(server.SessionWithTools)
		if !ok {
			return
		}
		toolName := "only_" + identity
		swt.SetSessionTools(map[string]server.ServerTool{
			toolName: {
				Tool: mcp.NewTool(toolName, mcp.WithDescription("identity-scoped tool")),
				Handler: func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
					return mcp.NewToolResultText("ok"), nil
				},
			},
		})
	})

	mcpSrv := server.NewMCPServer("iso-shared-id", "1.0.0", server.WithHooks(hooks), server.WithToolCapabilities(false))
	s := server.NewStreamableHTTPServer(
		mcpSrv,
		server.WithStateless(true),
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, identityCtxKey{}, r.Header.Get(identityHeader))
		}),
	)
	ts := httptest.NewServer(s)
	defer ts.Close()

	const goroutines = 50
	const iterations = 100
	const sharedStaleSessionID = "attacker-shared-session-id"

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines)
	for g := 0; g < goroutines; g++ {
		identity, other := "A", "B"
		if g%2 == 1 {
			identity, other = "B", "A"
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				names, err := statelessListToolNames(ts.URL, identity, sharedStaleSessionID)
				if err != nil {
					errCh <- fmt.Errorf("identity %s: %w", identity, err)
					return
				}
				if !containsName(names, "only_"+identity) {
					errCh <- fmt.Errorf("identity %s: response missing its own tool only_%s (got %v)",
						identity, identity, names)
					return
				}
				if containsName(names, "only_"+other) {
					errCh <- fmt.Errorf("CROSS-IDENTITY LEAK (shared session id): identity %s observed only_%s (got %v)",
						identity, other, names)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// statelessListToolNames issues a stateless tools/list POST carrying the
// given identity header and, if sessionID is non-empty, a Mcp-Session-Id
// header set to it (exercising the "client sends a session id under
// stateless" shape without relying on go-sdk actually honoring it). It
// returns the returned tool names.
func statelessListToolNames(url, identity string, sessionID ...string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	body := `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", bothAcceptMediaTypesForTest)
	req.Header.Set("MCP-Protocol-Version", "2025-06-18")
	req.Header.Set(identityHeader, identity)
	if len(sessionID) > 0 && sessionID[0] != "" {
		req.Header.Set("Mcp-Session-Id", sessionID[0])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	var r rpcResult
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, err
	}
	if r.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", r.Error.Message)
	}
	var res struct {
		Tools []struct {
			Name string `json:"name"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names, nil
}

func containsName(names []string, name string) bool {
	for _, n := range names {
		if n == name {
			return true
		}
	}
	return false
}

// statelessSpySessionManager is a SessionIdManager test double that records
// how many times each method was invoked, via atomic counters so it can be
// safely read from the test goroutine after concurrent driving from the
// server. Mirrors the sharedSessionManager pattern in rehydration_test.go
// (named distinctly from discover_fallback_test.go's countingSessionManager,
// which counts a different, narrower subset for a different test).
type statelessSpySessionManager struct {
	generateCalls  atomic.Int64
	validateCalls  atomic.Int64
	terminateCalls atomic.Int64
}

func (m *statelessSpySessionManager) Generate() string {
	m.generateCalls.Add(1)
	return "should-never-be-called"
}

func (m *statelessSpySessionManager) Validate(string) (bool, error) {
	m.validateCalls.Add(1)
	return false, nil
}

func (m *statelessSpySessionManager) Terminate(string) (bool, error) {
	m.terminateCalls.Add(1)
	return false, nil
}

// TestStateless_SessionIdManagerNeverConsulted verifies that a configured
// SessionIdManager is inert under WithStateless(true): go-sdk's stateless
// path never consults GetSessionID, and the shim's own DELETE/rehydration/
// local-session-validation branches (which would otherwise drive
// Validate/Terminate) are skipped entirely by the ServeHTTP short-circuit.
func TestStateless_SessionIdManagerNeverConsulted(t *testing.T) {
	t.Parallel()

	mgr := &statelessSpySessionManager{}
	mcpSrv := server.NewMCPServer("stateless", "1.0.0")
	addGreetTool(mcpSrv)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(true), server.WithSessionIdManager(mgr))
	ts := httptest.NewServer(s)
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	listResp := postRPC(ctx, t, ts.URL, "", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	listResult := readFirstResult(t, listResp)
	require.Nil(t, listResult.Error)

	callBody := `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"greet","arguments":{}}}`
	callResp := postRPC(ctx, t, ts.URL, "", callBody)
	callResult := readFirstResult(t, callResp)
	require.Nil(t, callResult.Error)

	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL, nil)
	require.NoError(t, err)
	getReq.Header.Set("Accept", bothAcceptMediaTypesForTest)
	getResp, err := http.DefaultClient.Do(getReq)
	require.NoError(t, err)
	_ = getResp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, getResp.StatusCode)

	delReq, err := http.NewRequestWithContext(ctx, http.MethodDelete, ts.URL, nil)
	require.NoError(t, err)
	delReq.Header.Set("Mcp-Session-Id", "some-stale-id")
	delResp, err := http.DefaultClient.Do(delReq)
	require.NoError(t, err)
	_ = delResp.Body.Close()
	assert.Equal(t, http.StatusMethodNotAllowed, delResp.StatusCode)

	assert.Equal(t, int64(0), mgr.generateCalls.Load(), "Generate must never be called under stateless serving")
	assert.Equal(t, int64(0), mgr.validateCalls.Load(), "Validate must never be called under stateless serving")
	assert.Equal(t, int64(0), mgr.terminateCalls.Load(), "Terminate must never be called under stateless serving")
}

// TestStateful_RegressionSessionIDStillIssued pins the divergence: a server
// explicitly configured WithStateless(false) (the default) still runs go-sdk's
// stateful path, so an initialize response still carries an Mcp-Session-Id and
// the session is usable on follow-up requests. This guards against a future
// change accidentally flipping the default or breaking the stateful path
// while adding stateless support.
func TestStateful_RegressionSessionIDStillIssued(t *testing.T) {
	t.Parallel()

	mcpSrv := server.NewMCPServer("stateful", "1.0.0")
	addGreetTool(mcpSrv)
	s := server.NewStreamableHTTPServer(mcpSrv, server.WithStateless(false))
	ts := httptest.NewServer(s)
	defer ts.Close()

	sid := initSession(t, ts.URL)
	assert.NotEmpty(t, sid, "a stateful initialize response must carry a session ID")
	assert.Contains(t, listToolNames(t, ts.URL, sid), "greet")
}
