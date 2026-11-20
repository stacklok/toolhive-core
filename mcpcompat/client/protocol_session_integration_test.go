// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

// Session lifecycle: method-not-found versus termination, recovery, concurrency,
// deadlines, cancellation and disconnects over a real client.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestProtocolStatus_MethodNotFoundVersusTerminatedSession shows the two
// conditions are distinguishable through errors.Is, and that only genuine
// session termination invalidates the session.
func TestProtocolStatus_MethodNotFoundVersusTerminatedSession(t *testing.T) {
	t.Parallel()

	t.Run("server lacking an optional method reports method-not-found and keeps the session", func(t *testing.T) {
		t.Parallel()
		// The go-sdk server implements resources/list by default, so a server
		// that lacks it is modeled with receiving middleware returning the
		// JSON-RPC method-not-found error the SDK would send for an
		// unrecognized method. The error still travels the real wire path.
		ss := newStatusServer(t, nil, func(s *gosdk.Server) {
			s.AddReceivingMiddleware(func(next gosdk.MethodHandler) gosdk.MethodHandler {
				return func(ctx context.Context, method string, req gosdk.Request) (gosdk.Result, error) {
					if method == "resources/list" {
						return nil, &jsonrpc.Error{Code: jsonrpc.CodeMethodNotFound, Message: "resources/list not supported"}
					}
					return next(ctx, method, req)
				}
			})
		})
		c := newInitializedClient(t, ss.URL)

		ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
		defer cancel()
		_, err := c.ListResources(ctx, mcp.ListResourcesRequest{})
		require.Error(t, err)
		assert.True(t, errors.Is(err, mcp.ErrMethodNotFound), "got %v", err)
		assert.False(t, errors.Is(err, transport.ErrSessionTerminated), "got %v", err)

		require.NoError(t, c.Ping(ctx), "session must remain valid")
		requireUsable(t, c, "after-method-not-found")
	})

	t.Run("HTTP 404 carrying JSON-RPC method-not-found is not a terminated session", func(t *testing.T) {
		t.Parallel()
		// go-sdk servers negotiating newer protocol versions answer an unknown
		// method with HTTP 404 plus a -32601 body. A bare 404 means "session
		// gone", so the JSON-RPC code must win.
		arm := armed()
		ss := newStatusServer(t, onMethod("resources/list", arm, func(w http.ResponseWriter, call rpcCall) {
			writeRPCError(w, http.StatusNotFound, call.ID, int(jsonrpc.CodeMethodNotFound), "method not found", nil)
		}))
		c := newInitializedClient(t, ss.URL)

		ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
		defer cancel()
		_, err := c.ListResources(ctx, mcp.ListResourcesRequest{})
		require.Error(t, err)
		assert.True(t, errors.Is(err, mcp.ErrMethodNotFound), "got %v", err)
		assert.False(t, errors.Is(err, transport.ErrSessionTerminated), "got %v", err)

		requireUsable(t, c, "after-404-method-not-found")
	})

	t.Run("server-side session removal is reported as terminated, not method-not-found", func(t *testing.T) {
		t.Parallel()
		ss := newStatusServer(t, nil)
		c := newInitializedClient(t, ss.URL)
		requireUsable(t, c, "before-termination")

		// Terminate the session for real: a DELETE with the session ID makes the
		// SDK server drop it, so the next request gets a genuine 404.
		deleteSession(t, ss.URL, c.GetSessionId())

		ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
		defer cancel()
		_, err := callEcho(ctx, c, "x")
		require.Error(t, err)
		assert.True(t, errors.Is(err, transport.ErrSessionTerminated), "got %v", err)
		assert.False(t, errors.Is(err, mcp.ErrMethodNotFound), "got %v", err)
		assert.False(t, errors.Is(err, transport.ErrUnauthorized), "got %v", err)
	})
}

func deleteSession(t *testing.T, url, sessionID string) {
	t.Helper()
	require.NotEmpty(t, sessionID)
	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
	require.NoError(t, err)
	req.Header.Set("Mcp-Session-Id", sessionID)
	hc, err := isolatedHTTPClient()
	require.NoError(t, err)
	defer hc.CloseIdleConnections()
	resp, err := hc.Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Less(t, resp.StatusCode, 300, "session DELETE must succeed")
}

// isRPCError reports whether err carries a decoded JSON-RPC error with code and
// was NOT reclassified as an auth or session failure.
func isRPCError(err error, code int64) bool {
	var wire *jsonrpc.Error
	return errors.As(err, &wire) && wire.Code == code &&
		!errors.Is(err, transport.ErrUnauthorized) &&
		!errors.Is(err, transport.ErrSessionTerminated)
}

// isAuthChallenge reports whether err is an auth-required error carrying this
// suite's RFC 9728 resource_metadata URL.
func isAuthChallenge(err error) bool {
	var are *transport.AuthorizationRequiredError
	return errors.Is(err, transport.ErrUnauthorized) &&
		errors.As(err, &are) && are.ResourceMetadataURL == resourceMetadataURL
}

// TestProtocolStatus_RecoveryAfterRecoverableErrors drives several error kinds
// through ONE client, interleaved with successful calls, and checks that each
// failure is classified as its own kind (not as a previous call's error).
func TestProtocolStatus_RecoveryAfterRecoverableErrors(t *testing.T) {
	t.Parallel()

	type failure struct {
		respond func(w http.ResponseWriter, call rpcCall)
		check   func(err error) bool
	}
	failures := map[int32]failure{
		2: { // JSON-RPC error over HTTP 400
			respond: func(w http.ResponseWriter, call rpcCall) {
				writeRPCError(w, http.StatusBadRequest, call.ID, -32602, "invalid params", nil)
			},
			check: func(err error) bool { return isRPCError(err, -32602) },
		},
		4: { // JSON-RPC error over HTTP 200
			respond: func(w http.ResponseWriter, call rpcCall) {
				writeRPCError(w, http.StatusOK, call.ID, -32603, "internal tool failure", nil)
			},
			check: func(err error) bool { return isRPCError(err, -32603) },
		},
		6: { // transient 503 with a plain-text body
			respond: func(w http.ResponseWriter, _ rpcCall) {
				http.Error(w, "try later", http.StatusServiceUnavailable)
			},
			check: func(err error) bool {
				return err != nil &&
					strings.Contains(err.Error(), "request failed with status 503: try later") &&
					!errors.Is(err, transport.ErrUnauthorized) &&
					!errors.Is(err, transport.ErrSessionTerminated)
			},
		},
		8: { // 403 with a JSON-RPC body
			// Not -32003/-32004/-32005: go-sdk reserves those internally
			// (client closing, server closing, rejected by transport) and
			// surfaces a server error with -32003 as "connection closed",
			// dropping the *jsonrpc.Error.
			respond: func(w http.ResponseWriter, call rpcCall) {
				writeRPCError(w, http.StatusForbidden, call.ID, -32010, "forbidden by policy", nil)
			},
			check: func(err error) bool { return isRPCError(err, -32010) },
		},
		10: { // 401 with JSON-RPC body and challenge
			respond: func(w http.ResponseWriter, call rpcCall) {
				w.Header().Set("WWW-Authenticate", bearerChallenge)
				writeRPCError(w, http.StatusUnauthorized, call.ID, -32001, "expired", nil)
			},
			check: isAuthChallenge,
		},
	}

	var step atomic.Int32
	ss := newStatusServer(t, func(w http.ResponseWriter, r *http.Request, call rpcCall) bool {
		if r.Method != http.MethodPost || call.Method != "tools/call" {
			return false
		}
		f, ok := failures[step.Add(1)]
		if ok {
			f.respond(w, call)
		}
		return ok
	})
	c := newInitializedClient(t, ss.URL)
	sessionID := c.GetSessionId()
	require.NotEmpty(t, sessionID)

	ctx, cancel := context.WithTimeout(context.Background(), 4*statusTestTimeout)
	defer cancel()
	for i := int32(1); i <= 11; i++ {
		got, err := callEcho(ctx, c, fmt.Sprint(i))
		if f, ok := failures[i]; ok {
			require.Error(t, err, "call %d should fail", i)
			assert.True(t, f.check(err), "call %d classified wrongly: %v", i, err)
			continue
		}
		require.NoError(t, err, "call %d should succeed", i)
		assert.Equal(t, "echo: "+fmt.Sprint(i), got)
	}
	assert.Equal(t, sessionID, c.GetSessionId(), "the session must not have been replaced")
	assert.True(t, c.IsInitialized())
}

// triggerFault fails a tools/call according to its echo message: "401" gets an
// auth challenge with a JSON-RPC body, "400" a JSON-RPC invalid-params error.
// Any other message is served by the real server.
func triggerFault(w http.ResponseWriter, r *http.Request, call rpcCall) bool {
	if r.Method != http.MethodPost {
		return false
	}
	switch call.echoMessage() {
	case "401":
		w.Header().Set("WWW-Authenticate", bearerChallenge)
		writeRPCError(w, http.StatusUnauthorized, call.ID, -32001, "expired", nil)
		return true
	case "400":
		writeRPCError(w, http.StatusBadRequest, call.ID, -32602, "invalid", nil)
		return true
	}
	return false
}

// checkTriggeredCall sends trigger through callEcho and verifies the result
// matches what triggerFault does for it. It returns an error instead of using
// t so it is safe to call from goroutines.
func checkTriggeredCall(ctx context.Context, c *client.Client, trigger string) error {
	got, err := callEcho(ctx, c, trigger)
	switch trigger {
	case "401":
		if !isAuthChallenge(err) {
			return fmt.Errorf("%s: want auth challenge, got %v", trigger, err)
		}
	case "400":
		if !isRPCError(err, -32602) {
			return fmt.Errorf("%s: want JSON-RPC -32602 only, got %v", trigger, err)
		}
	default:
		if err != nil || got != "echo: "+trigger {
			return fmt.Errorf("%s: want success, got %q %v", trigger, got, err)
		}
	}
	return nil
}

// TestProtocolStatus_ConcurrentCallsOnOneClient fires failing and succeeding
// calls in parallel on ONE client. Error capture is scoped to each call's
// context, but every call goes through the same client RoundTripper, so this
// is where a leak between calls would show: one call's 401 challenge attached
// to another call's 400, or a successful call reporting an error.
func TestProtocolStatus_ConcurrentCallsOnOneClient(t *testing.T) {
	t.Parallel()
	const calls = 24
	triggers := []string{"401", "400", "ok"}

	ss := newStatusServer(t, triggerFault)
	c := newInitializedClient(t, ss.URL)
	sessionID := c.GetSessionId()

	ctx, cancel := context.WithTimeout(context.Background(), 2*statusTestTimeout)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, calls)
	for i := 0; i < calls; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if err := checkTriggeredCall(ctx, c, triggers[i%len(triggers)]); err != nil {
				errs <- fmt.Errorf("call %d: %w", i, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.Equal(t, sessionID, c.GetSessionId(), "the session must not have been replaced")
	requireUsable(t, c, "after-concurrent-calls")
}

// TestProtocolStatus_ConcurrentIndependentClients checks per-call capture state
// does not leak between separate clients running at the same time.
func TestProtocolStatus_ConcurrentIndependentClients(t *testing.T) {
	t.Parallel()
	const clients = 8

	// Even-indexed clients trigger a 401 challenge, odd ones a JSON-RPC 400.
	ss := newStatusServer(t, triggerFault)

	var wg sync.WaitGroup
	errs := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- runConcurrentClient(ss.URL, i)
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
}

// runConcurrentClient is goroutine-safe: it returns errors instead of using t.
func runConcurrentClient(url string, i int) error {
	c, err := newIsolatedClient(url)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()
	ctx, cancel := context.WithTimeout(context.Background(), 2*statusTestTimeout)
	defer cancel()
	if _, err := c.Initialize(ctx, initRequest()); err != nil {
		return fmt.Errorf("client %d initialize: %w", i, err)
	}
	trigger := "400"
	if i%2 == 0 {
		trigger = "401"
	}
	for round := 0; round < 5; round++ {
		for _, msg := range []string{trigger, "ok"} {
			if err := checkTriggeredCall(ctx, c, msg); err != nil {
				return fmt.Errorf("client %d round %d: %w", i, round, err)
			}
		}
	}
	return nil
}

// TestProtocolStatus_TimeoutAndCancellation verifies deadline and cancellation
// surface as context errors (not auth/session errors) and leave the session
// usable once the stalled request is released. The server signals when it has
// received the call, so cancellation never races the request.
func TestProtocolStatus_TimeoutAndCancellation(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		want error
	}{
		{"deadline", context.DeadlineExceeded},
		{"cancel", context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			arm := armed()
			entered := make(chan struct{})
			release := make(chan struct{})
			ss := newStatusServer(t, onMethod("tools/call", arm, func(w http.ResponseWriter, _ rpcCall) {
				close(entered)
				select { // stall until released or the test ends
				case <-release:
				case <-time.After(statusTestTimeout):
				}
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			// Registered after the server so it runs first: a failing assertion
			// must not leave ss.Close waiting on the stalled handler.
			var once sync.Once
			releaseOnce := func() { once.Do(func() { close(release) }) }
			t.Cleanup(releaseOnce)
			c := newInitializedClient(t, ss.URL)

			var ctx context.Context
			var cancel context.CancelFunc
			if tc.want == context.DeadlineExceeded {
				ctx, cancel = context.WithTimeout(context.Background(), 200*time.Millisecond)
			} else {
				ctx, cancel = context.WithCancel(context.Background())
				go func() {
					select {
					case <-entered:
						cancel()
					case <-time.After(statusTestTimeout):
						cancel()
					}
				}()
			}
			defer cancel()

			start := time.Now()
			_, err := callEcho(ctx, c, "x")
			require.Error(t, err)
			assert.Less(t, time.Since(start), statusTestTimeout/2, "call must not hang")
			if tc.want == context.Canceled { // cancellation was triggered by the server's signal
				select {
				case <-entered:
				default:
					t.Fatal("server never received the call")
				}
			}
			assert.True(t, errors.Is(err, tc.want), "want %v, got %v", tc.want, err)
			assert.False(t, errors.Is(err, transport.ErrUnauthorized))
			assert.False(t, errors.Is(err, transport.ErrSessionTerminated))

			// The deadline can expire before the stalled call reaches the
			// server, leaving the fault armed; disarm it so the recovery call
			// below is served by the real server rather than stalled.
			arm.Store(false)
			releaseOnce()
			requireUsable(t, c, "after-"+tc.name)
		})
	}
}

// TestProtocolStatus_ServerDisconnectDoesNotHang closes the server under an
// initialized client; calls must fail promptly and Close must return.
func TestProtocolStatus_ServerDisconnectDoesNotHang(t *testing.T) {
	t.Parallel()
	ss := newStatusServer(t, nil)
	c := newInitializedClient(t, ss.URL)
	requireUsable(t, c, "before-disconnect")

	ss.CloseClientConnections()
	ss.Close()

	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	_, err := callEcho(ctx, c, "x")
	require.Error(t, err)
	assert.False(t, errors.Is(err, context.DeadlineExceeded), "must fail on the broken connection, not stall: %v", err)
	assert.False(t, errors.Is(err, transport.ErrUnauthorized))

	done := make(chan struct{})
	go func() { _ = c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(statusTestTimeout):
		t.Fatal("Close hung after server disconnect")
	}
}
