// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

// Shared real-client/real-server harness for the protocol-status integration
// tests (ToolHive issue #7034). Every test in the protocol_*_integration_test.go
// files drives the real mcpcompat client over real HTTP against a real go-sdk
// Streamable HTTP server. A thin http.Handler sits in front of the SDK server
// only to inject faults (a non-2xx status, a JSON-RPC error body, an auth
// challenge) for selected requests; every other request, including the
// initialize handshake, is served by the real SDK handler.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	gosdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

const (
	// statusTestTimeout bounds every blocking call so a regression fails fast
	// instead of hanging the suite.
	statusTestTimeout = 10 * time.Second

	resourceMetadataURL = "https://mcp.example.test/.well-known/oauth-protected-resource"
	bearerChallenge     = `Bearer resource_metadata="` + resourceMetadataURL + `"`
)

// rpcCall is the JSON-RPC envelope fields a fault hook needs to match on.
type rpcCall struct {
	Method string          `json:"method"`
	ID     any             `json:"id"`
	Params json.RawMessage `json:"params"`
}

// echoMessage returns the echo tool's "message" argument of a tools/call, or ""
// for any other request. Faults use it to pick a failure per call.
func (c rpcCall) echoMessage() string {
	var p struct {
		Arguments echoInput `json:"arguments"`
	}
	if c.Method != "tools/call" || json.Unmarshal(c.Params, &p) != nil {
		return ""
	}
	return p.Arguments.Message
}

// fault decides whether to answer a request itself. It returns true when it has
// written the response; otherwise the real SDK handler serves the request.
type fault func(w http.ResponseWriter, r *http.Request, call rpcCall) bool

// statusServer is a real go-sdk MCP server (one "echo" tool, no resources or
// prompts) behind a fault-injecting front handler.
type statusServer struct {
	*httptest.Server
	deletes atomic.Int32 // session-cleanup DELETEs that reached the server
}

func newStatusServer(t *testing.T, f fault, serverOpts ...func(*gosdk.Server)) *statusServer {
	t.Helper()
	srv := newEchoSDKServer(&gosdk.Implementation{Name: "status-server", Version: "1.0.0"})
	for _, opt := range serverOpts {
		opt(srv)
	}
	sdkHandler := gosdk.NewStreamableHTTPHandler(func(*http.Request) *gosdk.Server { return srv }, nil)

	ss := &statusServer{}
	ss.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			ss.deletes.Add(1)
		}
		var call rpcCall
		if r.Method == http.MethodPost {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			_ = json.Unmarshal(body, &call) // best effort: non-JSON bodies leave call zero
			r.Body = io.NopCloser(bytes.NewReader(body))
		}
		if f != nil && f(w, r, call) {
			return
		}
		sdkHandler.ServeHTTP(w, r)
	}))
	t.Cleanup(ss.Close)
	return ss
}

// writeRPCError writes a JSON-RPC error response with the given HTTP status.
func writeRPCError(w http.ResponseWriter, status int, id any, code int, msg string, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	type rpcErr struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    any    `json:"data,omitempty"`
	}
	_ = json.NewEncoder(w).Encode(struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   rpcErr `json:"error"`
	}{"2.0", id, rpcErr{code, msg, data}})
}

// onMethod returns a fault that applies h to the first POST for method while
// armed is true, disarming it atomically so exactly one request is faulted even
// when several are in flight. Arming lets a test initialize cleanly first; a
// test may also disarm it itself if the targeted request never reached the
// server.
func onMethod(method string, armed *atomic.Bool, h func(w http.ResponseWriter, call rpcCall)) fault {
	return func(w http.ResponseWriter, r *http.Request, call rpcCall) bool {
		if r.Method != http.MethodPost || call.Method != method || !armed.CompareAndSwap(true, false) {
			return false
		}
		h(w, call)
		return true
	}
}

// newStatusClient builds an uninitialized client with its own HTTP transport.
// Sharing http.DefaultTransport would let one parallel test's server shutdown
// (httptest.Server.Close closes the default transport's idle connections) break
// another test's pooled connection.
func newStatusClient(t *testing.T, url string) *client.Client {
	t.Helper()
	c, err := newIsolatedClient(url)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func newIsolatedClient(url string) (*client.Client, error) {
	hc, err := isolatedHTTPClient()
	if err != nil {
		return nil, err
	}
	return client.NewStreamableHttpClient(url, transport.WithHTTPBasicClient(hc))
}

// isolatedHTTPClient returns an *http.Client with its own clone of the default
// transport, so its connection pool is not shared with other parallel tests.
func isolatedHTTPClient() (*http.Client, error) {
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("http.DefaultTransport is not an *http.Transport")
	}
	return &http.Client{Transport: base.Clone()}, nil
}

func newInitializedClient(t *testing.T, url string) *client.Client {
	t.Helper()
	c := newStatusClient(t, url)

	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	require.NoError(t, c.Start(ctx))
	_, err := c.Initialize(ctx, initRequest())
	require.NoError(t, err)
	return c
}

func initRequest() mcp.InitializeRequest {
	return mcp.InitializeRequest{Params: mcp.InitializeParams{
		ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
		ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
	}}
}

func callEcho(ctx context.Context, c *client.Client, msg string) (string, error) {
	res, err := c.CallTool(ctx, mcp.CallToolRequest{Params: mcp.CallToolParams{
		Name: echoToolName, Arguments: echoInput{Message: msg},
	}})
	if err != nil {
		return "", err
	}
	if len(res.Content) != 1 {
		return "", fmt.Errorf("unexpected content length %d", len(res.Content))
	}
	txt, ok := mcp.AsTextContent(res.Content[0])
	if !ok {
		return "", errors.New("content is not text")
	}
	return txt.Text, nil
}

// requireUsable asserts the same client still completes a real tool call.
func requireUsable(t *testing.T, c *client.Client, msg string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), statusTestTimeout)
	defer cancel()
	got, err := callEcho(ctx, c, msg)
	require.NoError(t, err, "client must stay usable on the same session")
	assert.Equal(t, "echo: "+msg, got)
}

func armed() *atomic.Bool {
	b := &atomic.Bool{}
	b.Store(true)
	return b
}
