// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

const (
	skillsExtension = "io.modelcontextprotocol/skills"
	skillsList      = "skills/list"
	skillsGet       = "skills/get"
)

// callerKey carries a per-request value set by WithHTTPContextFunc, standing in
// for the caller identity a host's HTTP middleware establishes.
type callerKey struct{}

// startExtensionServer serves srv over Streamable HTTP with a context func
// that copies the X-Caller header into the request context, and returns an
// initialized client, which sends opts, together with its initialize result.
func startExtensionServer(
	t *testing.T, srv *server.MCPServer, opts ...transport.StreamableHTTPCOption,
) (*client.Client, *mcp.InitializeResult) {
	t.Helper()
	ctx := context.Background()

	httpSrv := server.NewStreamableHTTPServer(srv,
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, callerKey{}, r.Header.Get("X-Caller"))
		}),
	)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL, opts...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	require.NoError(t, c.Start(ctx))

	initRes, err := c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)
	return c, initRes
}

// TestExtension_AdvertisedAndServedEndToEnd declares the skills extension and
// its two methods on the compat server, then drives them with the compat
// client over Streamable HTTP: the extension appears in the initialize result,
// params and results pass through member-for-member, and a handler's
// *jsonrpc.Error reaches the client with its code.
func TestExtension_AdvertisedAndServedEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	var gotParams json.RawMessage
	srv := server.NewMCPServer("compat-server", "1.2.3",
		server.WithResourceCapabilities(false, false),
		server.WithExtension(skillsExtension, map[string]any{"directoryRead": false}),
		server.WithCustomMethod(skillsList, func(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
			gotParams = params
			return json.RawMessage(`{"skills":[{"name":"pdf","uri":"skill://acme/pdf/SKILL.md"}],"nextCursor":"c2"}`), nil
		}),
		server.WithCustomMethod(skillsGet, func(_ context.Context, _ json.RawMessage) (json.RawMessage, error) {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "skill not found"}
		}),
	)
	c, initRes := startExtensionServer(t, srv)

	require.Contains(t, initRes.Capabilities.Extensions, skillsExtension)
	assert.Equal(t, map[string]any{"directoryRead": false}, initRes.Capabilities.Extensions[skillsExtension])
	assert.NotNil(t, initRes.Capabilities.Resources, "declaring an extension must not drop standard capabilities")

	out, err := c.CallCustomMethod(ctx, skillsList, json.RawMessage(`{"cursor":"c1","filter":{"tag":"docs"}}`))
	require.NoError(t, err)

	var params map[string]any
	require.NoError(t, json.Unmarshal(gotParams, &params))
	assert.Equal(t, "c1", params["cursor"])
	assert.Equal(t, map[string]any{"tag": "docs"}, params["filter"], "unknown params members pass through")

	var result map[string]any
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "c2", result["nextCursor"])
	require.Len(t, result["skills"], 1)
	assert.Equal(t, "pdf", result["skills"].([]any)[0].(map[string]any)["name"])

	_, err = c.CallCustomMethod(ctx, skillsGet, json.RawMessage(`{"uri":"skill://acme/missing/SKILL.md"}`))
	require.Error(t, err)
	var wireErr *jsonrpc.Error
	require.True(t, errors.As(err, &wireErr), "got %T: %v", err, err)
	assert.Equal(t, int64(jsonrpc.CodeInvalidParams), wireErr.Code)
	assert.Equal(t, "skill not found", wireErr.Message)
}

// TestCustomMethod_SeesRequestContext checks that a custom method handler runs
// with the per-request HTTP context values, as the standard handlers do, so a
// host can authorize it by caller identity.
func TestCustomMethod_SeesRequestContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("compat-server", "1.2.3",
		server.WithCustomMethod(skillsList, func(ctx context.Context, _ json.RawMessage) (json.RawMessage, error) {
			caller, _ := ctx.Value(callerKey{}).(string)
			return json.Marshal(map[string]any{"caller": caller})
		}),
	)
	c, _ := startExtensionServer(t, srv, transport.WithHTTPHeaders(map[string]string{"X-Caller": "alice"}))

	out, err := c.CallCustomMethod(ctx, skillsList, nil)
	require.NoError(t, err)
	assert.JSONEq(t, `{"caller":"alice"}`, string(out))
}

// TestCustomMethod_UnregisteredFails checks that calling a method the server
// does not serve fails. A go-sdk server rejects an unknown method at the HTTP
// layer (400) rather than with a JSON-RPC method-not-found, so callers check
// the server's declared extensions before calling instead of relying on the
// error code; the absent extension in the initialize result is that signal.
func TestCustomMethod_UnregisteredFails(t *testing.T) {
	t.Parallel()

	srv := server.NewMCPServer("compat-server", "1.2.3", server.WithToolCapabilities(false))
	c, initRes := startExtensionServer(t, srv)
	assert.Empty(t, initRes.Capabilities.Extensions)

	_, err := c.CallCustomMethod(context.Background(), skillsList, nil)
	require.Error(t, err)
}

// TestCustomMethod_InvalidRegistrationFailsBuild checks that a custom method
// that shadows a standard method, or has no handler, fails the server build
// instead of silently answering method-not-found.
func TestCustomMethod_InvalidRegistrationFailsBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		method string
		h      server.CustomMethodHandlerFunc
	}{
		{
			name:   "shadows a standard method",
			method: "tools/list",
			h: func(context.Context, json.RawMessage) (json.RawMessage, error) {
				return nil, nil
			},
		},
		{name: "nil handler", method: skillsList, h: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			srv := server.NewMCPServer("compat-server", "1.2.3", server.WithCustomMethod(tc.method, tc.h))
			ts := httptest.NewServer(server.NewStreamableHTTPServer(srv))
			t.Cleanup(ts.Close)

			c, err := client.NewStreamableHttpClient(ts.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })
			_, err = c.Initialize(context.Background(), mcp.InitializeRequest{
				Params: mcp.InitializeParams{
					ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
					ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
				},
			})
			require.Error(t, err)
		})
	}
}

// TestExtension_StdioHandleMessage checks the stdio HandleMessage bridge, which
// dispatches without a go-sdk server: it advertises declared extensions and
// routes custom methods to their handlers, keeping a *jsonrpc.Error's code.
func TestExtension_StdioHandleMessage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	srv := server.NewMCPServer("compat-server", "1.2.3",
		server.WithExtension(skillsExtension, nil),
		server.WithCustomMethod(skillsList, func(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"echo": params})
		}),
		server.WithCustomMethod(skillsGet, func(context.Context, json.RawMessage) (json.RawMessage, error) {
			return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "skill not found"}
		}),
	)

	encode := func(t *testing.T, msg mcp.JSONRPCMessage) map[string]any {
		t.Helper()
		b, err := json.Marshal(msg)
		require.NoError(t, err)
		var out map[string]any
		require.NoError(t, json.Unmarshal(b, &out))
		return out
	}

	init := encode(t, srv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)))
	caps := init["result"].(map[string]any)["capabilities"].(map[string]any)
	assert.Equal(t, map[string]any{skillsExtension: map[string]any{}}, caps["extensions"],
		"a nil settings map is advertised as the empty object")

	list := encode(t, srv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":2,"method":"skills/list","params":{"cursor":"x"}}`)))
	assert.Equal(t, map[string]any{"echo": map[string]any{"cursor": "x"}}, list["result"])

	get := encode(t, srv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":3,"method":"skills/get","params":{}}`)))
	assert.Equal(t, float64(jsonrpc.CodeInvalidParams), get["error"].(map[string]any)["code"])

	unknown := encode(t, srv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":4,"method":"skills/other"}`)))
	assert.Equal(t, float64(mcp.METHOD_NOT_FOUND), unknown["error"].(map[string]any)["code"])
}
