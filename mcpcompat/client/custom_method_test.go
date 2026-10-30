// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcpclient "github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// TestCallCustomMethod_ResumedSession checks that CallCustomMethod works over
// the client's resume path (a session resumed by ID without Initialize).
//
// It resumes on the replica that initialized the session. A session
// rehydrated on ANOTHER replica cannot serve custom methods with go-sdk
// v1.8.0: the Streamable HTTP transport checks a request's method against the
// server's custom methods only when go-sdk's own handler connected the session
// (connectStreamable sets the unexported connection.server); the shim's
// rehydration uses the public Server.Connect, so the transport checks against
// the standard methods alone and answers 400. The second half pins that
// limitation, so this test fails, and the limitation can be dropped, once
// go-sdk checks custom methods on any connected session.
func TestCallCustomMethod_ResumedSession(t *testing.T) {
	t.Parallel()

	mgr := newSharedSessionManager()
	newReplica := func(name string) *httptest.Server {
		s := server.NewMCPServer(name, "1.0.0",
			server.WithExtension("io.modelcontextprotocol/skills", nil),
			server.WithCustomMethod("skills/list", func(_ context.Context, params json.RawMessage) (json.RawMessage, error) {
				return json.Marshal(map[string]any{"replica": name, "params": params})
			}),
		)
		return httptest.NewServer(server.NewStreamableHTTPServer(s, server.WithSessionIdManager(mgr)))
	}
	tsA := newReplica("A")
	defer tsA.Close()
	tsB := newReplica("B")
	defer tsB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	client1, err := mcpclient.NewStreamableHttpClient(tsA.URL)
	require.NoError(t, err)
	require.NoError(t, client1.Start(ctx))
	initRes, err := client1.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err)
	defer func() { _ = client1.Close() }()
	assert.Contains(t, initRes.Capabilities.Extensions, "io.modelcontextprotocol/skills")

	resumed, err := mcpclient.NewStreamableHttpClient(tsA.URL, transport.WithSession(client1.GetSessionId()))
	require.NoError(t, err)
	require.NoError(t, resumed.Start(ctx))
	defer func() { _ = resumed.Close() }()

	out, err := resumed.CallCustomMethod(ctx, "skills/list", json.RawMessage(`{"cursor":"c"}`))
	require.NoError(t, err)
	var result struct {
		Replica string         `json:"replica"`
		Params  map[string]any `json:"params"`
	}
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Equal(t, "A", result.Replica)
	assert.Equal(t, "c", result.Params["cursor"])

	// No params sends none, rather than a JSON null.
	result.Params = nil
	out, err = resumed.CallCustomMethod(ctx, "skills/list", nil)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(out, &result))
	assert.Nil(t, result.Params)

	// Known go-sdk v1.8.0 limitation, see the doc comment above.
	rehydrated, err := mcpclient.NewStreamableHttpClient(tsB.URL, transport.WithSession(client1.GetSessionId()))
	require.NoError(t, err)
	require.NoError(t, rehydrated.Start(ctx))
	defer func() { _ = rehydrated.Close() }()
	_, err = rehydrated.CallCustomMethod(ctx, "skills/list", nil)
	require.ErrorContains(t, err, "HTTP 400")
}

// TestCallCustomMethod_NotInitialized checks the error before Initialize when
// no session is being resumed.
func TestCallCustomMethod_NotInitialized(t *testing.T) {
	t.Parallel()

	c, err := mcpclient.NewStreamableHttpClient("http://127.0.0.1:1")
	require.NoError(t, err)
	_, err = c.CallCustomMethod(context.Background(), "skills/list", nil)
	require.ErrorContains(t, err, "not initialized")
}
