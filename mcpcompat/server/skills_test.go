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

const pdfSkillURI = "skill://pdf-processing/SKILL.md"

// callerKey carries a per-request value set by WithHTTPContextFunc, standing in
// for the caller identity a host's HTTP middleware establishes.
type callerKey struct{}

// pdfSkill is the skill entry the test servers serve.
func pdfSkill() mcp.Skill {
	return mcp.Skill{
		URI: pdfSkillURI,
		Frontmatter: map[string]any{
			nameKey:       "pdf-processing",
			"description": "Extract, fill, and assemble PDF documents",
			"metadata":    map[string]any{"version": "2.1.0"},
		},
		Resources: mcp.SkillResources{Files: []mcp.SkillResource{
			{URI: pdfSkillURI, Digest: "sha256:d5e6", Size: 5120},
			{URI: "skill://pdf-processing/references/FORMS.md", Digest: "sha256:e6f7", Size: 18433},
		}},
	}
}

// skillsServer returns a server serving pdfSkill. skills/list reports the
// caller found in ctx as its cursor, so a test can see the request context;
// skills/get answers -32602 for any other URI, as the extension requires.
func skillsServer() *server.MCPServer {
	return server.NewMCPServer("compat-server", "1.2.3",
		server.WithResourceCapabilities(false, false),
		server.WithSkillsHandlers(
			func(ctx context.Context, req mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
				caller, _ := ctx.Value(callerKey{}).(string)
				res := &mcp.ListSkillsResult{Skills: []mcp.Skill{pdfSkill()}}
				res.NextCursor = mcp.Cursor(caller + "/" + string(req.Params.Cursor))
				return res, nil
			},
			func(_ context.Context, req mcp.GetSkillRequest) (*mcp.GetSkillResult, error) {
				if req.Params.URI != pdfSkillURI {
					return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "skill not found"}
				}
				return &mcp.GetSkillResult{Skill: pdfSkill()}, nil
			},
		),
	)
}

// startSkillsServer serves srv over Streamable HTTP with a context func that
// copies the X-Caller header into the request context, and returns an
// initialized client, which sends opts, with its initialize result.
func startSkillsServer(
	t *testing.T, srv *server.MCPServer, opts ...transport.StreamableHTTPCOption,
) (*client.Client, *mcp.InitializeResult) {
	t.Helper()
	ctx := context.Background()

	ts := httptest.NewServer(server.NewStreamableHTTPServer(srv,
		server.WithHTTPContextFunc(func(ctx context.Context, r *http.Request) context.Context {
			return context.WithValue(ctx, callerKey{}, r.Header.Get("X-Caller"))
		}),
	))
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

// TestSkills_EndToEnd serves the Skills extension on the compat server and
// drives it with the compat client over Streamable HTTP: the extension is
// declared, both methods round-trip a full skill entry, the handler sees the
// request context, and an unknown skill reaches the client as -32602.
func TestSkills_EndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c, initRes := startSkillsServer(t, skillsServer(),
		transport.WithHTTPHeaders(map[string]string{"X-Caller": "alice"}))

	assert.Equal(t, map[string]any{}, initRes.Capabilities.Extensions[mcp.ExtensionSkills],
		"declared with no settings: directoryRead is not served")
	assert.NotNil(t, initRes.Capabilities.Resources)

	listReq := mcp.ListSkillsRequest{}
	listReq.Params.Cursor = "c1"
	list, err := c.ListSkills(ctx, listReq)
	require.NoError(t, err)
	require.Len(t, list.Skills, 1)
	assert.Equal(t, pdfSkill(), list.Skills[0])
	assert.Equal(t, mcp.Cursor("alice/c1"), list.NextCursor, "cursor and request context reach the handler")

	got, err := c.GetSkill(ctx, mcp.GetSkillRequest{Params: mcp.GetSkillParams{URI: pdfSkillURI}})
	require.NoError(t, err)
	assert.Equal(t, pdfSkill(), got.Skill)

	_, err = c.GetSkill(ctx, mcp.GetSkillRequest{Params: mcp.GetSkillParams{URI: "skill://missing/SKILL.md"}})
	var wireErr *jsonrpc.Error
	require.True(t, errors.As(err, &wireErr), "got %T: %v", err, err)
	assert.Equal(t, int64(jsonrpc.CodeInvalidParams), wireErr.Code)
}

// TestSkills_NotDeclared checks that a server without WithSkillsHandlers
// declares no extension, and that calling the method on it fails. A go-sdk
// server rejects an unserved method at the HTTP layer rather than with
// method-not-found, which is why callers check the declaration first.
func TestSkills_NotDeclared(t *testing.T) {
	t.Parallel()

	c, initRes := startSkillsServer(t, server.NewMCPServer("compat-server", "1.2.3",
		server.WithToolCapabilities(false)))
	assert.NotContains(t, initRes.Capabilities.Extensions, mcp.ExtensionSkills)

	_, err := c.ListSkills(context.Background(), mcp.ListSkillsRequest{})
	require.Error(t, err)
}

// TestSkills_MissingHandlerFailsBuild checks that declaring the extension
// without both handlers fails the server build instead of advertising a
// method the server cannot answer.
func TestSkills_MissingHandlerFailsBuild(t *testing.T) {
	t.Parallel()

	srv := server.NewMCPServer("compat-server", "1.2.3", server.WithSkillsHandlers(
		func(context.Context, mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
			return &mcp.ListSkillsResult{}, nil
		},
		nil,
	))
	ts := httptest.NewServer(server.NewStreamableHTTPServer(srv))
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	t.Cleanup(func() { _ = c.Close() })
	_, err = c.Initialize(context.Background(), mcp.InitializeRequest{})
	require.Error(t, err)
}

// TestSkills_StdioHandleMessage checks the stdio HandleMessage bridge, which
// dispatches without a go-sdk server.
func TestSkills_StdioHandleMessage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	srv := skillsServer()

	decode := func(t *testing.T, msg mcp.JSONRPCMessage) map[string]any {
		t.Helper()
		b, err := json.Marshal(msg)
		require.NoError(t, err)
		var out map[string]any
		require.NoError(t, json.Unmarshal(b, &out))
		return out
	}

	init := decode(t, srv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)))
	caps := init["result"].(map[string]any)["capabilities"].(map[string]any)
	assert.Equal(t, map[string]any{mcp.ExtensionSkills: map[string]any{}}, caps["extensions"])

	list := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":2,"method":"skills/list","params":{"cursor":"x"}}`)))
	result := list["result"].(map[string]any)
	assert.Equal(t, "/x", result["nextCursor"])
	require.Len(t, result["skills"], 1)

	get := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":3,"method":"skills/get","params":{"uri":"skill://missing/SKILL.md"}}`)))
	assert.Equal(t, float64(jsonrpc.CodeInvalidParams), get["error"].(map[string]any)["code"])

	plain := server.NewMCPServer("compat-server", "1.2.3")
	unserved := decode(t, plain.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":4,"method":"skills/list"}`)))
	assert.Equal(t, float64(mcp.METHOD_NOT_FOUND), unserved["error"].(map[string]any)["code"])
}
