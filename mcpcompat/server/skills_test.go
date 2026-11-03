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

// skillsServer returns a server serving pdfSkill, plus opts. skills/list
// reports the caller found in ctx as its cursor, so a test can see the request
// context; skills/get answers -32602 for any other URI, as the extension
// requires.
func skillsServer(opts ...server.ServerOption) *server.MCPServer {
	return server.NewMCPServer("compat-server", "1.2.3", append([]server.ServerOption{
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
	}, opts...)...)
}

// pdfTemplatesURI is the one directory readTemplates serves.
const pdfTemplatesURI = "skill://pdf-processing/templates"

// readTemplates is a resources/directory/read handler serving
// pdfTemplatesURI, echoing the request cursor as nextCursor; any other URI
// answers -32602, as the extension requires.
func readTemplates(_ context.Context, req mcp.ReadDirectoryRequest) (*mcp.ReadDirectoryResult, error) {
	if req.Params.URI != pdfTemplatesURI {
		return nil, &jsonrpc.Error{Code: jsonrpc.CodeInvalidParams, Message: "not a directory"}
	}
	res := &mcp.ReadDirectoryResult{Resources: []mcp.Resource{
		{URI: pdfTemplatesURI + "/invoice.md", Name: "invoice.md", MIMEType: "text/markdown"},
		{URI: pdfTemplatesURI + "/regional", Name: "regional", MIMEType: mcp.MIMETypeDirectory},
	}}
	res.NextCursor = req.Params.Cursor
	return res, nil
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

// TestSkills_DirectoryReadEndToEnd serves the optional
// resources/directory/read method alongside the skills methods: directoryRead
// is declared, children round-trip with the directory MIME type, the cursor
// reaches the handler, and a non-directory reaches the client as -32602.
func TestSkills_DirectoryReadEndToEnd(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	c, initRes := startSkillsServer(t, skillsServer(server.WithDirectoryReadHandler(readTemplates)))
	assert.Equal(t, map[string]any{mcp.SkillsSettingDirectoryRead: true},
		initRes.Capabilities.Extensions[mcp.ExtensionSkills])

	got, err := c.ReadDirectory(ctx, mcp.ReadDirectoryRequest{
		Params: mcp.ReadDirectoryParams{URI: pdfTemplatesURI, Cursor: "p2"},
	})
	require.NoError(t, err)
	require.Len(t, got.Resources, 2)
	assert.Equal(t, "invoice.md", got.Resources[0].Name)
	assert.Equal(t, mcp.MIMETypeDirectory, got.Resources[1].MIMEType)
	assert.Equal(t, mcp.Cursor("p2"), got.NextCursor)

	_, err = c.ReadDirectory(ctx, mcp.ReadDirectoryRequest{Params: mcp.ReadDirectoryParams{URI: pdfSkillURI}})
	var wireErr *jsonrpc.Error
	require.True(t, errors.As(err, &wireErr), "got %T: %v", err, err)
	assert.Equal(t, int64(jsonrpc.CodeInvalidParams), wireErr.Code)

	// The skills methods are unaffected by the optional one.
	_, err = c.ListSkills(ctx, mcp.ListSkillsRequest{})
	require.NoError(t, err)
}

// TestSkills_DirectoryReadMisconfiguredFailsBuild checks that directory reads
// without the Skills extension that declares them, or without a handler, fail
// the server build.
func TestSkills_DirectoryReadMisconfiguredFailsBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		srv  *server.MCPServer
	}{
		{
			name: "without WithSkillsHandlers",
			srv:  server.NewMCPServer("compat-server", "1.2.3", server.WithDirectoryReadHandler(readTemplates)),
		},
		{
			name: "nil handler",
			srv:  skillsServer(server.WithDirectoryReadHandler(nil)),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts := httptest.NewServer(server.NewStreamableHTTPServer(tc.srv))
			t.Cleanup(ts.Close)

			c, err := client.NewStreamableHttpClient(ts.URL)
			require.NoError(t, err)
			t.Cleanup(func() { _ = c.Close() })
			_, err = c.Initialize(context.Background(), mcp.InitializeRequest{})
			require.Error(t, err)
		})
	}
}

// TestSkills_StdioEdgeCases checks that the stdio bridge answers as the
// go-sdk path does for a misconfigured extension, an empty listing, a handler
// returning (nil, nil) and a panicking handler.
func TestSkills_StdioEdgeCases(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	decode := func(t *testing.T, msg mcp.JSONRPCMessage) map[string]any {
		t.Helper()
		b, err := json.Marshal(msg)
		require.NoError(t, err)
		var out map[string]any
		require.NoError(t, json.Unmarshal(b, &out))
		return out
	}
	const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// A misconfigured extension is not advertised: the bridge has no build
	// step to fail, so it must not declare methods it will not answer.
	misconfigured := server.NewMCPServer("compat-server", "1.2.3", server.WithSkillsHandlers(
		func(context.Context, mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
			return &mcp.ListSkillsResult{}, nil
		},
		nil,
	))
	init := decode(t, misconfigured.HandleMessage(ctx, json.RawMessage(initialize)))
	assert.NotContains(t, init["result"].(map[string]any)["capabilities"], "extensions")

	srv := server.NewMCPServer("compat-server", "1.2.3",
		server.WithResourceCapabilities(false, false),
		server.WithSkillsHandlers(
			func(context.Context, mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
				return &mcp.ListSkillsResult{}, nil
			},
			func(context.Context, mcp.GetSkillRequest) (*mcp.GetSkillResult, error) {
				return nil, nil
			},
		),
		server.WithDirectoryReadHandler(func(context.Context, mcp.ReadDirectoryRequest) (*mcp.ReadDirectoryResult, error) {
			panic("boom")
		}),
	)

	// An empty listing encodes as an empty array, not null.
	b, err := json.Marshal(srv.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":2,"method":"skills/list"}`)))
	require.NoError(t, err)
	assert.Contains(t, string(b), `"skills":[]`)

	nilResult := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":3,"method":"skills/get","params":{"uri":"skill://a/SKILL.md"}}`)))
	assert.Equal(t, float64(mcp.INTERNAL_ERROR), nilResult["error"].(map[string]any)["code"])

	panicked := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":4,"method":"resources/directory/read","params":{"uri":"skill://a"}}`)))
	assert.Equal(t, float64(mcp.INTERNAL_ERROR), panicked["error"].(map[string]any)["code"])
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
	// The extension requires Resources. skillsServer declares them with
	// WithResourceCapabilities but registers none, as the go-sdk path allows.
	assert.Contains(t, caps, "resources")

	list := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":2,"method":"skills/list","params":{"cursor":"x"}}`)))
	result := list["result"].(map[string]any)
	assert.Equal(t, "/x", result["nextCursor"])
	require.Len(t, result["skills"], 1)

	get := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":3,"method":"skills/get","params":{"uri":"skill://missing/SKILL.md"}}`)))
	assert.Equal(t, float64(jsonrpc.CodeInvalidParams), get["error"].(map[string]any)["code"])

	// Without WithDirectoryReadHandler the optional method is not served.
	noDir := decode(t, srv.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":4,"method":"resources/directory/read","params":{"uri":"skill://pdf-processing/templates"}}`)))
	assert.Equal(t, float64(mcp.METHOD_NOT_FOUND), noDir["error"].(map[string]any)["code"])

	withDir := skillsServer(server.WithDirectoryReadHandler(readTemplates))
	init = decode(t, withDir.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":5,"method":"initialize","params":{}}`)))
	caps = init["result"].(map[string]any)["capabilities"].(map[string]any)
	assert.Equal(t, map[string]any{mcp.ExtensionSkills: map[string]any{mcp.SkillsSettingDirectoryRead: true}},
		caps["extensions"])
	dir := decode(t, withDir.HandleMessage(ctx, json.RawMessage(
		`{"jsonrpc":"2.0","id":6,"method":"resources/directory/read","params":{"uri":"skill://pdf-processing/templates"}}`)))
	require.Len(t, dir["result"].(map[string]any)["resources"], 2)

	plain := server.NewMCPServer("compat-server", "1.2.3")
	unserved := decode(t, plain.HandleMessage(ctx, json.RawMessage(`{"jsonrpc":"2.0","id":7,"method":"skills/list"}`)))
	assert.Equal(t, float64(mcp.METHOD_NOT_FOUND), unserved["error"].(map[string]any)["code"])
}
