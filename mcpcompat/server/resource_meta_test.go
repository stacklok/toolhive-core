// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package server_test

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client"
	"github.com/stacklok/toolhive-core/mcpcompat/mcp"
	"github.com/stacklok/toolhive-core/mcpcompat/server"
)

// TestAddResourceWithResult_MetaOnWire verifies that a resource handler
// registered via AddResourceWithResult has its _meta forwarded onto the
// resources/read wire result — the gap that dropped backend resource metadata
// before this registration path existed (toolhive-core#194).
func TestAddResourceWithResult_MetaOnWire(t *testing.T) {
	t.Parallel()

	const resourceURI = "file:///meta-resource"

	srv := server.NewMCPServer("meta-server", testClientVersion,
		server.WithResourceCapabilities(true, true),
	)
	srv.AddResourceWithResult(
		mcp.Resource{URI: resourceURI, Name: "meta-resource"},
		func(_ context.Context, req mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Result: mcp.Result{Meta: &mcp.Meta{
					AdditionalFields: map[string]any{"traceparent": "00-abc-01"},
				}},
				Contents: []mcp.ResourceContents{
					mcp.TextResourceContents{URI: req.Params.URI, Text: "with meta"},
				},
			}, nil
		},
	)

	res := readResourceOverHTTP(t, srv, resourceURI)
	require.Len(t, res.Contents, 1)
	require.NotNil(t, res.Meta, "handler _meta must reach the wire result")
	assert.Equal(t, "00-abc-01", res.Meta.AdditionalFields["traceparent"])
}

// TestAddResourceTemplateWithResult_MetaOnWire is the template twin of
// TestAddResourceWithResult_MetaOnWire: AddResourceTemplateWithResult must
// forward _meta from a templated read.
func TestAddResourceTemplateWithResult_MetaOnWire(t *testing.T) {
	t.Parallel()

	const (
		templateName = "meta-template"
		uriTemplate  = "file:///users/{id}"
		readURI      = "file:///users/42"
	)

	srv := server.NewMCPServer("meta-template-server", testClientVersion,
		server.WithResourceCapabilities(true, true),
	)
	srv.AddResourceTemplateWithResult(
		mcp.ResourceTemplate{Name: templateName, URITemplate: uriTemplate},
		func(_ context.Context, req mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
			return &mcp.ReadResourceResult{
				Result: mcp.Result{Meta: &mcp.Meta{
					AdditionalFields: map[string]any{"backend": "meta"},
				}},
				Contents: []mcp.ResourceContents{
					mcp.TextResourceContents{URI: req.Params.URI, Text: "template with meta"},
				},
			}, nil
		},
	)

	res := readResourceOverHTTP(t, srv, readURI)
	require.Len(t, res.Contents, 1)
	require.NotNil(t, res.Meta, "template handler _meta must reach the wire result")
	assert.Equal(t, "meta", res.Meta.AdditionalFields["backend"])
}

// TestAddResource_ContentsOnlyUnchanged pins the pre-existing shape: a
// contents-only handler registered via AddResource still compiles and serves
// contents with no _meta, exactly as before the WithResult path existed.
func TestAddResource_ContentsOnlyUnchanged(t *testing.T) {
	t.Parallel()

	const resourceURI = "file:///plain-resource"

	srv := server.NewMCPServer("plain-server", testClientVersion,
		server.WithResourceCapabilities(true, true),
	)
	srv.AddResource(
		mcp.Resource{URI: resourceURI, Name: "plain-resource"},
		func(_ context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
			return []mcp.ResourceContents{
				mcp.TextResourceContents{URI: req.Params.URI, Text: "plain body"},
			}, nil
		},
	)

	res := readResourceOverHTTP(t, srv, resourceURI)
	require.Len(t, res.Contents, 1)
	txt, ok := res.Contents[0].(mcp.TextResourceContents)
	require.True(t, ok, "contents must decode as text")
	assert.Equal(t, "plain body", txt.Text)
	assert.Nil(t, res.Meta, "contents-only registration must not synthesize _meta")
}

// readResourceOverHTTP serves srv over Streamable HTTP and issues a single
// resources/read for uri, returning the decoded result.
func readResourceOverHTTP(t *testing.T, srv *server.MCPServer, uri string) *mcp.ReadResourceResult {
	t.Helper()
	ctx := t.Context()

	httpSrv := server.NewStreamableHTTPServer(srv)
	ts := httptest.NewServer(httpSrv)
	t.Cleanup(ts.Close)

	c, err := client.NewStreamableHttpClient(ts.URL)
	require.NoError(t, err)
	require.NoError(t, c.Start(ctx))
	t.Cleanup(func() { _ = c.Close() })

	_, err = c.Initialize(ctx, mcp.InitializeRequest{
		Params: mcp.InitializeParams{
			ProtocolVersion: mcp.LATEST_PROTOCOL_VERSION,
			ClientInfo:      mcp.Implementation{Name: testClientName, Version: testClientVersion},
		},
	})
	require.NoError(t, err)

	res, err := c.ReadResource(ctx, mcp.ReadResourceRequest{Params: mcp.ReadResourceParams{URI: uri}})
	require.NoError(t, err)
	return res
}

// TestSessionResource_WithResult_MetaOnWire verifies the per-session twin of
// AddResourceWithResult: a ServerResource built with
// NewServerResourceWithResult and installed via SetSessionResources serves its
// handler's _meta on resources/read. This is the shape ToolHive's vMCP uses
// (per-session resource projection), so meta must survive it.
func TestSessionResource_WithResult_MetaOnWire(t *testing.T) {
	t.Parallel()

	const resourceURI = "file:///session-meta-resource"

	hooks := &server.Hooks{}
	hooks.AddOnRegisterSession(func(_ context.Context, s server.ClientSession) {
		swr, ok := s.(server.SessionWithResources)
		require.True(t, ok, "session must implement SessionWithResources")
		swr.SetSessionResources(map[string]server.ServerResource{
			resourceURI: server.NewServerResourceWithResult(
				mcp.Resource{URI: resourceURI, Name: "session-meta-resource"},
				func(_ context.Context, req mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
					return &mcp.ReadResourceResult{
						Result: mcp.Result{Meta: &mcp.Meta{
							AdditionalFields: map[string]any{"session": "meta"},
						}},
						Contents: []mcp.ResourceContents{
							mcp.TextResourceContents{URI: req.Params.URI, Text: "session body"},
						},
					}, nil
				},
			),
		})
	})

	srv := server.NewMCPServer("session-meta-server", testClientVersion,
		server.WithResourceCapabilities(true, true),
		server.WithHooks(hooks),
	)

	res := readResourceOverHTTP(t, srv, resourceURI)
	require.Len(t, res.Contents, 1)
	require.NotNil(t, res.Meta, "per-session WithResult handler _meta must reach the wire result")
	assert.Equal(t, "meta", res.Meta.AdditionalFields["session"])
}
