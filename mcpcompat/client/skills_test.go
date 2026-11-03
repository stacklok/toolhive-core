// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client_test

import (
	"context"
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

// TestSkills_ResumedSession checks ListSkills, GetSkill and ReadDirectory over
// the client's resume path (a session resumed by ID without Initialize).
//
// It resumes on the replica that initialized the session. A session
// rehydrated on ANOTHER replica cannot serve the skills methods with go-sdk
// v1.8.0 (see server.WithSkillsHandlers); the last step pins that limitation,
// so this test fails, and the limitation can be dropped, once go-sdk checks
// custom methods on any connected session.
func TestSkills_ResumedSession(t *testing.T) {
	t.Parallel()

	const uri = "skill://notes/SKILL.md"
	mgr := newSharedSessionManager()
	newReplica := func(name string) *httptest.Server {
		s := server.NewMCPServer(name, "1.0.0",
			server.WithResourceCapabilities(false, false),
			server.WithSkillsHandlers(
				func(_ context.Context, req mcp.ListSkillsRequest) (*mcp.ListSkillsResult, error) {
					res := &mcp.ListSkillsResult{}
					res.NextCursor = mcp.Cursor(name + "/" + string(req.Params.Cursor))
					return res, nil
				},
				func(_ context.Context, req mcp.GetSkillRequest) (*mcp.GetSkillResult, error) {
					return &mcp.GetSkillResult{Skill: mcp.Skill{
						URI:         req.Params.URI,
						Frontmatter: map[string]any{"name": "notes", "description": name},
						Resources:   mcp.SkillResources{Dynamic: true},
					}}, nil
				},
			),
			server.WithDirectoryReadHandler(
				func(_ context.Context, req mcp.ReadDirectoryRequest) (*mcp.ReadDirectoryResult, error) {
					return &mcp.ReadDirectoryResult{Resources: []mcp.Resource{
						{URI: req.Params.URI + "/" + name, Name: name, MIMEType: mcp.MIMETypeDirectory},
					}}, nil
				},
			),
		)
		return httptest.NewServer(server.NewStreamableHTTPServer(s, server.WithSessionIdManager(mgr)))
	}
	tsA := newReplica("A")
	defer tsA.Close()
	tsB := newReplica("B")
	defer tsB.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	initializer, err := mcpclient.NewStreamableHttpClient(tsA.URL)
	require.NoError(t, err)
	require.NoError(t, initializer.Start(ctx))
	_, err = initializer.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err)
	defer func() { _ = initializer.Close() }()
	sid := initializer.GetSessionId()

	resumed, err := mcpclient.NewStreamableHttpClient(tsA.URL, transport.WithSession(sid))
	require.NoError(t, err)
	require.NoError(t, resumed.Start(ctx))
	defer func() { _ = resumed.Close() }()

	listReq := mcp.ListSkillsRequest{}
	listReq.Params.Cursor = "c"
	list, err := resumed.ListSkills(ctx, listReq)
	require.NoError(t, err)
	assert.Equal(t, mcp.Cursor("A/c"), list.NextCursor)

	got, err := resumed.GetSkill(ctx, mcp.GetSkillRequest{Params: mcp.GetSkillParams{URI: uri}})
	require.NoError(t, err)
	assert.Equal(t, uri, got.Skill.URI)
	assert.True(t, got.Skill.Resources.Dynamic)

	dir, err := resumed.ReadDirectory(ctx, mcp.ReadDirectoryRequest{Params: mcp.ReadDirectoryParams{URI: "skill://notes"}})
	require.NoError(t, err)
	require.Len(t, dir.Resources, 1)
	assert.Equal(t, "skill://notes/A", dir.Resources[0].URI)

	// Known go-sdk v1.8.0 limitation, see the doc comment above.
	rehydrated, err := mcpclient.NewStreamableHttpClient(tsB.URL, transport.WithSession(sid))
	require.NoError(t, err)
	require.NoError(t, rehydrated.Start(ctx))
	defer func() { _ = rehydrated.Close() }()
	_, err = rehydrated.ListSkills(ctx, mcp.ListSkillsRequest{})
	require.ErrorContains(t, err, "HTTP 400")
}

// TestSkills_NotInitialized checks the error before Initialize when no session
// is being resumed.
func TestSkills_NotInitialized(t *testing.T) {
	t.Parallel()

	c, err := mcpclient.NewStreamableHttpClient("http://127.0.0.1:1")
	require.NoError(t, err)
	_, err = c.ListSkills(context.Background(), mcp.ListSkillsRequest{})
	require.ErrorContains(t, err, "not initialized")
	_, err = c.GetSkill(context.Background(), mcp.GetSkillRequest{})
	require.ErrorContains(t, err, "not initialized")
	_, err = c.ReadDirectory(context.Background(), mcp.ReadDirectoryRequest{})
	require.ErrorContains(t, err, "not initialized")
}
