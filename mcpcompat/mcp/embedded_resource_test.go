// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

// TestUnmarshalContent_EmbeddedResource covers the chokepoint used by both
// tools/call and prompts/get: a "type":"resource" content item must decode into
// an EmbeddedResource whose polymorphic Resource field resolves to the correct
// concrete text/blob type. Before the custom UnmarshalJSON this errored,
// aborting the whole result decode.
func TestUnmarshalContent_EmbeddedResource(t *testing.T) {
	t.Parallel()

	t.Run("text resource", func(t *testing.T) {
		t.Parallel()
		wire := []byte(`{"type":"resource","resource":{"uri":"file:///x.txt","mimeType":"text/plain","text":"embedded body"}}`)

		c, err := mcp.UnmarshalContent(wire)
		require.NoError(t, err)

		er, ok := c.(mcp.EmbeddedResource)
		require.True(t, ok, "expected EmbeddedResource, got %T", c)
		trc, ok := er.Resource.(mcp.TextResourceContents)
		require.True(t, ok, "expected TextResourceContents, got %T", er.Resource)
		assert.Equal(t, "file:///x.txt", trc.URI)
		assert.Equal(t, "text/plain", trc.MIMEType)
		assert.Equal(t, "embedded body", trc.Text)
	})

	t.Run("blob resource", func(t *testing.T) {
		t.Parallel()
		wire := []byte(`{"type":"resource","resource":{"uri":"file:///x.png","mimeType":"image/png","blob":"UE5HREFUQQ=="}}`)

		c, err := mcp.UnmarshalContent(wire)
		require.NoError(t, err)

		er, ok := c.(mcp.EmbeddedResource)
		require.True(t, ok, "expected EmbeddedResource, got %T", c)
		brc, ok := er.Resource.(mcp.BlobResourceContents)
		require.True(t, ok, "expected BlobResourceContents, got %T", er.Resource)
		assert.Equal(t, "file:///x.png", brc.URI)
		assert.Equal(t, "image/png", brc.MIMEType)
		assert.Equal(t, "UE5HREFUQQ==", brc.Blob)
	})
}

// TestCallToolResult_MixedContent asserts that a single embedded resource no
// longer aborts the decode of sibling text/image parts.
func TestCallToolResult_MixedContent(t *testing.T) {
	t.Parallel()

	wire := []byte(`{"content":[` +
		`{"type":"text","text":"hello"},` +
		`{"type":"image","data":"UE5HREFUQQ==","mimeType":"image/png"},` +
		`{"type":"resource","resource":{"uri":"file:///x.txt","mimeType":"text/plain","text":"body"}}` +
		`]}`)

	var r mcp.CallToolResult
	require.NoError(t, json.Unmarshal(wire, &r))
	require.Len(t, r.Content, 3)

	txt, ok := r.Content[0].(mcp.TextContent)
	require.True(t, ok, "content[0] should be TextContent, got %T", r.Content[0])
	assert.Equal(t, "hello", txt.Text)

	img, ok := r.Content[1].(mcp.ImageContent)
	require.True(t, ok, "content[1] should be ImageContent, got %T", r.Content[1])
	assert.Equal(t, "image/png", img.MIMEType)

	er, ok := r.Content[2].(mcp.EmbeddedResource)
	require.True(t, ok, "content[2] should be EmbeddedResource, got %T", r.Content[2])
	trc, ok := er.Resource.(mcp.TextResourceContents)
	require.True(t, ok, "expected TextResourceContents, got %T", er.Resource)
	assert.Equal(t, "body", trc.Text)
}

// TestEmbeddedResource_RoundTrip decodes, re-marshals, and decodes again,
// asserting the concrete type and fields are stable across the round trip.
func TestEmbeddedResource_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		wire string
	}{
		{
			name: "text",
			wire: `{"type":"resource","resource":{"uri":"file:///x.txt","mimeType":"text/plain","text":"body"}}`,
		},
		{
			name: "blob",
			wire: `{"type":"resource","resource":{"uri":"file:///x.png","mimeType":"image/png","blob":"UE5HREFUQQ=="}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first, err := mcp.UnmarshalContent([]byte(tt.wire))
			require.NoError(t, err)

			remarshaled, err := mcp.MarshalContent(first)
			require.NoError(t, err)

			second, err := mcp.UnmarshalContent(remarshaled)
			require.NoError(t, err)

			assert.Equal(t, first, second)
		})
	}
}
