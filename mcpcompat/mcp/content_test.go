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

// TestUnmarshalContent_EmbeddedResource_Text verifies that a "resource" content
// carrying a text resource decodes into an EmbeddedResource whose Resource is a
// TextResourceContents with all fields intact. Without EmbeddedResource's
// custom UnmarshalJSON, encoding/json cannot populate the ResourceContents
// interface field and this fails.
func TestUnmarshalContent_EmbeddedResource_Text(t *testing.T) {
	t.Parallel()

	data := []byte(`{
		"type": "resource",
		"resource": {
			"uri": "file:///a.txt",
			"mimeType": "text/plain",
			"text": "hello world"
		}
	}`)

	content, err := mcp.UnmarshalContent(data)
	require.NoError(t, err)

	er, ok := mcp.AsEmbeddedResource(content)
	require.True(t, ok, "expected EmbeddedResource, got %T", content)
	assert.Equal(t, mcp.ContentTypeResource, er.Type)

	text, ok := mcp.AsTextResourceContents(er.Resource)
	require.True(t, ok, "expected TextResourceContents, got %T", er.Resource)
	assert.Equal(t, "file:///a.txt", text.URI)
	assert.Equal(t, "text/plain", text.MIMEType)
	assert.Equal(t, "hello world", text.Text)
}

// TestUnmarshalContent_EmbeddedResource_Blob verifies that a "resource" content
// carrying a blob resource decodes into an EmbeddedResource whose Resource is a
// BlobResourceContents with all fields intact.
func TestUnmarshalContent_EmbeddedResource_Blob(t *testing.T) {
	t.Parallel()

	data := []byte(`{
		"type": "resource",
		"resource": {
			"uri": "file:///b.bin",
			"mimeType": "application/octet-stream",
			"blob": "ZGF0YQ=="
		}
	}`)

	content, err := mcp.UnmarshalContent(data)
	require.NoError(t, err)

	er, ok := mcp.AsEmbeddedResource(content)
	require.True(t, ok, "expected EmbeddedResource, got %T", content)
	assert.Equal(t, mcp.ContentTypeResource, er.Type)

	blob, ok := mcp.AsBlobResourceContents(er.Resource)
	require.True(t, ok, "expected BlobResourceContents, got %T", er.Resource)
	assert.Equal(t, "file:///b.bin", blob.URI)
	assert.Equal(t, "application/octet-stream", blob.MIMEType)
	assert.Equal(t, "ZGF0YQ==", blob.Blob)
}

// TestUnmarshalContent_EmbeddedResource_Absent verifies that an absent or null
// resource decodes gracefully to a nil Resource without panicking.
func TestUnmarshalContent_EmbeddedResource_Absent(t *testing.T) {
	t.Parallel()

	for name, data := range map[string]string{
		"missing": `{"type":"resource"}`,
		"null":    `{"type":"resource","resource":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			content, err := mcp.UnmarshalContent([]byte(data))
			require.NoError(t, err)

			er, ok := mcp.AsEmbeddedResource(content)
			require.True(t, ok, "expected EmbeddedResource, got %T", content)
			assert.Nil(t, er.Resource)
		})
	}
}

// TestCallToolResult_Unmarshal_WithEmbeddedResource_And_Siblings reproduces the
// exact downstream failure: a CallToolResult whose content mixes text, image,
// and an embedded resource. All three items must survive the unmarshal with
// their fields intact. Without EmbeddedResource.UnmarshalJSON the whole result
// decode errors and every sibling is lost.
func TestCallToolResult_Unmarshal_WithEmbeddedResource_And_Siblings(t *testing.T) {
	t.Parallel()

	data := []byte(`{
		"content": [
			{"type": "text", "text": "some text"},
			{"type": "image", "data": "ZGF0YQ==", "mimeType": "image/png"},
			{
				"type": "resource",
				"resource": {
					"uri": "file:///embedded.txt",
					"mimeType": "text/plain",
					"text": "embedded body"
				}
			}
		]
	}`)

	var result mcp.CallToolResult
	err := json.Unmarshal(data, &result)
	require.NoError(t, err)
	require.Len(t, result.Content, 3, "all three content items must survive")

	text, ok := mcp.AsTextContent(result.Content[0])
	require.True(t, ok, "expected TextContent, got %T", result.Content[0])
	assert.Equal(t, "some text", text.Text)

	img, ok := mcp.AsImageContent(result.Content[1])
	require.True(t, ok, "expected ImageContent, got %T", result.Content[1])
	assert.Equal(t, "ZGF0YQ==", img.Data)
	assert.Equal(t, "image/png", img.MIMEType)

	er, ok := mcp.AsEmbeddedResource(result.Content[2])
	require.True(t, ok, "expected EmbeddedResource, got %T", result.Content[2])
	embedded, ok := mcp.AsTextResourceContents(er.Resource)
	require.True(t, ok, "expected TextResourceContents, got %T", er.Resource)
	assert.Equal(t, "file:///embedded.txt", embedded.URI)
	assert.Equal(t, "text/plain", embedded.MIMEType)
	assert.Equal(t, "embedded body", embedded.Text)
}
