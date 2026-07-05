// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

const queryProp = "query"

// TestWireFormat_GoldenJSON pins the exact JSON wire shape of the re-exported
// types and constructors. These goldens are the equivalence spec: when the
// aliases in alias.go are later replaced by standalone definitions to drop the
// mcp-go dependency, these tests must continue to pass unchanged.
func TestWireFormat_GoldenJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		value    any
		wantJSON string
	}{
		{
			name:     "text content",
			value:    mcp.NewTextContent("hi"),
			wantJSON: `{"type":"text","text":"hi"}`,
		},
		{
			name:     "image content",
			value:    mcp.NewImageContent("ZGF0YQ==", "image/png"),
			wantJSON: `{"type":"image","data":"ZGF0YQ==","mimeType":"image/png"}`,
		},
		{
			name:     "audio content",
			value:    mcp.NewAudioContent("YXVkaW8=", "audio/wav"),
			wantJSON: `{"type":"audio","data":"YXVkaW8=","mimeType":"audio/wav"}`,
		},
		{
			name:     "tool result text",
			value:    mcp.NewToolResultText("hi"),
			wantJSON: `{"content":[{"type":"text","text":"hi"}]}`,
		},
		{
			name:     "tool result error",
			value:    mcp.NewToolResultError("boom"),
			wantJSON: `{"content":[{"type":"text","text":"boom"}],"isError":true}`,
		},
		{
			name:     "implementation",
			value:    mcp.Implementation{Name: "client", Version: "1.0.0"},
			wantJSON: `{"name":"client","version":"1.0.0"}`,
		},
		{
			name:     "call tool params",
			value:    mcp.CallToolParams{Name: "t", Arguments: map[string]any{"a": "b"}},
			wantJSON: `{"name":"t","arguments":{"a":"b"}}`,
		},
		{
			name: "resource link content",
			value: mcp.NewResourceLink(
				"file:///x", "x", "desc", "text/plain"),
			wantJSON: `{"type":"resource_link","uri":"file:///x","name":"x","description":"desc","mimeType":"text/plain"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := json.Marshal(tt.value)
			require.NoError(t, err)
			assert.JSONEq(t, tt.wantJSON, string(got))
		})
	}
}

// TestTool_StructLiteralWire mirrors how ToolHive builds tools in production:
// a struct literal (not the fluent builder) with an explicit InputSchema and
// annotations. It verifies the fields survive marshaling to the MCP wire shape.
func TestTool_StructLiteralWire(t *testing.T) {
	t.Parallel()

	tool := mcp.Tool{
		Name:        "search",
		Description: "search the index",
		InputSchema: mcp.ToolInputSchema{
			Type: "object",
			Properties: map[string]any{
				queryProp: map[string]any{"type": "string"},
			},
			Required: []string{queryProp},
		},
		Annotations: mcp.ToolAnnotation{},
	}

	raw, err := json.Marshal(tool)
	require.NoError(t, err)

	var got map[string]any
	require.NoError(t, json.Unmarshal(raw, &got))

	assert.Equal(t, "search", got["name"])
	assert.Equal(t, "search the index", got["description"])

	schema, ok := got["inputSchema"].(map[string]any)
	require.True(t, ok, "inputSchema must be an object")
	assert.Equal(t, "object", schema["type"])
	assert.Contains(t, schema, "properties")
	assert.Equal(t, []any{"query"}, schema["required"])
}

// TestCallToolRequest_Accessors mirrors how ToolHive handlers read arguments:
// via Params.Name and the argument accessor helpers.
func TestCallToolRequest_Accessors(t *testing.T) {
	t.Parallel()

	req := mcp.CallToolRequest{
		Params: mcp.CallToolParams{
			Name: "greet",
			Arguments: map[string]any{
				"name":  "ada",
				"count": float64(3),
				"loud":  true,
			},
		},
	}

	assert.Equal(t, "greet", req.Params.Name)

	args := req.GetArguments()
	assert.Equal(t, "ada", args["name"])

	assert.Equal(t, "ada", req.GetString("name", "default"))
	assert.Equal(t, "default", req.GetString("missing", "default"))
	assert.Equal(t, 3, req.GetInt("count", 0))
	assert.True(t, req.GetBool("loud", false))

	s, err := req.RequireString("name")
	require.NoError(t, err)
	assert.Equal(t, "ada", s)

	_, err = req.RequireString("missing")
	assert.Error(t, err)
}

// TestContent_InterfaceAndAsHelpers verifies the polymorphic Content interface
// and the As* type-assertion helpers used by ToolHive's content conversion.
func TestContent_InterfaceAndAsHelpers(t *testing.T) {
	t.Parallel()

	var content []mcp.Content
	content = append(content, mcp.NewTextContent("hello"))
	content = append(content, mcp.NewImageContent("ZGF0YQ==", "image/png"))

	txt, ok := mcp.AsTextContent(content[0])
	require.True(t, ok)
	assert.Equal(t, "hello", txt.Text)

	_, ok = mcp.AsImageContent(content[0])
	assert.False(t, ok, "text content is not image content")

	img, ok := mcp.AsImageContent(content[1])
	require.True(t, ok)
	assert.Equal(t, "image/png", img.MIMEType)

	assert.Equal(t, "hello", mcp.GetTextFromContent(content[0]))
}

// TestResourceContents_AsHelpers verifies the resource-contents helpers used
// when converting resource read results.
func TestResourceContents_AsHelpers(t *testing.T) {
	t.Parallel()

	var contents []mcp.ResourceContents
	contents = append(contents, mcp.TextResourceContents{URI: "file:///a", Text: "body"})
	contents = append(contents, mcp.BlobResourceContents{URI: "file:///b", Blob: "ZGF0YQ=="})

	txt, ok := mcp.AsTextResourceContents(contents[0])
	require.True(t, ok)
	assert.Equal(t, "body", txt.Text)

	blob, ok := mcp.AsBlobResourceContents(contents[1])
	require.True(t, ok)
	assert.Equal(t, "ZGF0YQ==", blob.Blob)
}

// TestNewToolFluentBuilder exercises the fluent tool builder that ToolHive uses
// only in its test/helper code (fake backends).
func TestNewToolFluentBuilder(t *testing.T) {
	t.Parallel()

	tool := mcp.NewTool("greet",
		mcp.WithDescription("greets a person"),
		mcp.WithString("name", mcp.Required()),
	)

	assert.Equal(t, "greet", tool.Name)
	assert.Equal(t, "greets a person", tool.Description)
	assert.Contains(t, tool.InputSchema.Properties, "name")
	assert.Contains(t, tool.InputSchema.Required, "name")
}

// TestProtocolConstants pins stable protocol-level values. These come straight
// from the MCP spec (JSON-RPC error codes, method names) and must be preserved
// verbatim by any future standalone reimplementation.
func TestProtocolConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, -32601, mcp.METHOD_NOT_FOUND)
	assert.Equal(t, -32602, mcp.INVALID_PARAMS)
	assert.Equal(t, -32603, mcp.INTERNAL_ERROR)

	assert.Equal(t, "tools/call", string(mcp.MethodToolsCall))
	assert.Equal(t, "tools/list", string(mcp.MethodToolsList))
	assert.Equal(t, "resources/read", string(mcp.MethodResourcesRead))
	assert.Equal(t, "prompts/get", string(mcp.MethodPromptsGet))
	assert.Equal(t, "initialize", string(mcp.MethodInitialize))

	assert.NotEmpty(t, mcp.LATEST_PROTOCOL_VERSION)

	assert.Equal(t, "accept", string(mcp.ElicitationResponseActionAccept))
	assert.Equal(t, "decline", string(mcp.ElicitationResponseActionDecline))
	assert.Equal(t, "cancel", string(mcp.ElicitationResponseActionCancel))
}

// Handler signature guards. These package-level assignments will fail to compile
// if the re-exported request/result types drift from the exact function shapes
// ToolHive's server package registers. They document the contract the
// mcpcompat/server adapters must satisfy.
var (
	_ = func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) { return nil, nil }
	_ = func(_ context.Context, _ mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) { return nil, nil }
	_ = func(_ context.Context, _ mcp.GetPromptRequest) (*mcp.GetPromptResult, error) { return nil, nil }
)
