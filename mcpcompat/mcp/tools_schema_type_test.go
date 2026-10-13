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

// TestToolInputSchema_NonStringType verifies a top-level schema "type" that is
// not a string — most importantly a JSON Schema type array such as
// ["object","null"], which is valid JSON Schema — decodes without error and is
// re-emitted verbatim. Before, it failed with "cannot unmarshal array into Go
// struct field .type of type string", which failed the whole tools/list page the
// tool arrived in.
func TestToolInputSchema_NonStringType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		schema   string
		wantType string // Type field after decoding
		wantJSON string // "type" value that must be re-emitted, as raw JSON
	}{
		{
			name:     "type array",
			schema:   `{"type":["object","null"],"properties":{"a":{"type":"string"}}}`,
			wantType: "",
			wantJSON: `["object","null"]`,
		},
		{
			name:     "single-element type array",
			schema:   `{"type":["object"]}`,
			wantType: "",
			wantJSON: `["object"]`,
		},
		{
			name:     "string type is unchanged",
			schema:   `{"type":"object","properties":{"a":{"type":"string"}}}`,
			wantType: schemaTypeObject,
			wantJSON: `"object"`,
		},
		{
			name:     "other non-string type is preserved rather than failing the schema",
			schema:   `{"type":5}`,
			wantType: "",
			wantJSON: `5`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var schema mcp.ToolInputSchema
			require.NoError(t, json.Unmarshal([]byte(tt.schema), &schema))
			assert.Equal(t, tt.wantType, schema.Type)

			out, err := json.Marshal(schema)
			require.NoError(t, err)

			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &got))
			assert.JSONEq(t, tt.wantJSON, string(got["type"]),
				"top-level type must round-trip unchanged; got %s", string(out))
		})
	}
}

// TestTool_TypeArraySchemasThroughTool verifies a tool whose input and output
// schemas both use a type array survives ingestion into mcp.Tool and a
// re-marshal: the neighbouring fields are kept, the type arrays are re-emitted,
// and the output schema is not dropped (an output schema is only emitted when it
// declares a top-level type, which for a type array lives outside Type).
func TestTool_TypeArraySchemasThroughTool(t *testing.T) {
	t.Parallel()

	raw := `{
		"name": "nullable",
		"description": "nullable object schemas",
		"inputSchema": {"type":["object","null"],"properties":{"q":{"type":"string"}},"required":["q"]},
		"outputSchema": {"type":["object","null"],"properties":{"r":{"type":"string"}}}
	}`

	var tool mcp.Tool
	require.NoError(t, json.Unmarshal([]byte(raw), &tool))
	assert.Equal(t, "nullable", tool.Name)

	out, err := json.Marshal(tool)
	require.NoError(t, err)

	var got struct {
		InputSchema  map[string]json.RawMessage `json:"inputSchema"`
		OutputSchema map[string]json.RawMessage `json:"outputSchema"`
	}
	require.NoError(t, json.Unmarshal(out, &got))

	assert.JSONEq(t, `["object","null"]`, string(got.InputSchema["type"]))
	assert.JSONEq(t, `{"q":{"type":"string"}}`, string(got.InputSchema[keyProperties]))
	assert.JSONEq(t, `["q"]`, string(got.InputSchema["required"]))

	require.NotNil(t, got.OutputSchema, "output schema with a type array must not be dropped; got %s", string(out))
	assert.JSONEq(t, `["object","null"]`, string(got.OutputSchema["type"]))
	assert.JSONEq(t, `{"r":{"type":"string"}}`, string(got.OutputSchema[keyProperties]))
}

// TestToolInputSchema_TypeReplacedOnReuse verifies a present "type" replaces
// whatever the receiver held before, in both directions. encoding/json decodes
// into existing elements in place (for example into a reused []Tool), so a stale
// string Type must not survive over a newly decoded type array, which
// MarshalJSON would otherwise write after the preserved one.
func TestToolInputSchema_TypeReplacedOnReuse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		first    string
		second   string
		wantType string
		wantJSON string
	}{
		{
			name:     "string then array",
			first:    `{"type":"object"}`,
			second:   `{"type":["object","null"]}`,
			wantType: "",
			wantJSON: `["object","null"]`,
		},
		{
			name:     "array then string",
			first:    `{"type":["object","null"],"oneOf":[{"type":"object"}]}`,
			second:   `{"type":"object","oneOf":[{"type":"object"}]}`,
			wantType: schemaTypeObject,
			wantJSON: `"object"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var schema mcp.ToolInputSchema
			require.NoError(t, json.Unmarshal([]byte(tt.first), &schema))
			require.NoError(t, json.Unmarshal([]byte(tt.second), &schema))
			assert.Equal(t, tt.wantType, schema.Type)

			out, err := json.Marshal(schema)
			require.NoError(t, err)

			var got map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(out, &got))
			assert.JSONEq(t, tt.wantJSON, string(got["type"]),
				"the second decode's type must win; got %s", string(out))
		})
	}
}

// TestTool_RawSchemaConflictWithTypeArray verifies the raw-versus-structured
// schema conflict check still fires when the structured schema's type is a type
// array. That type lives in Extra rather than Type, so a check on Type alone would
// let both be set and silently emit the raw schema.
func TestTool_RawSchemaConflictWithTypeArray(t *testing.T) {
	t.Parallel()

	const typeArray = `{"type":["object","null"]}`

	tests := []struct {
		name    string
		prepare func(t *testing.T) mcp.Tool
		wantErr string
	}{
		{
			name: "input schema",
			prepare: func(t *testing.T) mcp.Tool {
				t.Helper()
				tool := mcp.Tool{Name: "conflict", RawInputSchema: json.RawMessage(`{"type":"object"}`)}
				require.NoError(t, json.Unmarshal([]byte(typeArray), &tool.InputSchema))
				return tool
			},
			wantErr: "both InputSchema and RawInputSchema",
		},
		{
			name: "output schema",
			prepare: func(t *testing.T) mcp.Tool {
				t.Helper()
				tool := mcp.Tool{Name: "conflict", RawOutputSchema: json.RawMessage(`{"type":"object"}`)}
				require.NoError(t, json.Unmarshal([]byte(typeArray), &tool.OutputSchema))
				return tool
			},
			wantErr: "both OutputSchema and RawOutputSchema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := json.Marshal(tt.prepare(t))
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}
