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

const (
	schemaTypeObject = "object"
	keyProperties    = "properties"
)

// TestToolInputSchema_RoundTripPreservesCompositors verifies that a tool input
// schema using top-level JSON Schema keywords not modeled by ToolArgumentsSchema
// (oneOf/anyOf/allOf/$ref/enum/...) survives an unmarshal -> marshal round-trip,
// and that a schema without a top-level "type" does not gain a fabricated
// "type":"". Regression guard for stacklok/toolhive#5976.
func TestToolInputSchema_RoundTripPreservesCompositors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		inputSchema   string
		wantContains  []string // substrings that must survive the round-trip
		wantNoType    bool     // true => marshaled output must not contain a "type" key
		wantTypeValue string   // when non-empty, the "type" value that must be preserved
	}{
		{
			name: "top-level oneOf with no type",
			inputSchema: `{"oneOf":[` +
				`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]},` +
				`{"type":"object","properties":{"b":{"type":"string"}},"required":["b"]}]}`,
			wantContains: []string{"oneOf"},
			wantNoType:   true,
		},
		{
			name:         "anyOf with no type",
			inputSchema:  `{"anyOf":[{"type":"string"},{"type":"number"}]}`,
			wantContains: []string{"anyOf"},
			wantNoType:   true,
		},
		{
			name:         "properties without top-level type",
			inputSchema:  `{"properties":{"c":{"type":"string"}},"required":["c"]}`,
			wantContains: []string{keyProperties, "\"c\""},
			wantNoType:   true,
		},
		{
			name:          "ordinary object schema is unchanged",
			inputSchema:   `{"type":"object","properties":{"x":{"type":"string"}},"required":["x"]}`,
			wantContains:  []string{keyProperties, "\"x\""},
			wantTypeValue: schemaTypeObject,
		},
		{
			name:          "object schema with extra compositor keyword",
			inputSchema:   `{"type":"object","properties":{"x":{"type":"string"}},"allOf":[{"required":["x"]}]}`,
			wantContains:  []string{"allOf", keyProperties},
			wantTypeValue: schemaTypeObject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var schema mcp.ToolInputSchema
			require.NoError(t, json.Unmarshal([]byte(tt.inputSchema), &schema),
				"unmarshal must succeed")

			out, err := json.Marshal(schema)
			require.NoError(t, err, "marshal must succeed")

			var got map[string]any
			require.NoError(t, json.Unmarshal(out, &got), "remarshaled output must be valid JSON")

			for _, want := range tt.wantContains {
				assert.Contains(t, string(out), want,
					"round-trip must preserve %q; got %s", want, string(out))
			}

			if tt.wantNoType {
				if typ, ok := got["type"]; ok {
					assert.NotEqual(t, "", typ,
						"a schema without a top-level type must not gain a fabricated empty type; got %s", string(out))
				}
			}
			if tt.wantTypeValue != "" {
				assert.Equal(t, tt.wantTypeValue, got["type"],
					"top-level type must be preserved; got %s", string(out))
			}
		})
	}
}

// TestToolInputSchema_RoundTripThroughTool verifies the fidelity holds when the
// schema is nested inside a Tool decoded from a tools/list-style payload — the
// exact path a client takes when ingesting a backend's advertised tools.
func TestToolInputSchema_RoundTripThroughTool(t *testing.T) {
	t.Parallel()

	raw := `{
		"name": "compose",
		"description": "oneOf tool",
		"inputSchema": {"oneOf":[{"type":"object"},{"type":"string"}]}
	}`

	var tool mcp.Tool
	require.NoError(t, json.Unmarshal([]byte(raw), &tool))

	out, err := json.Marshal(tool.InputSchema)
	require.NoError(t, err)
	assert.Contains(t, string(out), "oneOf",
		"the oneOf compositor must survive ingestion into mcp.Tool; got %s", string(out))

	var got map[string]any
	require.NoError(t, json.Unmarshal(out, &got))
	if typ, ok := got["type"]; ok {
		assert.NotEqual(t, "", typ, "must not fabricate an empty top-level type; got %s", string(out))
	}
}
