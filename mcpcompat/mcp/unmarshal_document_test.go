// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package mcp_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	mcp "github.com/stacklok/toolhive-core/mcpcompat/mcp"
)

const unchanged = "unchanged"

func TestMetaUnmarshalJSONDocumentAndNumbers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid", `{"progressToken":1e400,"value":1e400}`, true},
		{"trailing garbage", `{"value":1} garbage`, false},
		{"multiple values", `{"value":1} {}`, false},
		{"malformed", `{"value":`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			meta := mcp.Meta{ProgressToken: unchanged, AdditionalFields: map[string]any{unchanged: true}}
			before := meta
			err := meta.UnmarshalJSON([]byte(tt.input))
			if !tt.valid {
				require.Error(t, err)
				require.Equal(t, before, meta)
				return
			}

			require.NoError(t, err)
			require.Equal(t, json.Number("1e400"), meta.ProgressToken)
			require.Equal(t, json.Number("1e400"), meta.AdditionalFields["value"])
		})
	}
}

func TestToolArgumentsSchemaUnmarshalJSONDocumentAndNumbers(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		valid bool
	}{
		{"valid", `{"type":"object","properties":{"value":{"maximum":1e400}}}`, true},
		{"trailing garbage", `{"type":"object"} garbage`, false},
		{"multiple values", `{"type":"object"} {}`, false},
		{"malformed", `{"type":`, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			schema := mcp.ToolArgumentsSchema{Type: "string", Extra: map[string]json.RawMessage{"unchanged": json.RawMessage(`true`)}}
			before := schema
			err := schema.UnmarshalJSON([]byte(tt.input))
			if !tt.valid {
				require.Error(t, err)
				require.Equal(t, before, schema)
				return
			}

			require.NoError(t, err)
			maximum := schema.Properties["value"].(map[string]any)["maximum"]
			require.Equal(t, json.Number("1e400"), maximum)
		})
	}
}
