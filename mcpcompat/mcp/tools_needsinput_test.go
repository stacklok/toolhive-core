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

// TestCallToolResult_NeedsInput verifies that CallToolResult.NeedsInput
// classifies the go-sdk "resultType" wire field (SEP-2322 multi round-trip)
// after an UnmarshalJSON round-trip.
func TestCallToolResult_NeedsInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "input_required",
			body: `{"content":[],"resultType":"input_required","inputRequests":{"q1":{"mode":"form","message":"need more"}}}`,
			want: true,
		},
		{
			name: "complete",
			body: `{"content":[{"type":"text","text":"ok"}],"resultType":"complete"}`,
			want: false,
		},
		{
			name: "absent",
			body: `{"content":[{"type":"text","text":"ok"}]}`,
			want: false,
		},
		{
			name: "input_required with empty inputRequests",
			body: `{"content":[],"resultType":"input_required","inputRequests":{}}`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var r mcp.CallToolResult
			require.NoError(t, json.Unmarshal([]byte(tt.body), &r))
			assert.Equal(t, tt.want, r.NeedsInput())
		})
	}
}

// TestCallToolResult_NeedsInput_ZeroValue verifies a zero-value constructed
// result (never unmarshaled) reports NeedsInput false.
func TestCallToolResult_NeedsInput_ZeroValue(t *testing.T) {
	t.Parallel()

	var r mcp.CallToolResult
	assert.False(t, r.NeedsInput())
}

// TestCallToolResult_MarshalJSON_DropsResultType guards the documented
// contract that resultType is populated by UnmarshalJSON but not re-emitted
// by MarshalJSON (see the resultType field doc on CallToolResult): an
// unmarshal -> marshal round-trip must not resurface it on the wire.
func TestCallToolResult_MarshalJSON_DropsResultType(t *testing.T) {
	t.Parallel()

	var r mcp.CallToolResult
	require.NoError(t, json.Unmarshal([]byte(`{"content":[],"resultType":"input_required"}`), &r))
	require.True(t, r.NeedsInput())

	data, err := json.Marshal(r)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "resultType")
}
