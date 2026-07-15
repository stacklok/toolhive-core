// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// outcomeSuccess is the "success" value of the outcome label, used across
// several test cases below (as opposed to "success" as a rejected label
// key, which is tested separately).
const outcomeSuccess = "success"

func TestValidateName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		metric  string
		wantErr bool
	}{
		{
			name:    "rejects gateway as the service segment",
			metric:  "stacklok.gateway.request.duration",
			wantErr: true,
		},
		{
			name:    "accepts a qualified gateway service segment",
			metric:  "stacklok.ai_gateway.token.usage",
			wantErr: false,
		},
		{
			name:    "accepts a well-formed name with no gateway segment",
			metric:  "stacklok.toolhive.request.duration",
			wantErr: false,
		},
		{
			name:    "rejects an empty name",
			metric:  "",
			wantErr: true,
		},
		{
			name:    "rejects a name with too few segments",
			metric:  "stacklok.gateway",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateName(tc.metric)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateLabelKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		value   any
		wantErr bool
	}{
		{"rejects a bool value", "is_healthy", true, true},
		{"rejects a bool pointer value", "is_healthy", func() *bool { b := true; return &b }(), true},
		{"accepts a string value", "outcome", outcomeSuccess, false},
		{"accepts an int value", "count", 42, false},
		{"rejects the server re-spelling of mcp_server", "server", "backend-1", true},
		{"rejects the status re-spelling of outcome", "status", outcomeSuccess, true},
		{"rejects the success re-spelling of outcome", "success", "true", true},
		{"rejects the tool re-spelling of tool_name", "tool", "search", true},
		{"rejects the workflow.name re-spelling of composite_tool", "workflow.name", "pipeline", true},
		{"accepts the canonical mcp_server key", LabelMCPServer, "backend-1", false},
		{"accepts the canonical outcome key", LabelOutcome, outcomeSuccess, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLabelKind(tc.key, tc.value)
			if tc.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
