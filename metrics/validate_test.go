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

// Shared test fixture values, deduped to satisfy goconst.
const (
	// healthKey is an arbitrary non-canonical label key used by the
	// boolean-kind rejection cases.
	healthKey = "is_healthy"
	// serverValue is a sample MCP server label value.
	serverValue = "backend-1"
	// errBooleanTyped and errBannedRespelling are substrings of the errors
	// ValidateLabel returns, asserted so each case is pinned to the rule
	// that must fire rather than merely to "some error".
	errBooleanTyped     = "must not be boolean-typed"
	errBannedRespelling = "banned re-spelling"
	// errInvalidSegment is a substring of the error ValidateName returns for
	// a segment containing characters outside [a-z0-9_].
	errInvalidSegment = "invalid segment"
)

func TestValidateName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// metric is the metric name under test.
		metric string
		// wantErrContains, when non-empty, asserts the error message contains
		// this substring — pinning the case to the specific rule that must
		// fire, not merely that some error occurred. Empty means expect no
		// error.
		wantErrContains string
	}{
		{
			name:            "rejects gateway as the service segment",
			metric:          "stacklok.gateway.request.duration",
			wantErrContains: "banned service segment",
		},
		{
			name:   "accepts a qualified gateway service segment",
			metric: "stacklok.ai_gateway.token.usage",
		},
		{
			name:   "accepts gateway as a non-service segment",
			metric: "stacklok.vmcp.gateway.duration",
		},
		{
			name:   "accepts a well-formed name with no gateway segment",
			metric: "stacklok.toolhive.request.duration",
		},
		{
			name:            "rejects an empty name",
			metric:          "",
			wantErrContains: "must not be empty",
		},
		{
			name:            "rejects a name with too few segments",
			metric:          "stacklok.toolhive.duration",
			wantErrContains: "at least 4 dotted segments",
		},
		{
			name:            "rejects a name missing the stacklok prefix",
			metric:          "toolhive.proxy.request.duration",
			wantErrContains: "must start with",
		},
		{
			name:            "rejects a name with an empty dotted segment",
			metric:          "stacklok..request.duration",
			wantErrContains: errInvalidSegment,
		},
		{
			name:            "rejects a segment containing whitespace",
			metric:          "stacklok.ai gateway.request.duration",
			wantErrContains: errInvalidSegment,
		},
		{
			name:            "rejects a segment containing uppercase letters",
			metric:          "stacklok.Toolhive.request.duration",
			wantErrContains: errInvalidSegment,
		},
		{
			name:            "rejects a segment containing unicode characters",
			metric:          "stacklok.工具.request.duration",
			wantErrContains: errInvalidSegment,
		},
		{
			name:   "accepts a segment containing digits and underscores",
			metric: "stacklok.toolhive_2.request_v2.duration_ms",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateName(tc.metric)
			if tc.wantErrContains != "" {
				assert.ErrorContains(t, err, tc.wantErrContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateLabel(t *testing.T) {
	t.Parallel()

	var truePtr = func() *bool { b := true; return &b }()
	var nilBoolPtr *bool
	var namedTrue = health(true)
	var nilNamedBoolPtr *health

	tests := []struct {
		name  string
		key   string
		value any
		// wantErrContains, when non-empty, asserts the error message contains
		// this substring — pinning the case to whether the key-spelling rule or
		// the boolean-kind rule fired. Empty means expect no error.
		wantErrContains string
	}{
		// Boolean-kind rejection, including named bool types and pointers.
		{"rejects a bool value", healthKey, true, errBooleanTyped},
		{"rejects a bool pointer value", healthKey, truePtr, errBooleanTyped},
		{"rejects a nil bool pointer", healthKey, nilBoolPtr, errBooleanTyped},
		{"rejects a named bool type", healthKey, namedTrue, errBooleanTyped},
		{"rejects a pointer to a named bool type", healthKey, &namedTrue, errBooleanTyped},
		{"rejects a nil pointer to a named bool type", healthKey, nilNamedBoolPtr, errBooleanTyped},

		// Non-boolean values are accepted.
		{"accepts a string value", "some_key", outcomeSuccess, ""},
		{"accepts an int value", "count", 42, ""},

		// Every banned re-spelling in replacedLabelKeys is rejected.
		{"rejects the server re-spelling of mcp_server", "server", serverValue, errBannedRespelling},
		{"rejects the target.workload_name re-spelling of mcp_server", "target.workload_name", serverValue, errBannedRespelling},
		{"rejects the target.workload_id re-spelling of mcp_server", "target.workload_id", serverValue, errBannedRespelling},
		{"rejects the status re-spelling of outcome", "status", outcomeSuccess, errBannedRespelling},
		{"rejects the success re-spelling of outcome", "success", "true", errBannedRespelling},
		{"rejects the failure re-spelling of outcome", "failure", "true", errBannedRespelling},
		{"rejects the mcp.method.name re-spelling of mcp_method", "mcp.method.name", "tools/call", errBannedRespelling},
		{"rejects the tool re-spelling of tool_name", "tool", "search", errBannedRespelling},
		{"rejects the workflow.name re-spelling of composite_tool", "workflow.name", "pipeline", errBannedRespelling},
		{"rejects the target.transport_type re-spelling of transport", "target.transport_type", "stdio", errBannedRespelling},

		// Every canonical common key is accepted.
		{"accepts the canonical mcp_server key", LabelMCPServer, serverValue, ""},
		{"accepts the canonical outcome key", LabelOutcome, outcomeSuccess, ""},
		{"accepts the canonical mcp_method key", LabelMCPMethod, "tools/call", ""},
		{"accepts the canonical tool_name key", LabelToolName, "search", ""},
		{"accepts the canonical composite_tool key", LabelCompositeTool, "pipeline", ""},
		{"accepts the canonical transport key", LabelTransport, "stdio", ""},
		{"accepts the canonical provider key", LabelProvider, "openai", ""},
		{"accepts the canonical model key", LabelModel, "gpt-4", ""},
		{"accepts the canonical error_type key", LabelErrorType, "timeout", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := ValidateLabel(tc.key, tc.value)
			if tc.wantErrContains != "" {
				assert.ErrorContains(t, err, tc.wantErrContains)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// health is a named boolean type used to verify ValidateLabel rejects
// boolean-kinded values beyond the built-in bool.
type health bool
