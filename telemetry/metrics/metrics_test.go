// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBucketPresets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		preset func() []float64
		want   []float64
	}{
		{
			"fast HTTP",
			BucketsFastHTTP,
			[]float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
		},
		{
			"MCP/proxy",
			BucketsMCPProxy,
			[]float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300},
		},
		{
			"long-running",
			BucketsLongRunning,
			[]float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 180, 300},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			buckets := tc.preset()
			require.NotEmpty(t, buckets)
			assert.Equal(t, tc.want, buckets, "full documented boundary set")
			assert.IsIncreasing(t, buckets, "boundaries must be strictly increasing")
		})

		t.Run(tc.name+" returns independent slices", func(t *testing.T) {
			t.Parallel()
			a := tc.preset()
			b := tc.preset()
			a[0] = 999
			assert.NotEqual(t, a[0], b[0], "mutating one call's result must not affect another")
		})
	}
}

func TestLabelKeys(t *testing.T) {
	t.Parallel()

	// Pin the canonical label-key strings so a concept cannot be silently
	// respelled (e.g. mcp_server → server), which would break the
	// cross-component joins the shared vocabulary exists to guarantee.
	want := []struct {
		name string
		got  string
		want string
	}{
		{"LabelMCPServer", LabelMCPServer, "mcp_server"},
		{"LabelOutcome", LabelOutcome, "outcome"},
		{"LabelMCPMethod", LabelMCPMethod, "mcp_method"},
		{"LabelToolName", LabelToolName, "tool_name"},
		{"LabelCompositeTool", LabelCompositeTool, "composite_tool"},
		{"LabelTransport", LabelTransport, "transport"},
		{"LabelErrorType", LabelErrorType, "error_type"},
	}

	seen := make(map[string]bool, len(want))
	for _, tc := range want {
		assert.Equal(t, tc.want, tc.got, "%s must not be silently respelled", tc.name)
		assert.False(t, seen[tc.got], "duplicate label key: %q", tc.got)
		seen[tc.got] = true
	}
}

// TestOutcomeValues pins the canonical outcome-label values so the shared
// success/error/rejected vocabulary cannot drift per component.
func TestOutcomeValues(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "success", OutcomeSuccess)
	assert.Equal(t, "error", OutcomeError)
	assert.Equal(t, "rejected", OutcomeRejected)
}

// TestOwnershipAttrs pins the D8 ownership attribute keys, the frozen product
// value, and the known component roster. The product value is frozen at
// "stacklok-platform" and must not revert to "stacklok-enterprise".
func TestOwnershipAttrs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "stacklok.component", AttrStacklokComponent)
	assert.Equal(t, "stacklok.product", AttrStacklokProduct)
	assert.Equal(t, "stacklok-platform", ProductStacklokPlatform)

	roster := []struct{ name, got string }{
		{"ComponentToolhive", ComponentToolhive},
		{"ComponentVMCP", ComponentVMCP},
		{"ComponentRegistry", ComponentRegistry},
		{"ComponentAIGateway", ComponentAIGateway},
		{"ComponentOperator", ComponentOperator},
		{"ComponentConnectorGateway", ComponentConnectorGateway},
		{"ComponentDirectory", ComponentDirectory},
		{"ComponentConfigServer", ComponentConfigServer},
	}
	seen := make(map[string]bool, len(roster))
	for _, c := range roster {
		assert.NotContains(t, c.got, "gateway.", "%s must not contain the banned unqualified 'gateway'", c.name)
		assert.False(t, seen[c.got], "duplicate component value: %q", c.got)
		seen[c.got] = true
	}
}

// TestBuildInfoMetricName pins the fleet-wide build_info metric name.
func TestBuildInfoMetricName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "stacklok.build_info", BuildInfoMetricName)
}
