// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
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

// TestOwnershipAttrs pins the D8 ownership attribute keys and the frozen
// product value. The product value is frozen at "stacklok-platform" and must
// not revert to "stacklok-enterprise". The per-component AttrStacklokComponent
// value is supplied by each component, not defined here.
func TestOwnershipAttrs(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "stacklok.component", AttrStacklokComponent)
	assert.Equal(t, "stacklok.product", AttrStacklokProduct)
	assert.Equal(t, "stacklok-platform", ProductStacklokPlatform)
}

// TestBuildInfoMetricName pins the fleet-wide build_info metric name.
func TestBuildInfoMetricName(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "stacklok.build_info", BuildInfoMetricName)
}

func TestRegisterBuildInfoValidation(t *testing.T) {
	t.Parallel()

	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(sdkmetric.NewManualReader()))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })
	meter := mp.Meter("test")

	assert.Error(t, RegisterBuildInfo(nil, "toolhive", "1.0.0", "abc123"), "nil meter rejected")
	assert.Error(t, RegisterBuildInfo(meter, "", "1.0.0", "abc123"), "empty component rejected")
	assert.NoError(t, RegisterBuildInfo(meter, "toolhive", "1.0.0", "abc123"), "valid registration")
}

// TestRegisterBuildInfo pins the observed gauge value, unit, and label set by
// scraping a real manual reader, and confirms empty version/commit fall back
// to "unknown".
func TestRegisterBuildInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		component   string
		version     string
		commit      string
		wantVersion string
		wantCommit  string
	}{
		{"full values", "toolhive", "1.2.3", "deadbeef", "1.2.3", "deadbeef"},
		{"empty version and commit fall back to unknown", "toolhive", "", "", unknownBuildInfoValue, unknownBuildInfoValue},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			reader := sdkmetric.NewManualReader()
			mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
			t.Cleanup(func() { _ = mp.Shutdown(ctx) })
			meter := mp.Meter("test-build-info")

			require.NoError(t, RegisterBuildInfo(meter, tc.component, tc.version, tc.commit))

			var rm metricdata.ResourceMetrics
			require.NoError(t, reader.Collect(ctx, &rm))
			require.Len(t, rm.ScopeMetrics, 1)
			require.Len(t, rm.ScopeMetrics[0].Metrics, 1)

			m := rm.ScopeMetrics[0].Metrics[0]
			assert.Equal(t, BuildInfoMetricName, m.Name)
			assert.Equal(t, "1", m.Unit)

			gauge, ok := m.Data.(metricdata.Gauge[int64])
			require.True(t, ok, "build_info must be an Int64ObservableGauge")
			require.Len(t, gauge.DataPoints, 1)
			dp := gauge.DataPoints[0]
			assert.Equal(t, int64(1), dp.Value, "build_info always observes 1")

			component, ok := dp.Attributes.Value("component")
			require.True(t, ok)
			assert.Equal(t, tc.component, component.AsString())

			version, ok := dp.Attributes.Value("version")
			require.True(t, ok)
			assert.Equal(t, tc.wantVersion, version.AsString())

			commit, ok := dp.Attributes.Value("commit")
			require.True(t, ok)
			assert.Equal(t, tc.wantCommit, commit.AsString())
		})
	}
}
