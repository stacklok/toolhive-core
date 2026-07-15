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

func TestLabelKeysAreUnique(t *testing.T) {
	t.Parallel()

	keys := []string{
		LabelMCPServer,
		LabelOutcome,
		LabelMCPMethod,
		LabelToolName,
		LabelCompositeTool,
		LabelTransport,
		LabelErrorType,
	}

	seen := make(map[string]bool, len(keys))
	for _, k := range keys {
		assert.False(t, seen[k], "duplicate label key: %q", k)
		seen[k] = true
	}
}
