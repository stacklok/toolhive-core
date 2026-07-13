// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMeter(t *testing.T) {
	t.Parallel()

	meter := Meter("stacklok.toolhive")
	require.NotNil(t, meter)

	t.Run("constructing an instrument does not panic", func(t *testing.T) {
		t.Parallel()
		assert.NotPanics(t, func() {
			_, err := meter.Int64Counter("stacklok.toolhive.requests")
			require.NoError(t, err)
		})
	})
}

func TestBucketPresets(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		buckets []float64
		wantMin float64
		wantMax float64
	}{
		{"fast HTTP", BucketsFastHTTP(), 0.005, 10},
		{"MCP/proxy", BucketsMCPProxy(), 0.01, 300},
		{"long-running", BucketsLongRunning(), 0.1, 300},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.NotEmpty(t, tc.buckets)
			assert.Equal(t, tc.wantMin, tc.buckets[0], "minimum boundary")
			assert.Equal(t, tc.wantMax, tc.buckets[len(tc.buckets)-1], "maximum boundary")
			assert.IsIncreasing(t, tc.buckets, "boundaries must be strictly increasing")
		})
	}

	t.Run("returns independent slices", func(t *testing.T) {
		t.Parallel()
		a := BucketsFastHTTP()
		b := BucketsFastHTTP()
		a[0] = 999
		assert.NotEqual(t, a[0], b[0], "mutating one call's result must not affect another")
	})
}
