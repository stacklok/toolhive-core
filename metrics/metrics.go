// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package metrics

// BucketsFastHTTP returns the histogram bucket boundaries, in seconds, for
// fast HTTP-class measurements (RFC §3.3: 0.005-10).
func BucketsFastHTTP() []float64 {
	return []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
}

// BucketsMCPProxy returns the histogram bucket boundaries, in seconds, for
// MCP/proxy operation measurements (RFC §3.3: 0.01-300).
func BucketsMCPProxy() []float64 {
	return []float64{0.01, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300}
}

// BucketsLongRunning returns the histogram bucket boundaries, in seconds, for
// long-running measurements such as sync, reconcile, or composite-tool
// durations (RFC §3.3: 0.1-300).
func BucketsLongRunning() []float64 {
	return []float64{0.1, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 180, 300}
}
