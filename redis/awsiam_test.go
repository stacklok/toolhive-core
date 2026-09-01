// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolveAWSElastiCacheRegion_Static(t *testing.T) {
	t.Parallel()
	region, err := resolveAWSElastiCacheRegion(context.Background(), &DynamicAuthAWSElastiCacheIAM{
		Region: testRegion, ClusterName: testClusterName,
	})
	require.NoError(t, err)
	assert.Equal(t, testRegion, region)
}

func TestResolveAWSElastiCacheRegion_EmptyRegion(t *testing.T) {
	t.Parallel()
	_, err := resolveAWSElastiCacheRegion(context.Background(), &DynamicAuthAWSElastiCacheIAM{ClusterName: testClusterName})
	require.Error(t, err)
	assert.Contains(t, err.Error(), testErrRegionMissing)
}

// TestResolveAWSElastiCacheRegion_DetectFailsWithoutIMDS exercises the IMDS
// path. The test deadline must elapse before imdsRegionTimeout fires so we
// get a deterministic ctx-cancellation error rather than a flaky one.
func TestResolveAWSElastiCacheRegion_DetectFailsWithoutIMDS(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveAWSElastiCacheRegion(ctx, &DynamicAuthAWSElastiCacheIAM{
		Region: awsElastiCacheIAMRegionDetect, ClusterName: testClusterName,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IMDS")
}

// TestAWSElastiCacheIAMTokenFunc_ReturnsFuncForStaticRegion verifies the
// constructor returns a non-nil TokenFunc when the region is statically
// configured. Actually invoking the returned func would require AWS
// credentials and is out of scope for unit tests.
func TestAWSElastiCacheIAMTokenFunc_ReturnsFuncForStaticRegion(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Addr: testAddr, Username: testDynamicAuthUser,
		DynamicAuth: &DynamicAuthConfig{
			AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion, ClusterName: testClusterName},
		},
	}
	fn, err := awsElastiCacheIAMTokenFunc(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotNil(t, fn)
}

func TestAWSElastiCacheIAMTokenFunc_DefaultsServiceName(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Addr: testAddr, Username: testDynamicAuthUser,
		DynamicAuth: &DynamicAuthConfig{
			AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion, ClusterName: testClusterName},
		},
	}
	fn, err := awsElastiCacheIAMTokenFunc(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotNil(t, fn)
	assert.Empty(t, cfg.DynamicAuth.AWSElastiCacheIAM.ServiceName,
		"awsElastiCacheIAMTokenFunc must not mutate the caller's config")
}
