// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
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

// TestAWSElastiCacheIAMCredentialsFunc_ReturnsFuncForStaticRegion verifies
// the constructor returns a non-nil CredentialsFunc when the region is
// statically configured. Actually invoking the returned func would require
// AWS credentials and is out of scope for unit tests.
func TestAWSElastiCacheIAMCredentialsFunc_ReturnsFuncForStaticRegion(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Addr: testAddr, Username: testDynamicAuthUser,
		DynamicAuth: &DynamicAuthConfig{
			AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion, ClusterName: testClusterName},
		},
	}
	fn, err := awsElastiCacheIAMCredentialsFunc(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotNil(t, fn)
}

func TestAWSElastiCacheIAMCredentialsFunc_DoesNotMutateCallerConfig(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Addr: testAddr, Username: testDynamicAuthUser,
		DynamicAuth: &DynamicAuthConfig{
			AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion, ClusterName: testClusterName},
		},
	}
	fn, err := awsElastiCacheIAMCredentialsFunc(context.Background(), cfg)
	require.NoError(t, err)
	assert.NotNil(t, fn)
	assert.Empty(t, cfg.DynamicAuth.AWSElastiCacheIAM.ServiceName,
		"awsElastiCacheIAMCredentialsFunc must not mutate the caller's config")
}

// testAWSCredentials is a fixed, fake key pair used only to exercise SigV4
// presigning deterministically — never a real credential.
var testAWSCredentials = aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
	return aws.Credentials{AccessKeyID: "AKIAFAKEFAKEFAKEFAKE", SecretAccessKey: "fakefakefakefakefakefakefakefakefakefake"}, nil
})

func TestBuildAWSElastiCacheToken_SignsCanonicalConnectRequest(t *testing.T) {
	t.Parallel()
	token, err := buildAWSElastiCacheToken(
		t.Context(), testAWSCredentials, testRegion, awsElastiCacheDefaultServiceName, testClusterName, "", testDynamicAuthUser,
	)
	require.NoError(t, err)

	// The token is a presigned URL with its scheme stripped: host + query.
	require.False(t, strings.HasPrefix(token, "https://"), "scheme must be stripped from the token")
	u, err := url.Parse("https://" + token)
	require.NoError(t, err)
	assert.Equal(t, testClusterName, u.Host)
	q := u.Query()
	assert.Equal(t, "connect", q.Get("Action"))
	assert.Equal(t, testDynamicAuthUser, q.Get("User"))
	assert.Equal(t, awsElastiCacheTokenExpirySeconds, q.Get("X-Amz-Expires"))
	assert.Empty(t, q.Get("ResourceType"), "ResourceType must be omitted for provisioned (non-serverless) caches")
	assert.NotEmpty(t, q.Get("X-Amz-Signature"))
	assert.Contains(t, q.Get("X-Amz-Credential"), "/"+testRegion+"/"+awsElastiCacheDefaultServiceName+"/")
}

func TestBuildAWSElastiCacheToken_IncludesResourceTypeForServerless(t *testing.T) {
	t.Parallel()
	token, err := buildAWSElastiCacheToken(
		t.Context(), testAWSCredentials, testRegion, awsElastiCacheDefaultServiceName,
		testClusterName, awsElastiCacheServerlessResourceType, testDynamicAuthUser,
	)
	require.NoError(t, err)
	u, err := url.Parse("https://" + token)
	require.NoError(t, err)
	assert.Equal(t, awsElastiCacheServerlessResourceType, u.Query().Get("ResourceType"))
}

func TestBuildAWSElastiCacheToken_UsesMemoryDBServiceName(t *testing.T) {
	t.Parallel()
	token, err := buildAWSElastiCacheToken(
		t.Context(), testAWSCredentials, testRegion, awsElastiCacheMemoryDBServiceName, testClusterName, "", testDynamicAuthUser,
	)
	require.NoError(t, err)
	u, err := url.Parse("https://" + token)
	require.NoError(t, err)
	assert.Contains(t, u.Query().Get("X-Amz-Credential"), "/"+awsElastiCacheMemoryDBServiceName+"/")
}
