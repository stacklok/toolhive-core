// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package postgres

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAuthToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		cfg       *Config
		wantToken string
		wantErr   string
	}{
		{
			name:    testCaseNilConfig,
			cfg:     nil,
			wantErr: testErrConfigNil,
		},
		{
			name:      "no dynamic auth returns empty token without error",
			cfg:       &Config{Host: "h", Port: 5432, User: "u", Database: "d"},
			wantToken: "",
		},
		{
			name: testCaseNoBackend,
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{},
			},
			wantErr: testErrNoSupportedAuth,
		},
		{
			name: "AWS RDS IAM without region propagates error",
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{
					AWSRDSIAM: &DynamicAuthAWSRDSIAM{},
				},
			},
			wantErr: testErrRegionMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token, err := NewAuthToken(t.Context(), tt.cfg, "user")
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Empty(t, token)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

func TestNewDynamicAuthFunc(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name:    testCaseNilConfig,
			cfg:     nil,
			wantErr: testErrConfigNil,
		},
		{
			name:    "no dynamic auth returns explicit error",
			cfg:     &Config{Host: "h", Port: 5432, User: "u", Database: "d"},
			wantErr: "dynamic authentication is not configured",
		},
		{
			name: testCaseNoBackend,
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{},
			},
			wantErr: testErrNoSupportedAuth,
		},
		{
			name: "AWS RDS IAM without region",
			cfg: &Config{
				Host: "h", Port: 5432, User: "u", Database: "d",
				DynamicAuth: &DynamicAuthConfig{
					AWSRDSIAM: &DynamicAuthAWSRDSIAM{},
				},
			},
			wantErr: testErrRegionMissing,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			fn, err := NewDynamicAuthFunc(t.Context(), tt.cfg, "user")
			require.Error(t, err)
			assert.Nil(t, fn)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestResolveAWSRegion_Static(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Host: "h", Port: 5432, User: "u", Database: "d",
		DynamicAuth: &DynamicAuthConfig{
			AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: "us-west-2"},
		},
	}
	region, err := resolveAWSRegion(context.Background(), cfg)
	require.NoError(t, err)
	assert.Equal(t, "us-west-2", region)
}

func TestResolveAWSRegion_EmptyRegion(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Host: "h", Port: 5432, User: "u", Database: "d",
		DynamicAuth: &DynamicAuthConfig{AWSRDSIAM: &DynamicAuthAWSRDSIAM{}},
	}
	_, err := resolveAWSRegion(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), testErrRegionMissing)
}

// TestResolveAWSRegion_DetectFailsWithoutIMDS exercises the IMDS path. The
// test deadline must elapse before imdsRegionTimeout fires so we get a
// deterministic ctx-cancellation error rather than a flaky one.
func TestResolveAWSRegion_DetectFailsWithoutIMDS(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Host: "h", Port: 5432, User: "u", Database: "d",
		DynamicAuth: &DynamicAuthConfig{
			AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: "detect"},
		},
	}
	// Use an already-cancelled context so the IMDS call fails immediately
	// without depending on whether 169.254.169.254 is routable in CI.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolveAWSRegion(ctx, cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "IMDS")
}

// TestAwsRDSIAMBeforeConnect_ReturnsHookForStaticRegion verifies the
// constructor returns a non-nil hook when the region is statically
// configured. Actually invoking the hook would require AWS credentials and
// is out of scope for unit tests.
func TestAwsRDSIAMBeforeConnect_ReturnsHookForStaticRegion(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		Host: "h", Port: 5432, User: "u", Database: "d",
		DynamicAuth: &DynamicAuthConfig{
			AWSRDSIAM: &DynamicAuthAWSRDSIAM{Region: "us-west-2"},
		},
	}
	fn, err := awsRDSIAMBeforeConnect(context.Background(), cfg, "appuser")
	require.NoError(t, err)
	assert.NotNil(t, fn)
}
