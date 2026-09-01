// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testDynamicAuthUser    = "appuser"
	testErrConfigNil       = "config is nil"
	testErrNoSupportedAuth = "no supported auth method"
	testErrMultipleBackend = "more than one is set"
	testErrRegionMissing   = "AWS ElastiCache IAM region is not configured"
	testClusterName        = "my-cluster"
	testRegion             = "us-east-1"
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
			name:    "nil config",
			cfg:     nil,
			wantErr: testErrConfigNil,
		},
		{
			name:      "no dynamic auth returns empty token without error",
			cfg:       &Config{Addr: testAddr},
			wantToken: "",
		},
		{
			name: "dynamic auth without backend",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{},
			},
			wantErr: testErrNoSupportedAuth,
		},
		{
			name: "AWS ElastiCache IAM without region propagates error",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{
					AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{ClusterName: testClusterName},
				},
			},
			wantErr: testErrRegionMissing,
		},
		{
			name: "dynamic auth with more than one backend",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{
					AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion, ClusterName: testClusterName},
					GCPMemorystoreIAM: &DynamicAuthGCPMemorystoreIAM{},
				},
			},
			wantErr: testErrMultipleBackend,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token, err := NewAuthToken(t.Context(), tt.cfg)
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

func TestDynamicAuthConnMaxLifetime(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		da   *DynamicAuthConfig
		want time.Duration
	}{
		{
			name: "AWS ElastiCache IAM",
			da:   &DynamicAuthConfig{AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{}},
			want: DefaultAWSElastiCacheIAMTokenTTL,
		},
		{
			name: "Azure AD",
			da:   &DynamicAuthConfig{AzureAD: &DynamicAuthAzureAD{}},
			want: DefaultAzureADTokenTTL,
		},
		{
			name: "GCP Memorystore IAM",
			da:   &DynamicAuthConfig{GCPMemorystoreIAM: &DynamicAuthGCPMemorystoreIAM{}},
			want: DefaultGCPMemorystoreIAMTokenTTL,
		},
		{
			name: "no backend set",
			da:   &DynamicAuthConfig{},
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, dynamicAuthConnMaxLifetime(tt.da))
		})
	}
}
