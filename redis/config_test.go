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
	testAddr           = "localhost:6379"
	testMasterName     = "mymaster"
	testSentinelAddr   = "sentinel:26379"
	testSentinelAddrB  = "sentinel-1:26379"
	testClusterAddr    = "cluster:6379"
	testSecondSentinel = "sentinel-0:26379"
)

func TestConfigValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		cfg     *Config
		wantErr string
	}{
		{
			name:    "nil config is rejected",
			cfg:     nil,
			wantErr: "config is nil",
		},
		{
			name:    "no addr and no sentinel",
			cfg:     &Config{},
			wantErr: "one of addr",
		},
		{
			name: "addr and sentinel both set is rejected",
			cfg: &Config{
				Addr: testAddr,
				SentinelConfig: &SentinelConfig{
					MasterName:    testMasterName,
					SentinelAddrs: []string{testSentinelAddr},
				},
			},
			wantErr: "mutually exclusive",
		},
		{
			name: "cluster mode with sentinel is rejected",
			cfg: &Config{
				Addr:        testClusterAddr,
				ClusterMode: true,
				SentinelConfig: &SentinelConfig{
					MasterName:    testMasterName,
					SentinelAddrs: []string{testSentinelAddr},
				},
			},
			wantErr: "cluster mode cannot be used with sentinel",
		},
		{
			name: "cluster mode without addr is rejected",
			cfg: &Config{
				ClusterMode: true,
			},
			wantErr: "one of addr",
		},
		{
			name: "sentinel without master name is rejected",
			cfg: &Config{
				SentinelConfig: &SentinelConfig{
					SentinelAddrs: []string{testSentinelAddr},
				},
			},
			wantErr: "master name is required",
		},
		{
			name: "sentinel without addresses is rejected",
			cfg: &Config{
				SentinelConfig: &SentinelConfig{
					MasterName: testMasterName,
				},
			},
			wantErr: "at least one sentinel address",
		},
		{
			name:    "TLS client certificate without key is rejected",
			cfg:     &Config{Addr: testAddr, TLS: &TLSConfig{ClientCert: []byte("certificate")}},
			wantErr: "TLS config: client certificate and key must be provided together",
		},
		{
			name:    "TLS client key without certificate is rejected",
			cfg:     &Config{Addr: testAddr, TLS: &TLSConfig{ClientKey: []byte("key")}},
			wantErr: "TLS config: client certificate and key must be provided together",
		},
		{
			name: "sentinel TLS client certificate without key is rejected",
			cfg: &Config{
				SentinelConfig: &SentinelConfig{
					MasterName:    testMasterName,
					SentinelAddrs: []string{testSentinelAddr},
				},
				SentinelTLS: &TLSConfig{ClientCert: []byte("certificate")},
			},
			wantErr: "sentinel TLS config: client certificate and key must be provided together",
		},
		{
			name: "sentinel TLS client key without certificate is rejected",
			cfg: &Config{
				SentinelConfig: &SentinelConfig{
					MasterName:    testMasterName,
					SentinelAddrs: []string{testSentinelAddr},
				},
				SentinelTLS: &TLSConfig{ClientKey: []byte("key")},
			},
			wantErr: "sentinel TLS config: client certificate and key must be provided together",
		},
		{
			name: "dynamicAuth with password is rejected",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser, Password: "secret",
				DynamicAuth: &DynamicAuthConfig{AzureAD: &DynamicAuthAzureAD{}},
			},
			wantErr: "password must not be set when dynamicAuth is configured",
		},
		{
			name: "dynamicAuth without username is rejected",
			cfg: &Config{
				Addr:        testAddr,
				DynamicAuth: &DynamicAuthConfig{AzureAD: &DynamicAuthAzureAD{}},
			},
			wantErr: "username is required when dynamicAuth is configured",
		},
		{
			name: "dynamicAuth without backend is rejected",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{},
			},
			wantErr: testErrNoSupportedAuth,
		},
		{
			name: "dynamicAuth with more than one backend is rejected",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{
					AzureAD:           &DynamicAuthAzureAD{},
					GCPMemorystoreIAM: &DynamicAuthGCPMemorystoreIAM{},
				},
			},
			wantErr: testErrMultipleBackend,
		},
		{
			name: "AWS ElastiCache IAM without region is rejected",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{
					AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{ClusterName: testClusterName},
				},
			},
			wantErr: "dynamicAuth.awsElastiCacheIam.region is required",
		},
		{
			name: "AWS ElastiCache IAM without cluster name is rejected",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{
					AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion},
				},
			},
			wantErr: "dynamicAuth.awsElastiCacheIam.clusterName is required",
		},
		{
			name: "valid AWS ElastiCache IAM dynamicAuth config",
			cfg: &Config{
				Addr: testAddr, Username: testDynamicAuthUser,
				DynamicAuth: &DynamicAuthConfig{
					AWSElastiCacheIAM: &DynamicAuthAWSElastiCacheIAM{Region: testRegion, ClusterName: testClusterName},
				},
			},
		},
		{
			name: "valid standalone config",
			cfg: &Config{
				Addr: testAddr,
			},
		},
		{
			name: "valid cluster config",
			cfg: &Config{
				Addr:        testClusterAddr,
				ClusterMode: true,
			},
		},
		{
			name: "valid sentinel config",
			cfg: &Config{
				SentinelConfig: &SentinelConfig{
					MasterName:    testMasterName,
					SentinelAddrs: []string{testSecondSentinel, testSentinelAddrB},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestConfigApplyDefaults(t *testing.T) {
	t.Parallel()

	t.Run("zero timeouts get defaults", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{Addr: testAddr}
		cfg.applyDefaults()
		assert.Equal(t, DefaultDialTimeout, cfg.DialTimeout)
		assert.Equal(t, DefaultReadTimeout, cfg.ReadTimeout)
		assert.Equal(t, DefaultWriteTimeout, cfg.WriteTimeout)
	})

	t.Run("non-zero timeouts are preserved", func(t *testing.T) {
		t.Parallel()
		cfg := &Config{
			Addr:         testAddr,
			DialTimeout:  10 * time.Second,
			ReadTimeout:  7 * time.Second,
			WriteTimeout: 8 * time.Second,
		}
		cfg.applyDefaults()
		assert.Equal(t, 10*time.Second, cfg.DialTimeout)
		assert.Equal(t, 7*time.Second, cfg.ReadTimeout)
		assert.Equal(t, 8*time.Second, cfg.WriteTimeout)
	})
}
