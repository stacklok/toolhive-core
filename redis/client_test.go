// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package redis

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stacklok/toolhive-core/redisconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientCompatibility(t *testing.T) {
	srv := miniredis.RunT(t)
	client, err := NewClient(t.Context(), &Config{Addr: srv.Addr(), DB: 2})
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })
	require.NoError(t, client.Set(t.Context(), "key", "value", 0).Err())
	got, err := client.Get(t.Context(), "key").Result()
	require.NoError(t, err)
	assert.Equal(t, "value", got)
}

func TestNewClientCompatibilityErrors(t *testing.T) {
	tests := []struct {
		name string
		cfg  *Config
		want string
	}{
		{"nil", nil, "redis: config is nil"},
		{"invalid", &Config{}, "redis: invalid configuration"},
		{"ping", &Config{Addr: "127.0.0.1:1", DialTimeout: 20 * time.Millisecond}, "redis: failed to connect"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewClient(t.Context(), tt.cfg)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

func TestBuildTLSConfigCompatibility(t *testing.T) {
	got, err := BuildTLSConfig(&TLSConfig{})
	require.NoError(t, err)
	assert.Equal(t, uint16(tls.VersionTLS12), got.MinVersion)

	var legacy *TLSConfig = &redisconn.TLSConfig{}
	assert.NotNil(t, legacy, "TLSConfig remains an exact alias")
}

func TestLegacyConfigTranslation(t *testing.T) {
	provider := CredentialsFunc(func(context.Context) (string, string, error) { return "user", "token", nil })
	cfg := &Config{
		Addr: "redis:6379", Username: "user", TLS: &TLSConfig{}, ConnMaxLifetime: time.Minute,
		DynamicAuth: &DynamicAuthConfig{AzureAD: &DynamicAuthAzureAD{}},
	}
	translated := cfg.redisconnConfig(&redisconn.DynamicAuth{CredentialsProviderContext: redisconn.CredentialsProvider(provider)})
	assert.Equal(t, cfg.Addr, translated.Addr)
	assert.Equal(t, cfg.Username, translated.Username)
	assert.Equal(t, cfg.ConnMaxLifetime, translated.ConnMaxLifetime)
	assert.Same(t, cfg.TLS, translated.TLS)
	assert.NotNil(t, translated.DynamicAuth)
}
