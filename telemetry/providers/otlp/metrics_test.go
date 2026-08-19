// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCreateMetricExporter(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		ctx     func() context.Context
		wantErr bool
		errMsg  string
	}{
		{
			name: testNameValid,
			config: Config{
				Endpoint: testEndpointLocal,
				Headers:  map[string]string{testAPIKeyHeader: testSecretValue},
				Insecure: true,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: "config without headers",
			config: Config{
				Endpoint: testEndpointLocal,
				Insecure: false,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: testNameCustomPath,
			config: Config{
				Endpoint: testEndpointLangfuse,
				Headers:  map[string]string{testAuthHeader: testBasicCred},
				Insecure: false,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: "error creating metrics exporter due to invalid CA cert",
			config: Config{
				Endpoint:   testEndpointLocal,
				Insecure:   false,
				CACertPath: testInvalidCACert,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: true,
			errMsg:  "failed to configure TLS for metric exporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.ctx()
			exporter, err := createMetricExporter(ctx, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, exporter)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, exporter)
				// Clean up
				_ = exporter.Shutdown(ctx)
			}
		})
	}
}

func TestNewMetricReader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		config  Config
		wantErr bool
		errMsg  string
	}{
		{
			name: testNameValid,
			config: Config{
				Endpoint: testEndpointLocal,
				Headers:  map[string]string{testAuthHeader: testBearerToken},
				Insecure: true,
			},
			wantErr: false,
		},
		{
			name: "missing endpoint",
			config: Config{
				Headers: map[string]string{testAuthHeader: testBearerToken},
			},
			wantErr: true,
			errMsg:  "OTLP endpoint is required",
		},
		{
			name: "config with custom headers",
			config: Config{
				Endpoint: "otel-collector.local:4318",
				Headers: map[string]string{
					testAPIKeyHeader: testSecretValue,
					testEnvHeaderKey: "production",
				},
				Insecure: false,
			},
			wantErr: false,
		},
		{
			name: testNameCustomPath,
			config: Config{
				Endpoint: testEndpointLangfuse,
				Headers:  map[string]string{testAuthHeader: testBasicCred},
				Insecure: false,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			reader, err := NewMetricReader(ctx, tt.config)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, reader)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, reader)
			}
		})
	}
}
