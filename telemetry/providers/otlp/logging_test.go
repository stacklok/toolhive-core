// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
)

func TestCreateLogExporter(t *testing.T) {
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
				Headers:  map[string]string{testAuthHeader: testBearerToken},
				Insecure: true,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: false,
		},
		{
			name: "config with headers",
			config: Config{
				Endpoint: testEndpointLocal,
				Headers: map[string]string{
					testAPIKeyHeader: testSecretValue,
					testEnvHeaderKey: "test",
				},
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
			name: "error creating log exporter due to invalid CA cert",
			config: Config{
				Endpoint:   testEndpointLocal,
				Insecure:   false,
				CACertPath: testInvalidCACert,
			},
			ctx:     func() context.Context { return context.Background() },
			wantErr: true,
			errMsg:  "failed to configure TLS for log exporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := tt.ctx()
			exporter, err := createLogExporter(ctx, tt.config)

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

func TestNewLoggerProviderWithShutdown(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		config         Config
		wantErr        bool
		errMsg         string
		expectNoOp     bool
		expectShutdown bool
	}{
		{
			name: "valid config with endpoint returns SDK provider with shutdown",
			config: Config{
				Endpoint: testEndpointLocal,
				Headers:  map[string]string{testAuthHeader: testBearerToken},
				Insecure: true,
			},
			wantErr:        false,
			expectNoOp:     false,
			expectShutdown: true,
		},
		{
			name:           "no endpoint returns noop provider with nil shutdown",
			config:         Config{},
			wantErr:        false,
			expectNoOp:     true,
			expectShutdown: false,
		},
		{
			name: "config with custom path returns SDK provider with shutdown",
			config: Config{
				Endpoint: testEndpointLangfuse,
				Headers:  map[string]string{testAuthHeader: testBasicCred},
			},
			wantErr:        false,
			expectNoOp:     false,
			expectShutdown: true,
		},
		{
			name: "error creating log exporter propagates error",
			config: Config{
				Endpoint:   testEndpointLocal,
				Insecure:   false,
				CACertPath: testInvalidCACert,
			},
			wantErr:        true,
			errMsg:         "failed to create logger provider",
			expectNoOp:     false,
			expectShutdown: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			res, err := resource.New(ctx,
				resource.WithAttributes(
					semconv.ServiceName("test-service"),
					semconv.ServiceVersion("1.0.0"),
				),
			)
			require.NoError(t, err)

			provider, shutdown, err := NewLoggerProviderWithShutdown(ctx, tt.config, res)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, provider)
				assert.Nil(t, shutdown)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, provider)

				providerType := fmt.Sprintf("%T", provider)
				if tt.expectNoOp {
					assert.Contains(t, providerType, "noop")
				} else {
					assert.NotContains(t, providerType, "noop")
				}

				if tt.expectShutdown {
					assert.NotNil(t, shutdown)
					shutdownCtx := context.Background()
					err := shutdown(shutdownCtx)
					assert.NoError(t, err)
				} else {
					assert.Nil(t, shutdown)
				}
			}
		})
	}
}
