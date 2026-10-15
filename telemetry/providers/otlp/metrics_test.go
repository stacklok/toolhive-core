// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
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

func TestCreateMetricExporter_ProtocolSelection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		protocol string
		wantType string
	}{
		{
			name:     testNameProtocolUnsetDefaultsHTTP,
			protocol: "",
			wantType: "*otlpmetrichttp.Exporter",
		},
		{
			name:     testNameProtocolExplicitHTTP,
			protocol: ProtocolHTTPProtobuf,
			wantType: "*otlpmetrichttp.Exporter",
		},
		{
			name:     testNameProtocolGRPC,
			protocol: ProtocolGRPC,
			wantType: "*otlpmetricgrpc.Exporter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			config := Config{
				Endpoint: testEndpointLocal,
				Insecure: true,
				Protocol: tt.protocol,
			}

			exporter, err := createMetricExporter(ctx, config)
			require.NoError(t, err)
			require.NotNil(t, exporter)
			defer func() { _ = exporter.Shutdown(ctx) }()

			assert.Equal(t, tt.wantType, fmt.Sprintf("%T", exporter))
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

func TestNewMetricReader_AppliesExportTimeout(t *testing.T) {
	t.Parallel()

	// Both halves of the budget at once: the reader's own default is 30s, so a
	// flush that returns promptly proves the configured value reached the
	// reader, and reaching it at all means the exporter was built with it too.
	srv := delayedOTLPIngest(t, 30*time.Second)

	reader, err := NewMetricReader(t.Context(), Config{
		Endpoint:      srv.Listener.Addr().String(),
		Insecure:      true,
		ExportTimeout: 150 * time.Millisecond,
	})
	require.NoError(t, err)

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	// Without a recorded point there is nothing to export and the flush would
	// return promptly no matter what the budget is.
	counter, err := provider.Meter("test").Int64Counter("export.timeout")
	require.NoError(t, err)
	counter.Add(t.Context(), 1)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_ = provider.ForceFlush(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*time.Second,
		"flush against an unresponsive ingest took %s — the reader is still on its own 30s budget "+
			"rather than the configured 150ms", elapsed)
}

func TestNewMetricReader_ExportTimeoutFromEnvironment(t *testing.T) {
	// Not parallel: t.Setenv.
	t.Setenv(metricsTimeoutEnv.exporter, "150")

	srv := delayedOTLPIngest(t, 30*time.Second)

	// No ExportTimeout in code, so the only thing that can bound this flush is
	// the variable — which the SDK would otherwise ignore, since this package
	// passes the budget as an explicit option.
	reader, err := NewMetricReader(t.Context(), Config{
		Endpoint: srv.Listener.Addr().String(),
		Insecure: true,
	})
	require.NoError(t, err)

	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })

	counter, err := provider.Meter("test").Int64Counter("export.timeout.env")
	require.NoError(t, err)
	counter.Add(t.Context(), 1)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	start := time.Now()
	_ = provider.ForceFlush(ctx)
	elapsed := time.Since(start)

	assert.Less(t, elapsed, 3*time.Second,
		"flush took %s — OTEL_EXPORTER_OTLP_METRICS_TIMEOUT is not being honored", elapsed)
}
