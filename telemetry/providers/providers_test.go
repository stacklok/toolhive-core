// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"

	"github.com/stacklok/toolhive-core/telemetry/providers/otlp"
)

func TestConfig_EffectiveTracesProtocol(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		protocol       string
		tracesProtocol string
		want           string
	}{
		{
			name:           "unset Protocol and unset TracesProtocol default to empty (backward compat)",
			protocol:       "",
			tracesProtocol: "",
			want:           "",
		},
		{
			name:           "TracesProtocol unset falls back to Protocol",
			protocol:       otlp.ProtocolGRPC,
			tracesProtocol: "",
			want:           otlp.ProtocolGRPC,
		},
		{
			name:           "TracesProtocol overrides Protocol independently",
			protocol:       otlp.ProtocolGRPC,
			tracesProtocol: otlp.ProtocolHTTPProtobuf,
			want:           otlp.ProtocolHTTPProtobuf,
		},
		{
			name:           "TracesProtocol set with Protocol unset still applies",
			protocol:       "",
			tracesProtocol: otlp.ProtocolGRPC,
			want:           otlp.ProtocolGRPC,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			config := Config{Protocol: tt.protocol, TracesProtocol: tt.tracesProtocol}
			assert.Equal(t, tt.want, config.effectiveTracesProtocol())
		})
	}
}

func TestWithProtocol(t *testing.T) {
	t.Parallel()

	config := &Config{}
	require.NoError(t, WithProtocol(otlp.ProtocolGRPC)(config))
	assert.Equal(t, otlp.ProtocolGRPC, config.Protocol)
}

func TestWithTracesProtocol(t *testing.T) {
	t.Parallel()

	config := &Config{}
	require.NoError(t, WithTracesProtocol(otlp.ProtocolHTTPProtobuf)(config))
	assert.Equal(t, otlp.ProtocolHTTPProtobuf, config.TracesProtocol)
	// Setting TracesProtocol must not touch the general Protocol field.
	assert.Empty(t, config.Protocol)
}

func TestOTLPTracerStrategy_CreateTracerProvider_TracesProtocolOverride(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("test-service"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	require.NoError(t, err)

	// Protocol is set to gRPC generally, but the traces-specific override
	// selects http/protobuf instead; the tracer provider must still build
	// successfully, proving the override is honored independently.
	strategy := &OTLPTracerStrategy{}
	config := Config{
		OTLPEndpoint:   testEndpointLocal,
		Insecure:       true,
		TracingEnabled: true,
		Protocol:       otlp.ProtocolGRPC,
		TracesProtocol: otlp.ProtocolHTTPProtobuf,
	}

	provider, shutdown, err := strategy.CreateTracerProvider(ctx, config, res)
	require.NoError(t, err)
	require.NotNil(t, provider)
	require.NotNil(t, shutdown)
	assert.NoError(t, shutdown(ctx))
}

func TestCompositeProvider_LoggerProvider(t *testing.T) {
	t.Parallel()

	t.Run("logging disabled returns no-op logger provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		provider, err := NewCompositeProvider(ctx,
			WithServiceName("test-service"),
			WithServiceVersion("1.0.0"),
		)
		require.NoError(t, err)

		assert.Contains(t, fmt.Sprintf("%T", provider.LoggerProvider()), "noop")
		assert.NoError(t, provider.Shutdown(ctx))
	})

	t.Run("logging enabled with endpoint returns real logger provider", func(t *testing.T) {
		t.Parallel()

		ctx := context.Background()
		provider, err := NewCompositeProvider(ctx,
			WithServiceName("test-service"),
			WithServiceVersion("1.0.0"),
			WithOTLPEndpoint(testEndpointLocal),
			WithInsecure(true),
			WithLoggingEnabled(true),
		)
		require.NoError(t, err)

		assert.NotContains(t, fmt.Sprintf("%T", provider.LoggerProvider()), "noop")
		assert.NoError(t, provider.Shutdown(ctx))
	})
}
