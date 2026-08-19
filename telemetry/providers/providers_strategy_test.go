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
)

// testEndpointLocal is a shared fixture, extracted to satisfy goconst.
const testEndpointLocal = "localhost:4318"

func TestSelectLoggerStrategy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		config    Config
		wantOTLP  bool
		wantNoOp  bool
		fullyNoOp bool
	}{
		{
			name:      "no endpoint, logging disabled",
			config:    Config{},
			wantNoOp:  true,
			fullyNoOp: true,
		},
		{
			name:      "endpoint set but logging disabled",
			config:    Config{OTLPEndpoint: testEndpointLocal},
			wantNoOp:  true,
			fullyNoOp: true,
		},
		{
			name:      "logging enabled but no endpoint",
			config:    Config{LoggingEnabled: true},
			wantNoOp:  true,
			fullyNoOp: true,
		},
		{
			name:      "endpoint set and logging enabled",
			config:    Config{OTLPEndpoint: testEndpointLocal, LoggingEnabled: true},
			wantOTLP:  true,
			fullyNoOp: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			selector := NewStrategySelector(tt.config)
			strategy := selector.SelectLoggerStrategy()

			if tt.wantOTLP {
				_, ok := strategy.(*OTLPLoggerStrategy)
				assert.True(t, ok, "expected OTLPLoggerStrategy, got %T", strategy)
			}
			if tt.wantNoOp {
				_, ok := strategy.(*NoOpLoggerStrategy)
				assert.True(t, ok, "expected NoOpLoggerStrategy, got %T", strategy)
			}
			assert.Equal(t, tt.fullyNoOp, selector.IsFullyNoOp())
		})
	}
}

func TestLoggerStrategies_CreateLoggerProvider(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceName("test-service"),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	require.NoError(t, err)

	t.Run("no-op strategy returns no-op provider", func(t *testing.T) {
		t.Parallel()

		strategy := &NoOpLoggerStrategy{}
		provider, shutdown, err := strategy.CreateLoggerProvider(ctx, Config{}, res)

		require.NoError(t, err)
		assert.Contains(t, fmt.Sprintf("%T", provider), "noop")
		assert.Nil(t, shutdown)
	})

	t.Run("OTLP strategy returns real provider with shutdown", func(t *testing.T) {
		t.Parallel()

		strategy := &OTLPLoggerStrategy{}
		config := Config{
			OTLPEndpoint:   testEndpointLocal,
			Insecure:       true,
			LoggingEnabled: true,
		}
		provider, shutdown, err := strategy.CreateLoggerProvider(ctx, config, res)

		require.NoError(t, err)
		assert.NotContains(t, fmt.Sprintf("%T", provider), "noop")
		require.NotNil(t, shutdown)
		assert.NoError(t, shutdown(ctx))
	})
}
