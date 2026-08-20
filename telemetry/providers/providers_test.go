// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package providers

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
