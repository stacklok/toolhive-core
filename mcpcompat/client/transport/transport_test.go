// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/mcpcompat/client/transport"
)

func TestWithHTTPHeaderFunc(t *testing.T) {
	t.Parallel()

	// No header func by default.
	sh := transport.NewStreamableHTTP("https://example.test/mcp")
	assert.Nil(t, sh.HeaderFunc())

	// WithHTTPHeaderFunc records a per-request header function.
	const hdrKey = "X-Test"
	called := false
	fn := func(context.Context) map[string]string {
		called = true
		return map[string]string{hdrKey: "v"}
	}
	sh = transport.NewStreamableHTTP("https://example.test/mcp", transport.WithHTTPHeaderFunc(fn))
	got := sh.HeaderFunc()
	require.NotNil(t, got)
	hdrs := got(context.Background())
	assert.True(t, called)
	assert.Equal(t, "v", hdrs[hdrKey])
}

func TestStreamableHTTPOptions(t *testing.T) {
	t.Parallel()
	hc := &http.Client{}
	sh := transport.NewStreamableHTTP("https://example.test/mcp",
		transport.WithHTTPTimeout(5*time.Second),
		transport.WithHTTPBasicClient(hc),
		transport.WithHTTPHeaders(map[string]string{"X-Test": "1"}),
		transport.WithSession("sess-123"),
		transport.WithContinuousListening(),
	)

	assert.Equal(t, "https://example.test/mcp", sh.Endpoint())
	assert.Equal(t, 5*time.Second, sh.Timeout())
	assert.Same(t, hc, sh.HTTPClient())
	assert.Equal(t, "1", sh.Headers()["X-Test"])
	assert.True(t, sh.ContinuousListening())
	assert.Equal(t, "sess-123", sh.GetSessionId())

	sh.SetSessionID("live-456")
	assert.Equal(t, "live-456", sh.GetSessionId())

	// StreamableHTTP satisfies the Interface returned by client.GetTransport.
	var _ transport.Interface = sh
}

func TestSSEOptions(t *testing.T) {
	t.Parallel()
	hc := &http.Client{}
	s := transport.NewSSE("https://example.test/sse",
		transport.WithHTTPClient(hc),
		transport.WithHeaders(map[string]string{"X-Test": "2"}),
	)
	assert.Equal(t, "https://example.test/sse", s.Endpoint())
	assert.Same(t, hc, s.HTTPClient())
	assert.Equal(t, "2", s.Headers()["X-Test"])
}

func TestErrorTypesUnwrap(t *testing.T) {
	t.Parallel()

	are := &transport.AuthorizationRequiredError{ResourceMetadataURL: "https://as.example/meta"}
	assert.ErrorIs(t, are, transport.ErrAuthorizationRequired)

	wrapped := transport.NewError(errors.New("boom"))
	assert.Contains(t, wrapped.Error(), "boom")
	assert.EqualError(t, wrapped.Unwrap(), "boom")
}
