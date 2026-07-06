// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestErrorBodyEnrichment reproduces the authz case: a tool call denied with an
// HTTP 403 whose body says "Unauthorized". go-sdk's client would surface only
// "403 Forbidden" (status text, body dropped); the RoundTripper captures the
// body and mapCallError re-attaches it so callers (and ToolHive's authz e2e
// test) see "Unauthorized".
func TestErrorBodyEnrichment(t *testing.T) {
	t.Parallel()

	const bodyText = "Unauthorized: request denied by policy"
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(bodyText))
	}))
	t.Cleanup(ts.Close)

	ctx := withErrCapture(context.Background())
	hc := buildHTTPClient(nil, nil, nil, 0)
	require.NotNil(t, hc)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.URL, http.NoBody)
	require.NoError(t, err)
	resp, err := hc.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })

	// The RoundTripper must have restored the body for downstream readers.
	restored, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, bodyText, string(restored), "response body must be restored")

	// Simulate go-sdk's status-only error and confirm enrichment surfaces the body.
	gosdkErr := fmt.Errorf(`calling "tools/call": %s`, http.StatusText(resp.StatusCode))
	assert.NotContains(t, gosdkErr.Error(), "Unauthorized", "precondition: go-sdk error lacks the body")

	enriched := mapCallError(ctx, gosdkErr)
	require.Error(t, enriched)
	assert.Contains(t, enriched.Error(), "Unauthorized", "enriched error must include the server body")
	assert.Contains(t, enriched.Error(), "403")
}

// TestErrorBodyEnrichment_NoCaptureNoop verifies enrichment is a no-op when no
// body was captured (e.g. a 2xx path or a non-HTTP error).
func TestErrorBodyEnrichment_NoCaptureNoop(t *testing.T) {
	t.Parallel()
	ctx := withErrCapture(context.Background())
	orig := fmt.Errorf("some transport failure")
	assert.Equal(t, orig, mapCallError(ctx, orig))
}
