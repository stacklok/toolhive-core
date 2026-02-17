// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package recovery

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stacklok/toolhive-core/logging"
)

func TestMiddleware_NoPanic(t *testing.T) {
	t.Parallel()

	// Create a test handler that does not panic
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	// Wrap with recovery middleware
	wrappedHandler := Middleware(testHandler)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute request
	wrappedHandler.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", rec.Body.String())
}

func TestMiddleware_RecoverFromPanic(t *testing.T) {
	t.Parallel()

	// Create a test handler that panics
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	// Wrap with recovery middleware (no logger — silent recovery)
	wrappedHandler := Middleware(testHandler)

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute request - should not panic
	wrappedHandler.ServeHTTP(rec, req)

	// Verify 500 Internal Server Error response
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Internal Server Error")
}

func TestMiddleware_RecoverFromPanicWithLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.New(logging.WithOutput(&buf))

	// Create a test handler that panics
	testHandler := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("test panic")
	})

	// Wrap with recovery middleware with logger
	wrappedHandler := Middleware(testHandler, WithLogger(logger))

	// Create test request
	req := httptest.NewRequest(http.MethodPost, "/api/resource", nil)
	rec := httptest.NewRecorder()

	// Execute request - should not panic
	wrappedHandler.ServeHTTP(rec, req)

	// Verify 500 Internal Server Error response
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "Internal Server Error")

	// Verify log output contains expected fields
	logOutput := buf.String()
	assert.Contains(t, logOutput, "panic recovered")
	assert.Contains(t, logOutput, "test panic")
	assert.Contains(t, logOutput, "POST")
	assert.Contains(t, logOutput, "/api/resource")
	assert.Contains(t, logOutput, "stack")
}

func TestMiddleware_NoPanicWithLogger(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := logging.New(logging.WithOutput(&buf))

	// Create a test handler that does not panic
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	})

	// Wrap with recovery middleware with logger
	wrappedHandler := Middleware(testHandler, WithLogger(logger))

	// Create test request
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()

	// Execute request
	wrappedHandler.ServeHTTP(rec, req)

	// Verify response
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "success", rec.Body.String())

	// Verify no log output when no panic occurs
	assert.Empty(t, buf.String())
}

func TestMiddleware_PreservesRequestContext(t *testing.T) {
	t.Parallel()

	type contextKey string
	const key contextKey = "test-key"
	const value = "test-value"

	var receivedValue string

	// Create a test handler that reads from context
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v := r.Context().Value(key); v != nil {
			receivedValue = v.(string)
		}
		w.WriteHeader(http.StatusOK)
	})

	// Wrap with recovery middleware
	wrappedHandler := Middleware(testHandler)

	// Create test request with context value
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	ctx := context.WithValue(req.Context(), key, value)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()

	// Execute request
	wrappedHandler.ServeHTTP(rec, req)

	// Verify context was preserved
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, value, receivedValue)
}
