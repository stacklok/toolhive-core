// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package recovery

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// config holds the resolved configuration for the recovery middleware.
type config struct {
	logger  *slog.Logger
	handler PanicHandler
}

// Option configures the recovery middleware.
type Option func(*config)

// WithLogger sets the logger used to report recovered panics.
// When a panic is recovered and a logger is configured, the middleware
// logs the panic value, stack trace, and request context at ERROR level.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) {
		c.logger = l
	}
}

// WithPanicHandler sets the handler invoked when a panic is recovered.
// Typical implementations record the panic on a tracing span and/or report
// it to an error-tracking backend such as Sentry. The handler runs after
// logging and before the 500 response is written.
//
// The handler must not panic itself; a panicking handler crashes the
// serving goroutine just as an unrecovered panic would.
func WithPanicHandler(h PanicHandler) Option {
	return func(c *config) {
		c.handler = h
	}
}

// Middleware is an HTTP middleware that recovers from panics.
// When a panic occurs, it returns a 500 Internal Server Error response
// to the client, preventing the panic from crashing the server.
//
// A panic of [http.ErrAbortHandler] (or an error wrapping it) is re-panicked
// instead of recovered: net/http and httputil.ReverseProxy use that sentinel
// to abort in-flight streaming responses, and recovering it would corrupt
// the response and log noisy stack traces for a normal disconnect.
//
// Options can be provided to configure logging and panic reporting. By
// default, panics are recovered silently. Use [WithLogger] to enable
// logging and [WithPanicHandler] to report panics to observability backends.
func Middleware(next http.Handler, opts ...Option) http.Handler {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				// Re-panic http.ErrAbortHandler so Go's HTTP server can
				// handle it as designed (silently close the connection).
				// ReverseProxy panics with this sentinel when a streaming
				// response breaks mid-copy; catching it would log noisy
				// stack traces and corrupt the already-in-flight response.
				if isErrAbortHandler(v) {
					panic(http.ErrAbortHandler)
				}
				if cfg.logger != nil {
					stack := debug.Stack()
					cfg.logger.ErrorContext(r.Context(), "panic recovered",
						slog.String("panic", fmt.Sprintf("%v", v)),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.String("stack", string(stack)),
					)
				}
				if cfg.handler != nil {
					// RecordError receives a generic message, not the panic
					// value: panic values may embed credentials or internal
					// state that must not reach external telemetry backends.
					// Full details are in the log and in ReportPanic, which
					// is for backends the operator explicitly configured.
					cfg.handler.RecordError(r, errors.New("panic recovered"))
					cfg.handler.ReportPanic(r, v)
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// isErrAbortHandler reports whether v is the net/http abort-handler sentinel
// or an error wrapping it (see errors.Is). httputil.ReverseProxy uses this
// panic to stop copying a streaming response when the backend or client drops
// the connection.
//
// It must not be treated as a normal panic: logging it as ERROR and calling
// http.Error would run after headers may already be sent (SSE), which
// produces "superfluous response.WriteHeader" and corrupts the response.
func isErrAbortHandler(v any) bool {
	if v == nil {
		return false
	}
	if v == http.ErrAbortHandler {
		return true
	}
	err, ok := v.(error)
	if !ok {
		return false
	}
	return errors.Is(err, http.ErrAbortHandler)
}
