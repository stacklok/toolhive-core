// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package recovery

import (
	"fmt"
	"log/slog"
	"net/http"
	"runtime/debug"
)

// config holds the resolved configuration for the recovery middleware.
type config struct {
	logger *slog.Logger
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

// Middleware is an HTTP middleware that recovers from panics.
// When a panic occurs, it returns a 500 Internal Server Error response
// to the client, preventing the panic from crashing the server.
//
// Options can be provided to configure logging behavior. By default,
// panics are recovered silently. Use [WithLogger] to enable logging.
func Middleware(next http.Handler, opts ...Option) http.Handler {
	cfg := &config{}
	for _, opt := range opts {
		opt(cfg)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if cfg.logger != nil {
					stack := debug.Stack()
					cfg.logger.ErrorContext(r.Context(), "panic recovered",
						slog.String("panic", fmt.Sprintf("%v", v)),
						slog.String("method", r.Method),
						slog.String("path", r.URL.Path),
						slog.String("stack", string(stack)),
					)
				}
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
