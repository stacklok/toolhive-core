// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"
)

// Format represents the log output format.
type Format int

const (
	// FormatJSON produces JSON-formatted log output using [log/slog.JSONHandler].
	// This is the default format, suitable for production environments.
	FormatJSON Format = iota

	// FormatText produces human-readable text output using [log/slog.TextHandler].
	// This is suitable for local development.
	FormatText
)

// config holds the resolved configuration for creating a logger.
type config struct {
	format     Format
	level      slog.Leveler
	output     io.Writer
	middleware []func(slog.Handler) slog.Handler
}

// Option configures [New] and [NewHandler].
type Option func(*config)

// WithFormat sets the output format (JSON or Text).
// The default is [FormatJSON].
func WithFormat(f Format) Option {
	return func(c *config) {
		c.format = f
	}
}

// WithLevel sets the minimum log level.
// The default is [log/slog.LevelInfo].
//
// Accepts any [log/slog.Leveler], including [*log/slog.LevelVar] for
// dynamic level changes:
//
//	var lvl slog.LevelVar
//	lvl.Set(slog.LevelDebug)
//	logger := logging.New(logging.WithLevel(&lvl))
func WithLevel(l slog.Leveler) Option {
	return func(c *config) {
		c.level = l
	}
}

// WithOutput sets the destination writer for log output.
// The default is [os.Stderr].
func WithOutput(w io.Writer) Option {
	return func(c *config) {
		c.output = w
	}
}

// WithHandlerMiddleware wraps the handler [NewHandler] builds with fn before
// returning it, so a caller can inject a cross-cutting concern — trace-context
// stamping, redaction, sampling, or anything else expressible as
// func(slog.Handler) slog.Handler — without this package taking a dependency
// on it. Applying more than one middleware is equivalent to manually chaining
// fn calls in the given order: the last WithHandlerMiddleware call wraps every
// earlier one, so it is the outermost handler and sees (and can filter or
// annotate) each record before the others do.
//
//	handler := logging.NewHandler(
//		logging.WithFormat(logging.FormatText),
//		logging.WithHandlerMiddleware(myTraceContextHandler),
//	)
func WithHandlerMiddleware(fn func(slog.Handler) slog.Handler) Option {
	return func(c *config) {
		c.middleware = append(c.middleware, fn)
	}
}

// NewHandler creates a pre-configured [log/slog.Handler] with consistent
// defaults used across the ToolHive ecosystem. Use [WithHandlerMiddleware] to
// wrap the handler with cross-cutting concerns (e.g., trace injection) before
// the final logger is created — or, for a one-off need, call NewHandler and
// wrap its return value directly instead of creating the final logger with
// [New].
//
// Defaults:
//   - Format: JSON ([FormatJSON])
//   - Level: INFO ([log/slog.LevelInfo])
//   - Output: [os.Stderr]
//   - Timestamps: [time.RFC3339]
func NewHandler(opts ...Option) slog.Handler {
	cfg := &config{
		format: FormatJSON,
		level:  slog.LevelInfo,
		output: os.Stderr,
	}

	for _, opt := range opts {
		opt(cfg)
	}

	handlerOpts := &slog.HandlerOptions{
		Level:       cfg.level,
		ReplaceAttr: replaceAttr,
	}

	var handler slog.Handler
	switch cfg.format {
	case FormatText:
		handler = slog.NewTextHandler(cfg.output, handlerOpts)
	case FormatJSON:
		handler = slog.NewJSONHandler(cfg.output, handlerOpts)
	default:
		// Unreachable for known Format values; default to JSON for safety.
		handler = slog.NewJSONHandler(cfg.output, handlerOpts)
	}

	for _, mw := range cfg.middleware {
		handler = mw(handler)
	}
	return handler
}

// New creates a pre-configured [*log/slog.Logger] with consistent defaults
// used across the ToolHive ecosystem.
//
// Defaults:
//   - Format: JSON ([FormatJSON])
//   - Level: INFO ([log/slog.LevelInfo])
//   - Output: [os.Stderr]
//   - Timestamps: [time.RFC3339]
func New(opts ...Option) *slog.Logger {
	return slog.New(NewHandler(opts...))
}

// ParseLevel parses a level name ("debug", "info", "warn", or "error")
// into a [log/slog.Level]. An empty string resolves to [log/slog.LevelInfo],
// matching [New]'s default.
func ParseLevel(level string) (slog.Level, error) {
	switch level {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("unknown level %q", level)
	}
}

// replaceAttr formats the time attribute to RFC3339.
// All other attributes are passed through unchanged.
func replaceAttr(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.TimeKey {
		if t, ok := a.Value.Any().(time.Time); ok {
			a.Value = slog.StringValue(t.Format(time.RFC3339))
		}
	}
	return a
}
