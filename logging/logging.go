// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
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
	format Format
	level  slog.Leveler
	output io.Writer
}

// Option configures the logger created by [New].
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

// New creates a pre-configured [*log/slog.Logger] with consistent defaults
// used across the ToolHive ecosystem.
//
// Defaults:
//   - Format: JSON ([FormatJSON])
//   - Level: INFO ([log/slog.LevelInfo])
//   - Output: [os.Stderr]
//   - Timestamps: [time.RFC3339]
func New(opts ...Option) *slog.Logger {
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
	}

	return slog.New(handler)
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
