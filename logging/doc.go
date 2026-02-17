// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package logging provides a pre-configured [log/slog.Logger] factory with
consistent defaults for the ToolHive ecosystem.

All ToolHive projects share the same timestamp format, output destination,
and handler configuration. This package encapsulates those choices so that
each project does not need to replicate them.

# Defaults

  - Format: JSON ([FormatJSON]) via [log/slog.JSONHandler]
  - Level: INFO ([log/slog.LevelInfo])
  - Output: [os.Stderr]
  - Timestamps: [time.RFC3339]

# Basic Usage

Create a logger with default settings:

	logger := logging.New()
	logger.Info("server started", "port", 8080)

# Configuration

Use functional options to customize the logger:

	logger := logging.New(
		logging.WithFormat(logging.FormatText),
		logging.WithLevel(slog.LevelDebug),
	)

# Dynamic Level Changes

Pass a [log/slog.LevelVar] to change the level at runtime:

	var lvl slog.LevelVar
	logger := logging.New(logging.WithLevel(&lvl))
	lvl.Set(slog.LevelDebug) // takes effect immediately

# Testing

Inject a buffer to capture log output in tests:

	var buf bytes.Buffer
	logger := logging.New(logging.WithOutput(&buf))
	logger.Info("test message")
	// inspect buf.String()

# Handler Access

Use [NewHandler] when you need to wrap the handler with middleware:

	base := logging.NewHandler(logging.WithLevel(slog.LevelDebug))
	wrapped := &myMiddleware{Handler: base}
	logger := slog.New(wrapped)

# Stability

This package is Alpha stability. The API may change without notice.
See the toolhive-core README for stability level definitions.
*/
package logging
