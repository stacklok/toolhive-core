// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package logging

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	t.Parallel()

	t.Run("returns a non-nil logger with no options", func(t *testing.T) {
		t.Parallel()
		logger := New()
		assert.NotNil(t, logger)
	})

	t.Run("default format is JSON with RFC3339 timestamps", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := New(WithOutput(&buf))

		logger.Info("test message", "key", "value")

		var entry map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

		assert.Equal(t, "INFO", entry["level"])
		assert.Equal(t, "test message", entry["msg"])
		assert.Equal(t, "value", entry["key"])

		ts, ok := entry["time"].(string)
		require.True(t, ok, "time field should be a string")
		_, err := time.Parse(time.RFC3339, ts)
		assert.NoError(t, err, "timestamp should be valid RFC3339")
	})

	t.Run("default level is INFO", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		logger := New(WithOutput(&buf))

		logger.Debug("should not appear")
		assert.Empty(t, buf.String(), "DEBUG should be filtered at INFO level")

		logger.Info("should appear")
		assert.NotEmpty(t, buf.String(), "INFO should be written at INFO level")
	})
}

func TestNew_WithFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format Format
		check  func(t *testing.T, output string)
	}{
		{
			name:   "JSON format produces valid JSON",
			format: FormatJSON,
			check: func(t *testing.T, output string) {
				t.Helper()
				var entry map[string]any
				require.NoError(t, json.Unmarshal([]byte(output), &entry))
				assert.Equal(t, "INFO", entry["level"])
				assert.Equal(t, "hello", entry["msg"])
			},
		},
		{
			name:   "text format produces key=value output",
			format: FormatText,
			check: func(t *testing.T, output string) {
				t.Helper()
				assert.Contains(t, output, "level=INFO")
				assert.Contains(t, output, "msg=hello")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := New(WithFormat(tc.format), WithOutput(&buf))

			logger.Info("hello")

			tc.check(t, buf.String())
		})
	}
}

func TestNew_WithLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		level       slog.Level
		logLevel    slog.Level
		shouldWrite bool
	}{
		{"debug logger writes debug", slog.LevelDebug, slog.LevelDebug, true},
		{"info logger filters debug", slog.LevelInfo, slog.LevelDebug, false},
		{"info logger writes info", slog.LevelInfo, slog.LevelInfo, true},
		{"warn logger filters info", slog.LevelWarn, slog.LevelInfo, false},
		{"warn logger writes warn", slog.LevelWarn, slog.LevelWarn, true},
		{"error logger filters warn", slog.LevelError, slog.LevelWarn, false},
		{"error logger writes error", slog.LevelError, slog.LevelError, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := New(WithLevel(tc.level), WithOutput(&buf))

			logger.Log(context.TODO(), tc.logLevel, "test")

			if tc.shouldWrite {
				assert.NotEmpty(t, buf.String())
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestNew_DynamicLevel(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	var lvl slog.LevelVar
	lvl.Set(slog.LevelWarn)

	logger := New(WithLevel(&lvl), WithOutput(&buf))

	logger.Info("should not appear")
	assert.Empty(t, buf.String(), "INFO should be filtered at WARN level")

	lvl.Set(slog.LevelInfo)
	logger.Info("should appear")
	assert.NotEmpty(t, buf.String(), "INFO should be written after level change")
}

func TestNew_TimestampFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format Format
		parse  func(t *testing.T, output string) string
	}{
		{
			name:   "JSON timestamp is RFC3339",
			format: FormatJSON,
			parse: func(t *testing.T, output string) string {
				t.Helper()
				var entry map[string]any
				require.NoError(t, json.Unmarshal([]byte(output), &entry))
				ts, ok := entry["time"].(string)
				require.True(t, ok)
				return ts
			},
		},
		{
			name:   "text timestamp is RFC3339",
			format: FormatText,
			parse: func(t *testing.T, output string) string {
				t.Helper()
				// slog text format: time=<value> level=...
				// Extract the time value between "time=" and the next space
				const prefix = "time="
				start := len(prefix)
				require.Greater(t, len(output), start)
				end := start
				for end < len(output) && output[end] != ' ' {
					end++
				}
				return output[start:end]
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := New(WithFormat(tc.format), WithOutput(&buf))

			logger.Info("test")

			ts := tc.parse(t, buf.String())
			_, err := time.Parse(time.RFC3339, ts)
			assert.NoError(t, err, "timestamp %q should be valid RFC3339", ts)
		})
	}
}

func TestNew_MultipleOptions(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	logger := New(
		WithFormat(FormatText),
		WithLevel(slog.LevelDebug),
		WithOutput(&buf),
	)

	logger.Debug("debug message")

	output := buf.String()
	assert.Contains(t, output, "level=DEBUG")
	assert.Contains(t, output, "msg=\"debug message\"")
}

func TestNewHandler(t *testing.T) {
	t.Parallel()

	t.Run("returns a non-nil handler with no options", func(t *testing.T) {
		t.Parallel()
		handler := NewHandler()
		assert.NotNil(t, handler)
	})

	t.Run("default format is JSON with RFC3339 timestamps", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		handler := NewHandler(WithOutput(&buf))
		logger := slog.New(handler)

		logger.Info("test message", "key", "value")

		var entry map[string]any
		require.NoError(t, json.Unmarshal(buf.Bytes(), &entry))

		assert.Equal(t, "INFO", entry["level"])
		assert.Equal(t, "test message", entry["msg"])
		assert.Equal(t, "value", entry["key"])

		ts, ok := entry["time"].(string)
		require.True(t, ok, "time field should be a string")
		_, err := time.Parse(time.RFC3339, ts)
		assert.NoError(t, err, "timestamp should be valid RFC3339")
	})
}

func TestNewHandler_WithFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		format Format
		check  func(t *testing.T, output string)
	}{
		{
			name:   "JSON format produces valid JSON",
			format: FormatJSON,
			check: func(t *testing.T, output string) {
				t.Helper()
				var entry map[string]any
				require.NoError(t, json.Unmarshal([]byte(output), &entry))
				assert.Equal(t, "INFO", entry["level"])
				assert.Equal(t, "hello", entry["msg"])
			},
		},
		{
			name:   "text format produces key=value output",
			format: FormatText,
			check: func(t *testing.T, output string) {
				t.Helper()
				assert.Contains(t, output, "level=INFO")
				assert.Contains(t, output, "msg=hello")
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			handler := NewHandler(WithFormat(tc.format), WithOutput(&buf))
			logger := slog.New(handler)

			logger.Info("hello")

			tc.check(t, buf.String())
		})
	}
}

func TestNewHandler_WithLevel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		level       slog.Level
		logLevel    slog.Level
		shouldWrite bool
	}{
		{"debug logger writes debug", slog.LevelDebug, slog.LevelDebug, true},
		{"info logger filters debug", slog.LevelInfo, slog.LevelDebug, false},
		{"info logger writes info", slog.LevelInfo, slog.LevelInfo, true},
		{"warn logger filters info", slog.LevelWarn, slog.LevelInfo, false},
		{"warn logger writes warn", slog.LevelWarn, slog.LevelWarn, true},
		{"error logger filters warn", slog.LevelError, slog.LevelWarn, false},
		{"error logger writes error", slog.LevelError, slog.LevelError, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			handler := NewHandler(WithLevel(tc.level), WithOutput(&buf))
			logger := slog.New(handler)

			logger.Log(context.TODO(), tc.logLevel, "test")

			if tc.shouldWrite {
				assert.NotEmpty(t, buf.String())
			} else {
				assert.Empty(t, buf.String())
			}
		})
	}
}

func TestNewHandler_ProducesSameOutputAsNew(t *testing.T) {
	t.Parallel()

	var buf1, buf2 bytes.Buffer
	loggerFromNew := New(WithOutput(&buf1))
	loggerFromHandler := slog.New(NewHandler(WithOutput(&buf2)))

	loggerFromNew.Info("same message", "key", "value")
	loggerFromHandler.Info("same message", "key", "value")

	var entry1, entry2 map[string]any
	require.NoError(t, json.Unmarshal(buf1.Bytes(), &entry1))
	require.NoError(t, json.Unmarshal(buf2.Bytes(), &entry2))

	assert.Equal(t, entry1["level"], entry2["level"])
	assert.Equal(t, entry1["msg"], entry2["msg"])
	assert.Equal(t, entry1["key"], entry2["key"])
}

func TestReplaceAttr(t *testing.T) {
	t.Parallel()

	t.Run("formats time attribute to RFC3339", func(t *testing.T) {
		t.Parallel()
		now := time.Date(2026, 2, 17, 10, 30, 0, 0, time.UTC)
		attr := slog.Time(slog.TimeKey, now)

		result := replaceAttr(nil, attr)

		assert.Equal(t, slog.TimeKey, result.Key)
		assert.Equal(t, "2026-02-17T10:30:00Z", result.Value.String())
	})

	t.Run("passes non-time attributes unchanged", func(t *testing.T) {
		t.Parallel()
		attr := slog.String("key", "value")

		result := replaceAttr(nil, attr)

		assert.Equal(t, attr, result)
	})
}
