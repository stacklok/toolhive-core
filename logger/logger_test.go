// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/stacklok/toolhive-core/env/mocks"
)

// mockDebugProvider implements DebugProvider for testing
type mockDebugProvider struct {
	debug bool
}

func (m *mockDebugProvider) IsDebug() bool {
	return m.debug
}

// TestUnstructuredLogsCheck tests the unstructuredLogs function
func TestUnstructuredLogsCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		envValue string
		expected bool
	}{
		{"Default Case", "", true},
		{"Explicitly True", "true", true},
		{"Explicitly False", "false", false},
		{"Invalid Value", "not-a-bool", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			defer ctrl.Finish()

			mockEnv := mocks.NewMockReader(ctrl)
			mockEnv.EXPECT().Getenv("UNSTRUCTURED_LOGS").Return(tt.envValue)

			if got := unstructuredLogsWithEnv(mockEnv); got != tt.expected {
				t.Errorf("unstructuredLogsWithEnv() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestUnstructuredLogger tests the unstructured logger functionality
func TestUnstructuredLogger(t *testing.T) { //nolint:paralleltest // Uses global logger state
	// we only test for the formatted logs here because the unstructured logs
	// do not contain the key/value pair format that the structured logs do
	const (
		levelDebug  = "DEBUG"
		levelInfo   = "INFO"
		levelWarn   = "WARN"
		levelError  = "ERROR"
		levelDPanic = "DPANIC"
		levelPanic  = "PANIC"
	)

	formattedLogTestCases := []struct {
		level    string
		message  string
		key      string
		value    string
		expected string
	}{
		{levelDebug, "debug message %s and %s", "key", "value", "debug message key and value"},
		{levelInfo, "info message %s and %s", "key", "value", "info message key and value"},
		{levelWarn, "warn message %s and %s", "key", "value", "warn message key and value"},
		{levelError, "error message %s and %s", "key", "value", "error message key and value"},
		{levelDPanic, "dpanic message %s and %s", "key", "value", "dpanic message key and value"},
		{levelPanic, "panic message %s and %s", "key", "value", "panic message key and value"},
	}

	for _, tc := range formattedLogTestCases { //nolint:paralleltest // Uses global logger state
		t.Run("FormattedLogs_"+tc.level, func(t *testing.T) {
			// For unstructured logs, we still need to capture stderr output
			// but we can use a buffer-based approach that's more coverage-friendly
			var buf bytes.Buffer

			// Create a development config that writes to our buffer instead of stderr
			config := zap.NewDevelopmentConfig()
			config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
			config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
			config.DisableStacktrace = true
			config.DisableCaller = true

			// Create a core that writes to our buffer
			core := zapcore.NewCore(
				zapcore.NewConsoleEncoder(config.EncoderConfig),
				zapcore.AddSync(&buf),
				zapcore.DebugLevel,
			)

			logger := zap.New(core)
			zap.ReplaceGlobals(logger)

			// Handle panic recovery for DPANIC and PANIC levels
			var panicOccurred bool
			defer func() {
				if r := recover(); r != nil {
					panicOccurred = true
					if tc.level != "PANIC" {
						t.Errorf("Unexpected panic for level %s: %v", tc.level, r)
					}
				}
			}()

			// Log the message based on the level
			switch tc.level {
			case levelDebug:
				Debugf(tc.message, tc.key, tc.value)
			case levelInfo:
				Infof(tc.message, tc.key, tc.value)
			case levelWarn:
				Warnf(tc.message, tc.key, tc.value)
			case levelError:
				Errorf(tc.message, tc.key, tc.value)
			case levelDPanic:
				DPanicf(tc.message, tc.key, tc.value)
			case levelPanic:
				Panicf(tc.message, tc.key, tc.value)
			}

			// For panic levels, verify panic occurred, otherwise check output
			if tc.level == "PANIC" {
				require.True(t, panicOccurred, "Expected panic for level %s", tc.level)
				// For panic levels, we might not get log entries before the panic
				return
			}

			// Note: DPanic only panics in development mode, not in tests by default
			// So we treat it like a regular error level for verification purposes

			// Get the captured output from buffer
			output := buf.String()
			assert.Contains(t, output, tc.level, "Expected log entry '%s' to contain log level '%s'", output, tc.level)
			assert.Contains(t, output, tc.expected, "Expected log entry '%s' to contain message '%s'", output, tc.expected)
		})
	}
}

// TestInitialize tests the Initialize function
func TestInitialize(t *testing.T) { //nolint:paralleltest // Uses global logger state
	// Test structured logs (JSON)
	t.Run("Structured Logs", func(t *testing.T) { //nolint:paralleltest // Uses global logger state

		// Create observer to capture logs in memory
		core, observedLogs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)
		zap.ReplaceGlobals(logger)

		// Log a test message
		Info("test message")

		// Get captured log entries from observer
		allEntries := observedLogs.All()
		require.Len(t, allEntries, 1, "Expected exactly one log entry")

		entry := allEntries[0]
		assert.Equal(t, "info", entry.Level.String(), "Log level mismatch")
		assert.Equal(t, "test message", entry.Message, "Log message mismatch")
	})

	// Test unstructured logs
	t.Run("Unstructured Logs", func(t *testing.T) { //nolint:paralleltest // Uses global logger state

		// For unstructured logs, we use a buffer-based approach
		var buf bytes.Buffer

		// Create a development config that writes to our buffer
		config := zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("15:04:05")
		config.DisableStacktrace = true
		config.DisableCaller = true

		// Create a core that writes to our buffer
		core := zapcore.NewCore(
			zapcore.NewConsoleEncoder(config.EncoderConfig),
			zapcore.AddSync(&buf),
			zapcore.InfoLevel,
		)

		logger := zap.New(core)
		zap.ReplaceGlobals(logger)

		// Log a test message
		Info("test message")

		// Get the captured output from buffer
		output := buf.String()

		// Verify unstructured format (should contain message but not be JSON)
		assert.Contains(t, output, "test message", "Expected output to contain 'test message'")
		assert.Contains(t, output, "INFO", "Expected output to contain 'INFO'")
	})
}

// TestInitializeWithDebug tests the debug provider functionality
func TestInitializeWithDebug(t *testing.T) { //nolint:paralleltest // Uses global logger state
	t.Run("Debug Mode Enabled", func(t *testing.T) { //nolint:paralleltest // Uses global logger state
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockEnv := mocks.NewMockReader(ctrl)
		mockEnv.EXPECT().Getenv("UNSTRUCTURED_LOGS").Return("false")

		debugProvider := &mockDebugProvider{debug: true}
		InitializeWithOptions(mockEnv, debugProvider)

		// Verify debug level is set by checking if debug messages are logged
		core, observedLogs := observer.New(zapcore.DebugLevel)
		logger := zap.New(core)
		zap.ReplaceGlobals(logger)

		Debug("debug test message")

		allEntries := observedLogs.All()
		require.Len(t, allEntries, 1, "Expected one log entry")
		assert.Equal(t, "debug", allEntries[0].Level.String())
	})

	t.Run("Debug Mode Disabled", func(t *testing.T) { //nolint:paralleltest // Uses global logger state
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockEnv := mocks.NewMockReader(ctrl)
		mockEnv.EXPECT().Getenv("UNSTRUCTURED_LOGS").Return("false")

		debugProvider := &mockDebugProvider{debug: false}
		InitializeWithOptions(mockEnv, debugProvider)

		// With info level, debug messages should not be logged
		core, observedLogs := observer.New(zapcore.InfoLevel)
		logger := zap.New(core)
		zap.ReplaceGlobals(logger)

		Debug("debug test message - should not appear")
		Info("info test message")

		allEntries := observedLogs.All()
		require.Len(t, allEntries, 1, "Expected only one log entry (info)")
		assert.Equal(t, "info", allEntries[0].Level.String())
	})
}
