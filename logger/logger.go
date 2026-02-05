// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package logger provides a logging capability for toolhive projects for running locally as a CLI and in Kubernetes
package logger

import (
	"strconv"
	"time"

	"github.com/go-logr/logr"
	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/stacklok/toolhive-core/env"
)

// Debug logs a message at debug level using the singleton logger.
func Debug(msg string) {
	zap.S().Debug(msg)
}

// Debugf logs a message at debug level using the singleton logger.
func Debugf(msg string, args ...any) {
	zap.S().Debugf(msg, args...)
}

// Debugw logs a message at debug level using the singleton logger with additional key-value pairs.
func Debugw(msg string, keysAndValues ...any) {
	zap.S().Debugw(msg, keysAndValues...)
}

// Info logs a message at info level using the singleton logger.
func Info(msg string) {
	zap.S().Info(msg)
}

// Infof logs a message at info level using the singleton logger.
func Infof(msg string, args ...any) {
	zap.S().Infof(msg, args...)
}

// Infow logs a message at info level using the singleton logger with additional key-value pairs.
func Infow(msg string, keysAndValues ...any) {
	zap.S().Infow(msg, keysAndValues...)
}

// Warn logs a message at warning level using the singleton logger.
func Warn(msg string) {
	zap.S().Warn(msg)
}

// Warnf logs a message at warning level using the singleton logger.
func Warnf(msg string, args ...any) {
	zap.S().Warnf(msg, args...)
}

// Warnw logs a message at warning level using the singleton logger with additional key-value pairs.
func Warnw(msg string, keysAndValues ...any) {
	zap.S().Warnw(msg, keysAndValues...)
}

// Error logs a message at error level using the singleton logger.
func Error(msg string) {
	zap.S().Error(msg)
}

// Errorf logs a message at error level using the singleton logger.
func Errorf(msg string, args ...any) {
	zap.S().Errorf(msg, args...)
}

// Errorw logs a message at error level using the singleton logger with additional key-value pairs.
func Errorw(msg string, keysAndValues ...any) {
	zap.S().Errorw(msg, keysAndValues...)
}

// Panic logs a message at error level using the singleton logger and panics the program.
func Panic(msg string) {
	zap.S().Panic(msg)
}

// Panicf logs a message at error level using the singleton logger and panics the program.
func Panicf(msg string, args ...any) {
	zap.S().Panicf(msg, args...)
}

// Panicw logs a message at error level using the singleton logger with additional key-value pairs and panics the program.
func Panicw(msg string, keysAndValues ...any) {
	zap.S().Panicw(msg, keysAndValues...)
}

// DPanic logs a message at error level using the singleton logger and panics the program.
func DPanic(msg string) {
	zap.S().DPanic(msg)
}

// DPanicf logs a message at error level using the singleton logger and panics the program.
func DPanicf(msg string, args ...any) {
	zap.S().DPanicf(msg, args...)
}

// DPanicw logs a message at error level using the singleton logger with additional key-value pairs and panics the program.
func DPanicw(msg string, keysAndValues ...any) {
	zap.S().DPanicw(msg, keysAndValues...)
}

// Fatal logs a message at error level using the singleton logger and exits the program.
func Fatal(msg string) {
	zap.S().Fatal(msg)
}

// Fatalf logs a message at error level using the singleton logger and exits the program.
func Fatalf(msg string, args ...any) {
	zap.S().Fatalf(msg, args...)
}

// Fatalw logs a message at error level using the singleton logger with additional key-value pairs and exits the program.
func Fatalw(msg string, keysAndValues ...any) {
	zap.S().Fatalw(msg, keysAndValues...)
}

// NewLogr returns a logr.Logger which uses zap logger
func NewLogr() logr.Logger {
	return zapr.NewLogger(zap.L())
}

// DebugProvider is an interface for checking if debug mode is enabled.
// This allows different projects to plug in their own debug flag implementation.
type DebugProvider interface {
	IsDebug() bool
}

// defaultDebugProvider provides a default implementation that returns false.
type defaultDebugProvider struct{}

func (*defaultDebugProvider) IsDebug() bool {
	return false
}

// Initialize creates and configures the appropriate logger using the default debug provider.
// If the UNSTRUCTURED_LOGS is set to true, it will output plain log message
// with only time and LogLevelType (INFO, DEBUG, ERROR, WARN).
// Otherwise it will create a standard structured slog logger.
func Initialize() {
	InitializeWithOptions(&env.OSReader{}, &defaultDebugProvider{})
}

// InitializeWithDebug creates and configures the logger with a custom debug provider.
// This allows callers to plug in their own debug flag implementation (e.g., viper).
func InitializeWithDebug(debugProvider DebugProvider) {
	InitializeWithOptions(&env.OSReader{}, debugProvider)
}

// InitializeWithEnv creates and configures the appropriate logger with a custom environment reader.
// This allows for dependency injection of environment variable access for testing.
// Deprecated: Use InitializeWithOptions instead.
func InitializeWithEnv(envReader env.Reader) {
	InitializeWithOptions(envReader, &defaultDebugProvider{})
}

// InitializeWithOptions creates and configures the logger with custom environment reader and debug provider.
// This provides full control over logger configuration for both testing and production use.
func InitializeWithOptions(envReader env.Reader, debugProvider DebugProvider) {
	var config zap.Config
	if unstructuredLogsWithEnv(envReader) {
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		config.EncoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout(time.Kitchen)
		config.OutputPaths = []string{"stderr"}
		config.DisableStacktrace = true
		config.DisableCaller = true
	} else {
		config = zap.NewProductionConfig()
		config.OutputPaths = []string{"stdout"}
	}

	// Set log level based on current debug flag
	if debugProvider.IsDebug() {
		config.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	} else {
		config.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	zap.ReplaceGlobals(zap.Must(config.Build()))
}

func unstructuredLogsWithEnv(envReader env.Reader) bool {
	unstructuredLogs, err := strconv.ParseBool(envReader.Getenv("UNSTRUCTURED_LOGS"))
	if err != nil {
		// at this point if the error is not nil, the env var wasn't set, or is ""
		// which means we just default to outputting unstructured logs.
		return true
	}
	return unstructuredLogs
}
