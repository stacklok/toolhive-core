// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package recovery provides panic recovery middleware for HTTP handlers.
//
// The middleware recovers from panics in HTTP handlers and returns a
// 500 Internal Server Error response to the client. This prevents a single
// panicking request from crashing the entire server.
//
// # Basic Usage
//
//	mux := http.NewServeMux()
//	mux.HandleFunc("/", handler)
//	wrappedMux := recovery.Middleware(mux)
//	http.ListenAndServe(":8080", wrappedMux)
//
// # Logging
//
// By default panics are recovered silently. Use [WithLogger] to log
// panic details (value, stack trace, request method and path) at ERROR level:
//
//	logger := logging.New()
//	wrappedMux := recovery.Middleware(mux, recovery.WithLogger(logger))
//
// # Stability
//
// This package is Beta stability. The API may have minor changes before
// reaching stable status in v1.0.0.
package recovery
