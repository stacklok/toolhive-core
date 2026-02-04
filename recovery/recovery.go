// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package recovery

import (
	"net/http"
)

// Middleware is an HTTP middleware that recovers from panics.
// When a panic occurs, it returns a 500 Internal Server Error response
// to the client, preventing the panic from crashing the server.
//
// TODO(#7): Add configurable logging support once common logging is
// established across ToolHive. Currently panics are silently recovered.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recover() != nil {
				// TODO(#7): Log panic value and stack trace
				// stack := debug.Stack()
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}
