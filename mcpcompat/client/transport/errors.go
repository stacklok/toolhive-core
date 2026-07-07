// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package transport

import (
	"errors"
	"fmt"
)

// These error values mirror github.com/mark3labs/mcp-go/client/transport so that
// ToolHive's auth-detection code (errors.Is / errors.As against these) keeps
// working after the import swap. The go-sdk-backed client (see the client
// package) maps the underlying SDK/HTTP failures onto these sentinels.
var (
	// ErrAuthorizationRequired indicates the server requires authorization
	// (HTTP 401 with a WWW-Authenticate header per RFC 9728).
	ErrAuthorizationRequired = errors.New("authorization required")

	// ErrOAuthAuthorizationRequired indicates OAuth authorization is required
	// and no valid token is available.
	ErrOAuthAuthorizationRequired = errors.New("no valid token available, authorization required")

	// ErrUnauthorized indicates an HTTP 401 response.
	ErrUnauthorized = fmt.Errorf("unauthorized (401)")

	// ErrLegacySSEServer indicates the server returned 4xx for the initialize
	// POST, which usually means it is a legacy SSE-only server.
	ErrLegacySSEServer = fmt.Errorf("server returned 4xx for initialize POST, likely a legacy SSE server")

	// ErrSessionTerminated indicates the server no longer recognizes the
	// current session (HTTP 404); the client must re-initialize.
	ErrSessionTerminated = fmt.Errorf("session terminated (404). need to re-initialize")
)

// Error wraps a transport-level error. It mirrors mcp-go's transport.Error so
// that errors.As(err, new(*transport.Error)) continues to work.
type Error struct {
	Err error
}

func (e *Error) Error() string {
	return fmt.Sprintf("transport error: %v", e.Err)
}

// Unwrap returns the wrapped error.
func (e *Error) Unwrap() error {
	return e.Err
}

// NewError wraps err in a *Error.
func NewError(err error) *Error {
	return &Error{Err: err}
}

// AuthorizationRequiredError is returned for 401 responses carrying a
// WWW-Authenticate header. It mirrors mcp-go's transport.AuthorizationRequiredError.
type AuthorizationRequiredError struct {
	// ResourceMetadataURL is extracted from the WWW-Authenticate header per RFC 9728.
	ResourceMetadataURL string
}

func (*AuthorizationRequiredError) Error() string {
	return ErrAuthorizationRequired.Error()
}

// Unwrap returns ErrAuthorizationRequired so errors.Is works.
func (*AuthorizationRequiredError) Unwrap() error {
	return ErrAuthorizationRequired
}
