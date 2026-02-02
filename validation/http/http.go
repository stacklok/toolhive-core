// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package http provides validation functions for HTTP headers and URIs.
package http

import (
	"fmt"
	"net/url"

	"golang.org/x/net/http/httpguts"
)

// ValidateHeaderName validates that a string is a valid HTTP header name per RFC 7230.
// It checks for CRLF injection, control characters, and ensures RFC token compliance.
func ValidateHeaderName(name string) error {
	if name == "" {
		return fmt.Errorf("header name cannot be empty")
	}

	// Length limit to prevent DoS
	if len(name) > 256 {
		return fmt.Errorf("header name exceeds maximum length of 256 bytes")
	}

	// Use httpguts validation (same as Go's HTTP/2 implementation)
	if !httpguts.ValidHeaderFieldName(name) {
		return fmt.Errorf("invalid HTTP header name: contains invalid characters")
	}

	return nil
}

// ValidateHeaderValue validates that a string is a valid HTTP header value per RFC 7230.
// It checks for CRLF injection and control characters.
func ValidateHeaderValue(value string) error {
	if value == "" {
		return fmt.Errorf("header value cannot be empty")
	}

	// Length limit to prevent DoS (common HTTP server limit)
	if len(value) > 8192 {
		return fmt.Errorf("header value exceeds maximum length of 8192 bytes")
	}

	// Use httpguts validation
	if !httpguts.ValidHeaderFieldValue(value) {
		return fmt.Errorf("invalid HTTP header value: contains control characters")
	}

	return nil
}

// ValidateResourceURI validates that a resource URI conforms to RFC 8707 requirements
// for canonical URIs used in OAuth 2.0 resource indicators.
//
// A valid canonical URI must:
//   - Include a scheme (http/https)
//   - Include a host
//   - Not contain fragments
func ValidateResourceURI(resourceURI string) error {
	if resourceURI == "" {
		return fmt.Errorf("resource URI cannot be empty")
	}

	// Parse the URI
	parsed, err := url.Parse(resourceURI)
	if err != nil {
		return fmt.Errorf("invalid resource URI: %w", err)
	}

	// Must have a scheme
	if parsed.Scheme == "" {
		return fmt.Errorf("resource URI must include a scheme (e.g., https://): %s", resourceURI)
	}

	// Must have a host
	if parsed.Host == "" {
		return fmt.Errorf("resource URI must include a host: %s", resourceURI)
	}

	// Must not contain fragments
	if parsed.Fragment != "" {
		return fmt.Errorf("resource URI must not contain fragments (#): %s", resourceURI)
	}

	return nil
}
