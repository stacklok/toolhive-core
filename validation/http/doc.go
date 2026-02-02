// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

/*
Package http provides security-focused validation functions for HTTP headers and URIs.

This package helps prevent common security vulnerabilities such as HTTP header injection
(CRLF injection) and malformed URI attacks by validating input against RFC specifications.

# Header Validation

Validate HTTP header names and values per RFC 7230:

	if err := http.ValidateHeaderName("X-Custom-Header"); err != nil {
		// Handle invalid header name
	}

	if err := http.ValidateHeaderValue("Bearer token123"); err != nil {
		// Handle invalid header value
	}

The validators check for:
  - CRLF injection attempts (\r\n sequences)
  - Control characters
  - RFC 7230 token compliance for header names
  - Length limits to prevent DoS (256 bytes for names, 8192 for values)

# Resource URI Validation

Validate URIs for use as OAuth 2.0 resource indicators per RFC 8707:

	if err := http.ValidateResourceURI("https://api.example.com/v1"); err != nil {
		// Handle invalid URI
	}

Resource URIs must:
  - Include a scheme (typically http or https)
  - Include a host
  - Not contain fragment identifiers (#)
*/
package http
