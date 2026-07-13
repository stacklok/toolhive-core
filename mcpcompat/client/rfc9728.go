// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package client

import "strings"

// This file implements RFC 9728 §5.1 WWW-Authenticate header parsing to extract
// the resource_metadata parameter, which carries the URL to the protected
// resource metadata document. The parsing logic mirrors mcp-go's
// extractResourceMetadataURL/extractResourceMetadataURLs so the shim's
// AuthorizationRequiredError.ResourceMetadataURL is populated identically.
//
// The go-sdk does not surface the WWW-Authenticate header on its errors, so the
// shim's own headerRoundTripper captures it (see captureErrorBody) and the error
// mappers call extractResourceMetadataURL to parse it.

// extractResourceMetadataURLFromHeaders returns the first resource_metadata
// parameter value found across the given WWW-Authenticate header values, per
// RFC 9728 §5.1. Returns empty string when none is present.
func extractResourceMetadataURLFromHeaders(wwwAuthHeaders []string) string {
	for _, header := range wwwAuthHeaders {
		for _, u := range extractResourceMetadataURLs(header) {
			if u != "" {
				return u
			}
		}
	}
	return ""
}

// extractResourceMetadataURLs returns every resource_metadata parameter value
// from a single WWW-Authenticate header value per RFC 9728 §5.1, in the order
// they appear. Returns an empty slice when the header is empty or no such
// parameters are present. Parameter names are matched case-insensitively per
// RFC 9110 §11.2; both quoted-string and token value forms are accepted.
//
//nolint:gocyclo // direct port of mcp-go's well-tested parser; restructuring harms readability
func extractResourceMetadataURLs(header string) []string {
	const target = "resource_metadata"
	var out []string
	i := 0
	for i < len(header) {
		// Advance to the next token start.
		for i < len(header) && !isAuthTokenChar(header[i]) {
			i++
		}
		nameStart := i
		for i < len(header) && isAuthTokenChar(header[i]) {
			i++
		}
		name := header[nameStart:i]
		// Skip optional whitespace between the name and '='.
		for i < len(header) && (header[i] == ' ' || header[i] == '\t') {
			i++
		}
		if i >= len(header) || header[i] != '=' {
			// Name was a scheme token (e.g. "Bearer"), not a parameter.
			continue
		}
		// Skip '=' and optional whitespace.
		i++
		for i < len(header) && (header[i] == ' ' || header[i] == '\t') {
			i++
		}
		value, next, ok := parseAuthParamValue(header, i)
		i = next
		if !ok {
			continue
		}
		if value != "" && strings.EqualFold(name, target) {
			out = append(out, value)
		}
	}
	return out
}

// parseAuthParamValue reads a single WWW-Authenticate parameter value starting
// at offset i: a quoted-string (with backslash escapes) when the first byte is
// '"', otherwise a bare token. It returns the decoded value, the index of the
// first byte after it, and whether the value was well-formed. Truncated quoted
// strings (no closing '"') and lone trailing backslashes yield ok=false so
// malformed input is rejected rather than producing a partial value.
func parseAuthParamValue(s string, i int) (string, int, bool) {
	if i >= len(s) {
		return "", i, false
	}
	if s[i] == '"' {
		i++
		var b strings.Builder
		for i < len(s) {
			c := s[i]
			if c == '\\' {
				if i+1 >= len(s) {
					return "", i + 1, false
				}
				b.WriteByte(s[i+1])
				i += 2
				continue
			}
			if c == '"' {
				return b.String(), i + 1, true
			}
			b.WriteByte(c)
			i++
		}
		return "", i, false
	}
	start := i
	for i < len(s) && isAuthTokenChar(s[i]) {
		i++
	}
	return s[start:i], i, i > start
}

// isAuthTokenChar reports whether c is a valid RFC 9110 §5.6.2 token character
// — the character class used for scheme and parameter names in
// WWW-Authenticate.
func isAuthTokenChar(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	return strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}
