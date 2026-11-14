// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package jose

import "strings"

// JOSE "typ" header values (RFC 7515 Section 4.1.9), in short form without the
// optional "application/" prefix.
const (
	// JWTTypeAccessToken is the typ of an RFC 9068 JWT access token.
	JWTTypeAccessToken = "at+jwt"
	// JWTTypeIDJAG is the typ of an Identity Assertion JWT Authorization Grant,
	// which is presented at a token endpoint and is never a bearer token.
	JWTTypeIDJAG = "oauth-id-jag+jwt"
	// JWTTypeLogout is the typ of an OpenID Connect Back-Channel Logout token.
	JWTTypeLogout = "logout+jwt"
	// JWTTypeSecEvent is the typ of a Security Event Token (RFC 8417).
	JWTTypeSecEvent = "secevent+jwt"
	// JWTTypeDPoP is the typ of a DPoP proof JWT (RFC 9449).
	JWTTypeDPoP = "dpop+jwt"
	// JWTTypeTokenIntrospection is the typ of a JWT introspection response
	// (RFC 9701).
	JWTTypeTokenIntrospection = "token-introspection+jwt"
)

const mediaTypePrefix = "application/"

// IsJOSEType reports whether a "typ" header value names the given media type.
// The comparison is case-insensitive, the "application/" prefix is optional on
// either side, and whitespace is not trimmed. An empty value never matches.
func IsJOSEType(headerTyp, mediaType string) bool {
	typ := normalize(headerTyp)
	return typ != "" && typ == normalize(mediaType)
}

// IsIDJAG reports whether a "typ" header value names an ID-JAG.
func IsIDJAG(headerTyp string) bool {
	return IsJOSEType(headerTyp, JWTTypeIDJAG)
}

func normalize(v string) string {
	return strings.TrimPrefix(strings.ToLower(v), mediaTypePrefix)
}
