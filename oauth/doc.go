// SPDX-FileCopyrightText: Copyright 2025 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package oauth provides shared RFC-defined types, constants, and validation utilities
// for OAuth 2.0 and OpenID Connect. It serves as a shared foundation for both OAuth
// clients and servers, including redirect URI validation per RFC 6749 and RFC 8252.
//
// # Discovery Documents
//
// The package provides types for OAuth 2.0 Authorization Server Metadata (RFC 8414)
// and OpenID Connect Discovery 1.0:
//
//	doc := oauth.OIDCDiscoveryDocument{
//		AuthorizationServerMetadata: oauth.AuthorizationServerMetadata{
//			Issuer:                "https://auth.example.com",
//			AuthorizationEndpoint: "https://auth.example.com/authorize",
//			TokenEndpoint:         "https://auth.example.com/token",
//		},
//	}
//	if err := doc.Validate(true); err != nil {
//		// Handle validation error
//	}
//
// # Redirect URI Validation
//
// The package provides RFC-compliant redirect URI validation with configurable
// policies for security:
//
//	// Strict policy: only https and http-loopback
//	err := oauth.ValidateRedirectURI("https://example.com/callback", oauth.RedirectURIPolicyStrict)
//
//	// Allow private-use schemes for native apps
//	err := oauth.ValidateRedirectURI("myapp://callback", oauth.RedirectURIPolicyAllowPrivateSchemes)
//
// # Stability
//
// This package is Beta stability. The API may have minor changes before
// reaching stable status in v1.0.0.
package oauth
