// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// oidcDiscoveryPath is appended to the issuer to locate the OIDC discovery
// document (OpenID Connect Discovery 1.0 §4.1). For a multi-path issuer such
// as https://host/realms/X the path is appended to the issuer path, matching
// the common OIDC-provider convention (Keycloak, Entra ID, Auth0).
const oidcDiscoveryPath = "/.well-known/openid-configuration"

// oidcDiscoveryDocument is a deliberately minimal view of the OIDC discovery
// document: a resource server needs only issuer (for the §4.3 consistency
// check) and jwks_uri. It MUST stay narrower than a full OIDC discovery
// document — a resource server has no business requiring
// authorization_endpoint/token_endpoint, and MUST NOT grow to one.
type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverJWKSURI fetches {issuer}/.well-known/openid-configuration with
// v.httpClient and returns the discovered jwks_uri. Discovered metadata is
// untrusted input: the returned URL is validated exactly as if it had been
// configured (https unless InsecureAllowHTTP).
//
// The doc.Issuer assertion is BYTE-EXACT with NO normalization (OIDC
// Discovery §4.3 / RFC 8414 §3.3): without it a poisoned well-known repoints
// jwks_uri at an attacker JWKS and every downstream check still passes.
func (v *Validator) discoverJWKSURI(ctx context.Context, issuer string) (string, error) {
	// TrimSuffix (not path.Join) joins issuer and path with exactly one "/"
	// while preserving any leading path segments of a multi-path issuer.
	wellKnown := strings.TrimSuffix(issuer, "/") + oidcDiscoveryPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return "", fmt.Errorf("authn: failed to build discovery request for %s: %w", wellKnown, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := v.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("authn: failed to fetch OIDC discovery document from %s: %w", wellKnown, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authn: OIDC discovery endpoint %s returned status %d", wellKnown, resp.StatusCode)
	}

	// The body is already capped at maxResponseBody by the client's transport,
	// so no additional limit is applied here.
	var doc oidcDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("authn: failed to decode OIDC discovery document from %s: %w", wellKnown, err)
	}

	// Byte-exact issuer comparison: no TrimSpace, no trailing-slash folding.
	if doc.Issuer != issuer {
		return "", fmt.Errorf("authn: OIDC discovery document issuer %q does not match configured issuer %q",
			doc.Issuer, issuer)
	}

	if doc.JWKSURI == "" {
		return "", fmt.Errorf("authn: OIDC discovery document from %s is missing jwks_uri", wellKnown)
	}
	if err := validateHTTPSURI("discovered jwks_uri", doc.JWKSURI, v.cfg.InsecureAllowHTTP); err != nil {
		return "", err
	}

	return doc.JWKSURI, nil
}
