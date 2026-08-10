// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// oidcDiscoveryPath is appended to the issuer to locate the OIDC discovery
// document (OpenID Connect Discovery 1.0 §4.1). For a multi-path issuer such
// as https://host/realms/X the path is appended to the issuer path, matching
// the common OIDC-provider convention (Keycloak, Entra ID, Auth0).
const oidcDiscoveryPath = "/.well-known/openid-configuration"

const (
	// discoveryAttempts bounds how many times construction tries discovery
	// before giving up. A resource server often starts alongside its issuer, so
	// the first attempt can lose a startup race a retry wins.
	discoveryAttempts = 3
	// discoveryInitialBackoff is the first inter-attempt delay; it doubles.
	discoveryInitialBackoff = 250 * time.Millisecond
)

// errDiscoveryNotTransient marks a discovery failure that retrying cannot fix:
// the endpoint answered, and its answer is unacceptable. Wrapped rather than
// returned directly so callers still get the specific reason.
var errDiscoveryNotTransient = errors.New("discovery response is invalid")

// oidcDiscoveryDocument is a deliberately minimal view of the OIDC discovery
// document: a resource server needs only issuer (for the §4.3 consistency
// check) and jwks_uri. It MUST stay narrower than a full OIDC discovery
// document — a resource server has no business requiring
// authorization_endpoint/token_endpoint, and MUST NOT grow to one.
type oidcDiscoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discoverWithRetry calls discoverJWKSURI, retrying a transient failure with
// exponential backoff until ctx expires or the attempt budget is spent.
//
// A resource server commonly starts alongside its issuer, so the first attempt
// can lose a race that a retry a moment later wins. Only the LAST error is
// returned: the intermediate ones are the same failure observed earlier.
//
// Retries cover transport and status failures indiscriminately, including 5xx —
// a just-starting issuer can serve one. A poisoned-document rejection (issuer
// mismatch, missing jwks_uri, non-https jwks_uri) is NOT transient, so those
// return immediately rather than burning the budget on a verdict that cannot
// change.
func (v *Validator) discoverWithRetry(ctx context.Context, issuer string) (string, error) {
	var lastErr error
	backoff := discoveryInitialBackoff
	for attempt := range discoveryAttempts {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return "", fmt.Errorf("authn: OIDC discovery for %s aborted after %d attempt(s): %w",
					issuer, attempt, lastErr)
			case <-time.After(backoff):
			}
			backoff *= 2
		}
		jwksURI, err := v.discoverJWKSURI(ctx, issuer)
		if err == nil {
			return jwksURI, nil
		}
		lastErr = err
		if errors.Is(err, errDiscoveryNotTransient) {
			return "", err
		}
	}
	return "", fmt.Errorf("authn: OIDC discovery for %s failed after %d attempts: %w",
		issuer, discoveryAttempts, lastErr)
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
	//
	// The three checks below are verdicts on a document the endpoint actually
	// served, so they are marked non-transient: retrying re-fetches the same
	// unacceptable answer.
	if doc.Issuer != issuer {
		return "", fmt.Errorf("authn: OIDC discovery document issuer %q does not match configured issuer %q "+
			"(RFC 8414 §3.3 requires them to be byte-identical; a trailing-slash difference is the usual cause, "+
			"and is NOT folded because folding would accept a non-conformant document): %w",
			doc.Issuer, issuer, errDiscoveryNotTransient)
	}

	if doc.JWKSURI == "" {
		return "", fmt.Errorf("authn: OIDC discovery document from %s is missing jwks_uri: %w",
			wellKnown, errDiscoveryNotTransient)
	}
	if err := validateHTTPSURI("discovered jwks_uri", doc.JWKSURI, v.cfg.InsecureAllowHTTP); err != nil {
		return "", fmt.Errorf("%w: %w", err, errDiscoveryNotTransient)
	}

	return doc.JWKSURI, nil
}
