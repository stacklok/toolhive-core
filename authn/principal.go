// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"fmt"
	"slices"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	claimScope = "scope"
	claimSCP   = "scp"
)

// TrustRef identifies the TrustSet trust that verified a token: its ID, its
// issuer and the Tag the caller attached to it.
type TrustRef struct {
	ID     string
	Issuer string
	// Tag is Trust.Tag, returned unchanged.
	Tag any
}

// RequireScopes returns nil when the principal holds every scope in scopes (and
// when none are given). Otherwise it returns an *Error with CodeInsufficientScope
// and ReasonScope that carries the requested scopes.
//
// It checks Principal.Scopes only. A token with no `scope` or `scp` claim has no
// scopes, so it never satisfies a call with one or more scopes. That includes
// Microsoft Entra app-only (client-credentials) tokens, which carry `roles` and
// no `scp`, and ID tokens, which carry neither. The `roles` claim is
// deliberately not treated as scopes: read it from Principal.Claims.
func (p Principal) RequireScopes(scopes ...string) error {
	var missing []string
	for _, s := range scopes {
		if !slices.Contains(p.Scopes, s) {
			missing = append(missing, s)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return &Error{
		Code:   CodeInsufficientScope,
		Reason: ReasonScope,
		err:    fmt.Errorf("token lacks required scope(s) %q", missing),
		scopes: slices.Clone(scopes),
	}
}

// parseScopes reads the token's scopes. When `scope` is present it alone is
// used, and `scp` is never consulted or merged: a string is split on spaces and
// anything else yields nil. Otherwise `scp` is used: a string is split on
// spaces, and an array only when every element is a string. Empty elements are
// dropped and an empty result is nil.
func parseScopes(claims jwt.MapClaims) []string {
	var out []string
	if raw, present := claims[claimScope]; present {
		s, _ := raw.(string)
		out = splitScopes(s)
	} else {
		switch v := claims[claimSCP].(type) {
		case string:
			out = splitScopes(v)
		case []any:
			for _, e := range v {
				s, ok := e.(string)
				if !ok {
					return nil
				}
				if s != "" {
					out = append(out, s)
				}
			}
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// splitScopes splits a space-delimited scope string on SP (%x20) only, as RFC
// 6749 §3.3 defines, and drops empty elements so repeated spaces are tolerated.
// A tab, a no-break space or any other whitespace is part of a scope-token and
// never a delimiter, so such a value does not match a valid scope: it fails
// closed.
func splitScopes(s string) []string {
	return slices.DeleteFunc(strings.Split(s, " "), func(e string) bool { return e == "" })
}
