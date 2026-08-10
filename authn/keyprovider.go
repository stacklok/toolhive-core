// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"strings"
)

// KeyProvider supplies verification keys in-process, without an HTTP JWKS
// fetch.
//
// It exists for an EMBEDDED issuer — an authorization server running inside the
// same process or pod as the resource server. Two things make an HTTP fetch
// unworkable in that topology, and a provider solves both:
//
//   - Startup ordering. The embedded issuer's JWKS route is typically mounted on
//     the same listener that serves the resource server, so at the moment the
//     Validator is constructed that listener does not exist yet and a fetch
//     connection-refuses.
//   - Reachability. The issuer's advertised URL may be an external-facing
//     address that is not routable from inside the cluster, so OIDC discovery
//     against it can fail permanently rather than transiently.
//
// Configuring a KeyProvider therefore also relaxes construction: see the
// Config.KeyProvider docs for exactly what becomes non-fatal.
//
// Implementations must be safe for concurrent use: PublicKeys is called on the
// request path, once per token whose kid is not already resolved.
type KeyProvider interface {
	// PublicKeys returns the currently valid verification keys. It is called
	// per validation, so an implementation that computes or reads keys should
	// cache them itself; this package deliberately does not, so that key
	// rotation inside the provider takes effect immediately.
	PublicKeys(ctx context.Context) ([]PublicKey, error)
}

// PublicKey is one verification key offered by a KeyProvider.
type PublicKey struct {
	// KeyID is the JWK kid this key answers to. It may be empty, in which case
	// the key is considered a candidate for any token — including one that
	// carries a kid, since an embedded issuer with a single key commonly omits
	// it on one side or the other.
	KeyID string

	// Alg optionally restricts the key to a single JWA algorithm (e.g.
	// "RS256"). When empty the key is eligible for any allow-listed algorithm
	// its type supports, subject to the same kty/curve backstop applied to
	// JWKS keys.
	Alg string

	// Key is the public key itself: *rsa.PublicKey or *ecdsa.PublicKey. Any
	// other type is rejected, since the algorithm allow-list admits only RSA
	// and ECDSA families.
	Key crypto.PublicKey
}

// providerCandidates resolves the provider keys eligible to verify a token with
// the given (possibly empty) kid and algorithm, in the same shape
// candidateKeys returns for a JWKS.
//
// Eligibility mirrors the JWKS path deliberately: a key whose declared Alg
// disagrees with the token, or whose Go type is inconsistent with the token's
// alg family, is skipped rather than handed to the verifier. Without the type
// backstop an ECDSA key could be offered to an RS256 verification path.
func providerCandidates(keys []PublicKey, kid, alg string) []crypto.PublicKey {
	var out []crypto.PublicKey
	for _, pk := range keys {
		// A key that declares a kid must match the token's kid when the token
		// carries one. A key with no kid is always a candidate: an embedded
		// issuer with one key often omits it.
		if pk.KeyID != "" && kid != "" && pk.KeyID != kid {
			continue
		}
		if pk.Alg != "" && pk.Alg != alg {
			continue
		}
		if !providerKeyTypeMatchesAlg(pk.Key, alg) {
			continue
		}
		out = append(out, pk.Key)
		if len(out) == maxKeyCandidates {
			break
		}
	}
	return out
}

// providerKeyTypeMatchesAlg enforces that a provider key's Go type is consistent
// with the token's alg family. It is the KeyProvider analogue of
// keyTypeMatchesAlg, which does the same job for a jwk.Key.
func providerKeyTypeMatchesAlg(key crypto.PublicKey, alg string) bool {
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		// A KeyProvider is caller-implemented, so a nil pointer or a zero-value
		// key (nil N) is a malformed-config bug, not a trusted input; treat it
		// as ineligible rather than let BitLen panic on it.
		if !ok || pub == nil || pub.N == nil {
			return false
		}
		// Same RFC 7518 §3.3 strength floor as the JWKS path: an in-process key
		// source is trusted, but not trusted to be correctly configured.
		return pub.N.BitLen() >= minRSAKeyBits
	case strings.HasPrefix(alg, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		// Same reasoning as the RSA branch: guard against a nil pointer or a
		// nil/unset Curve before calling Params(), which would otherwise panic
		// on the nil interface method call.
		if !ok || pub == nil || pub.Curve == nil {
			return false
		}
		params := pub.Params()
		if params == nil {
			return false
		}
		return curveMatchesAlg(params.Name, alg)
	default:
		// Unreachable via Validate: the alg gate admits only RS/PS/ES.
		return false
	}
}

// keysFromProvider asks the provider for candidates. A provider error is
// reported as CodeUnavailable, not as an invalid token: the verifier could not
// make a determination, exactly as with an unreachable JWKS.
func (v *Validator) keysFromProvider(ctx context.Context, kid, alg string) ([]crypto.PublicKey, error) {
	keys, err := v.cfg.KeyProvider.PublicKeys(ctx)
	if err != nil {
		return nil, &Error{Code: CodeUnavailable, Reason: ReasonKeysUnavailable,
			err: fmt.Errorf("key provider failed: %w", err)}
	}
	return providerCandidates(keys, kid, alg), nil
}
