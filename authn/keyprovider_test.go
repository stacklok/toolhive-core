// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Algorithm names used repeatedly by the eligibility table below.
const (
	testAlgRS256 = "RS256"
	testAlgES256 = "ES256"
	testAlgES384 = "ES384"
)

// fakeKeyProvider is an in-memory KeyProvider. A nil err means success.
type fakeKeyProvider struct {
	keys []PublicKey
	err  error
	// calls counts PublicKeys invocations so tests can assert the provider is
	// consulted (and consulted first).
	calls int
}

func (f *fakeKeyProvider) PublicKeys(_ context.Context) ([]PublicKey, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.keys, nil
}

// providerConfig returns a Config that uses only a KeyProvider: the JWKS URL
// points at a closed port, standing in for an embedded issuer whose listener
// has not started (or is not routable).
func providerConfig(t *testing.T, kp KeyProvider) Config {
	t.Helper()
	cfg := validConfig()
	// 127.0.0.1:1 refuses connections, so any JWKS fetch fails.
	cfg.JWKSURL = "http://127.0.0.1:1/jwks.json"
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	cfg.KeyProvider = kp
	return cfg
}

// TestKeyProviderConstructionSurvivesUnreachableJWKS covers D4: with a
// KeyProvider configured, an unreachable JWKS endpoint must NOT fail
// construction. This is the embedded-auth-server topology — the issuer mounts
// its JWKS route on a listener that starts after the validator is built — and
// it is exactly the case ToolHive relies on today.
func TestKeyProviderConstructionSurvivesUnreachableJWKS(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "local-1")
	kp := &fakeKeyProvider{keys: []PublicKey{{KeyID: "local-1", Key: rsaKey.priv.Public()}}}

	v, err := NewValidator(context.Background(), providerConfig(t, kp))
	require.NoError(t, err, "a KeyProvider must make an unreachable JWKS non-fatal at construction")
	t.Cleanup(v.Close)

	// And the provider's keys verify a token without any HTTP at all.
	p, err := v.Validate(context.Background(), rsaKey.mint(t, validConfig().Issuer))
	require.NoError(t, err, "a provider key must verify a token with no JWKS fetch")
	assert.Equal(t, testSubject, p.Subject)
	assert.Positive(t, kp.calls, "the provider must be consulted")
}

// TestNoKeyProviderStillFailsClosed is the other half of D4: without a
// KeyProvider, construction must remain fail-closed. Relaxing the provider case
// must not relax the default one.
func TestNoKeyProviderStillFailsClosed(t *testing.T) {
	t.Parallel()

	cfg := providerConfig(t, nil)
	cfg.KeyProvider = nil
	v, err := NewValidator(context.Background(), cfg)
	require.Error(t, err, "with no KeyProvider an unreachable JWKS must fail construction")
	assert.Nil(t, v)
	assert.Contains(t, err.Error(), "failed to fetch JWKS")
}

// TestKeyProviderConsultedBeforeJWKS covers D3's ordering: when both sources can
// answer, the provider wins and no JWKS fetch is needed for that token.
func TestKeyProviderConsultedBeforeJWKS(t *testing.T) {
	t.Parallel()

	// The JWKS serves a DIFFERENT key under the same kid. If the JWKS were
	// consulted first the signature check would fail, so a success here proves
	// the provider was preferred.
	tokenKey := mintRSA(t, "shared-kid")
	decoyKey := mintRSA(t, "shared-kid")
	js := newJWKSServer(t, decoyKey.jwk)

	kp := &fakeKeyProvider{keys: []PublicKey{{KeyID: "shared-kid", Key: tokenKey.priv.Public()}}}
	cfg := js.configFor()
	cfg.KeyProvider = kp
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	_, err = v.Validate(context.Background(), tokenKey.mint(t, js.srv.URL))
	require.NoError(t, err, "the provider key must be preferred over the JWKS key for the same kid")
}

// TestKeyProviderMissFallsThroughToJWKS covers the rest of D3: a provider miss
// must still reach the JWKS, so a validator with both sources verifies tokens
// from either.
func TestKeyProviderMissFallsThroughToJWKS(t *testing.T) {
	t.Parallel()

	jwksKey := mintRSA(t, "from-jwks")
	js := newJWKSServer(t, jwksKey.jwk)

	// The provider offers an unrelated kid, so this token misses it.
	otherKey := mintRSA(t, "from-provider")
	kp := &fakeKeyProvider{keys: []PublicKey{{KeyID: "from-provider", Key: otherKey.priv.Public()}}}

	cfg := js.configFor()
	cfg.KeyProvider = kp
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	_, err = v.Validate(context.Background(), jwksKey.mint(t, js.srv.URL))
	require.NoError(t, err, "a provider miss must fall through to the JWKS")
}

// TestKeyProviderUnresolvableKid covers the degraded case: the provider cannot
// answer and there is no reachable JWKS. That must report CodeUnavailable or
// unknown_kid — never a bare signature failure, which would imply the verifier
// reached a verdict it could not actually reach.
func TestKeyProviderUnresolvableKid(t *testing.T) {
	t.Parallel()

	kp := &fakeKeyProvider{keys: []PublicKey{{KeyID: "local-1", Key: mintRSA(t, "local-1").priv.Public()}}}
	v, err := NewValidator(context.Background(), providerConfig(t, kp))
	require.NoError(t, err)
	t.Cleanup(v.Close)

	stranger := mintRSA(t, "stranger")
	_, err = v.Validate(context.Background(), stranger.mint(t, validConfig().Issuer))
	require.Error(t, err)
	var authnErr *Error
	require.ErrorAs(t, err, &authnErr)
	assert.Contains(t,
		[]Reason{ReasonKeysUnavailable, ReasonUnknownKID}, authnErr.Reason,
		"an unresolvable kid must report keys_unavailable or unknown_kid, got %q", authnErr.Reason)
	assert.NotEqual(t, ReasonSignature, authnErr.Reason,
		"a kid that could not be resolved must not be reported as a signature failure")
}

// TestKeyProviderError covers a provider that fails: that is an availability
// problem, not an invalid token.
func TestKeyProviderError(t *testing.T) {
	t.Parallel()

	kp := &fakeKeyProvider{err: errors.New("keystore offline")}
	v, err := NewValidator(context.Background(), providerConfig(t, kp))
	require.NoError(t, err)
	t.Cleanup(v.Close)

	rsaKey := mintRSA(t, "any")
	_, err = v.Validate(context.Background(), rsaKey.mint(t, validConfig().Issuer))
	requireAuthnError(t, err, CodeUnavailable, ReasonKeysUnavailable)
}

// TestProviderCandidateEligibility covers the filtering in providerCandidates:
// the kty/curve backstop and the declared-alg check must hold for provider keys
// exactly as they do for JWKS keys, or an EC key could reach an RSA verify path.
func TestProviderCandidateEligibility(t *testing.T) {
	t.Parallel()

	rsaPub := mintRSA(t, "r").priv.Public()
	ecPub := mintEC(t, "e").priv.Public()
	ec384Pub := mintECCurve(t, "e384", elliptic.P384()).priv.Public()

	tests := []struct {
		name      string
		keys      []PublicKey
		kid, alg  string
		wantCount int
	}{
		{
			name:      "kid match",
			keys:      []PublicKey{{KeyID: "a", Key: rsaPub}, {KeyID: "b", Key: rsaPub}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 1,
		},
		{
			name:      "kid-less key is a candidate for a kid-carrying token",
			keys:      []PublicKey{{Key: rsaPub}},
			kid:       "whatever",
			alg:       testAlgRS256,
			wantCount: 1,
		},
		{
			name:      "declared alg mismatch skipped",
			keys:      []PublicKey{{KeyID: "a", Alg: "RS512", Key: rsaPub}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 0,
		},
		{
			name:      "EC key not offered to an RSA alg",
			keys:      []PublicKey{{KeyID: "a", Key: ecPub}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 0,
		},
		{
			name:      "RSA key not offered to an EC alg",
			keys:      []PublicKey{{KeyID: "a", Key: rsaPub}},
			kid:       "a",
			alg:       testAlgES256,
			wantCount: 0,
		},
		{
			name:      "wrong curve skipped",
			keys:      []PublicKey{{KeyID: "a", Key: ec384Pub}},
			kid:       "a",
			alg:       testAlgES256,
			wantCount: 0,
		},
		{
			name:      "right curve accepted",
			keys:      []PublicKey{{KeyID: "a", Key: ec384Pub}},
			kid:       "a",
			alg:       testAlgES384,
			wantCount: 1,
		},
		{
			name:      "RSA-PSS accepted for an RSA key",
			keys:      []PublicKey{{KeyID: "a", Key: rsaPub}},
			kid:       "a",
			alg:       "PS256",
			wantCount: 1,
		},
		{
			name:      "unsupported key type skipped",
			keys:      []PublicKey{{KeyID: "a", Key: crypto.PublicKey("not-a-key")}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 0,
		},
		{
			// A malformed RSA key (nil modulus) must be rejected, not panic
			// BitLen on a nil *big.Int.
			name:      "RSA key with nil modulus skipped",
			keys:      []PublicKey{{KeyID: "a", Key: &rsa.PublicKey{}}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 0,
		},
		{
			// A malformed ECDSA key (nil curve) must be rejected, not panic on
			// the nil-interface Curve.Params() call.
			name:      "ECDSA key with nil curve skipped",
			keys:      []PublicKey{{KeyID: "a", Key: &ecdsa.PublicKey{}}},
			kid:       "a",
			alg:       testAlgES256,
			wantCount: 0,
		},
		{
			name:      "typed-nil RSA key skipped",
			keys:      []PublicKey{{KeyID: "a", Key: (*rsa.PublicKey)(nil)}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 0,
		},
		{
			name:      "typed-nil ECDSA key skipped",
			keys:      []PublicKey{{KeyID: "a", Key: (*ecdsa.PublicKey)(nil)}},
			kid:       "a",
			alg:       testAlgES256,
			wantCount: 0,
		},
		{
			name:      "untyped nil key skipped",
			keys:      []PublicKey{{KeyID: "a", Key: nil}},
			kid:       "a",
			alg:       testAlgRS256,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := providerCandidates(tt.keys, tt.kid, tt.alg)
			assert.Len(t, got, tt.wantCount)
		})
	}
}

// TestKeyProviderMalformedKeyDoesNotPanic covers the same finding end-to-end
// through the public API: a KeyProvider is caller-implemented, so a
// malformed key it returns (nil modulus/curve) must make Validate return an
// error, not panic the request path.
func TestKeyProviderMalformedKeyDoesNotPanic(t *testing.T) {
	t.Parallel()

	kp := &fakeKeyProvider{keys: []PublicKey{{KeyID: "malformed-1", Key: &rsa.PublicKey{}}}}
	v, err := NewValidator(context.Background(), providerConfig(t, kp))
	require.NoError(t, err)
	t.Cleanup(v.Close)

	rsaKey := mintRSA(t, "malformed-1")
	assert.NotPanics(t, func() {
		_, err = v.Validate(context.Background(), rsaKey.mint(t, validConfig().Issuer))
	})
	require.Error(t, err, "a malformed provider key must fail validation, not verify or panic")
}

// TestProviderCandidatesBounded asserts the maxKeyCandidates bound applies to
// provider keys too: a kid-less token against a large provider set must not turn
// into a per-request DoS amplifier.
func TestProviderCandidatesBounded(t *testing.T) {
	t.Parallel()

	rsaPub := mintRSA(t, "r").priv.Public()
	keys := make([]PublicKey, maxKeyCandidates*3)
	for i := range keys {
		keys[i] = PublicKey{Key: rsaPub}
	}
	got := providerCandidates(keys, "", testAlgRS256)
	assert.Len(t, got, maxKeyCandidates)
}

// TestDiscoveryRetriesTransientFailure covers D5: discovery must retry a
// transient failure. The server fails the first attempt and succeeds on the
// second, so construction succeeds only if a retry happened.
func TestDiscoveryRetriesTransientFailure(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	attempts := 0
	srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, oidcDiscoveryPath) {
				mu.Lock()
				attempts++
				n := attempts
				mu.Unlock()
				if n == 1 {
					// A just-starting issuer can serve a 5xx.
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
			}
			serveDiscovery(srvURL, srvURL+"/jwks.json", nil).ServeHTTP(w, r)
		}
	})

	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err, "discovery must retry a transient 503")
	t.Cleanup(v.Close)
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, attempts, "discovery must have retried exactly once")
}

// TestDiscoveryDoesNotRetryPoisonedDocument is the other half of D5: an issuer
// mismatch is a verdict on a document the endpoint actually served, so retrying
// would only re-fetch the same unacceptable answer. It must fail on the first
// attempt.
func TestDiscoveryDoesNotRetryPoisonedDocument(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	attempts := 0
	srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, oidcDiscoveryPath) {
				mu.Lock()
				attempts++
				mu.Unlock()
				// A well-known that claims a different issuer.
				w.Header().Set("Content-Type", "application/json")
				fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q}`, "https://attacker.example.com", srvURL+"/jwks.json")
				return
			}
			serveDiscovery(srvURL, srvURL+"/jwks.json", nil).ServeHTTP(w, r)
		}
	})

	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	_, err := NewValidator(context.Background(), cfg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match configured issuer")
	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, attempts, "a poisoned discovery document must not be retried")
}
