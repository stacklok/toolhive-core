// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test-only constants for claim names/values used repeatedly across cases.
const (
	claimIss = "iss"
	claimSub = "sub"
	claimAud = "aud"
	claimIat = "iat"
	claimExp = "exp"

	testSubject = "alice"
	testAPIAud  = "https://api.example.com"
	// testToken is a syntactically-JWT-shaped bearer token used for ParseBearer
	// cases (it is never cryptographically valid; ParseBearer only extracts).
	testToken = "abc.def.ghi"
)

// --- key minting -----------------------------------------------------------

type rsaPair struct {
	priv *rsa.PrivateKey
	jwk  jwk.Key
}

type ecPair struct {
	priv *ecdsa.PrivateKey
	jwk  jwk.Key
}

func mintRSA(t *testing.T, kid string) rsaPair {
	t.Helper()
	return mintRSABits(t, kid, 2048)
}

// mintRSABits mints an RSA pair with an explicit modulus size, so tests can
// exercise the RFC 7518 §3.3 strength floor.
func mintRSABits(t *testing.T, kid string, bits int) rsaPair {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	require.NoError(t, err)
	pub, err := jwk.Import(&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	return rsaPair{priv: priv, jwk: pub}
}

func mintEC(t *testing.T, kid string) ecPair {
	t.Helper()
	return mintECCurve(t, kid, elliptic.P256())
}

func mintECCurve(t *testing.T, kid string, curve elliptic.Curve) ecPair {
	t.Helper()
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	pub, err := jwk.Import(&priv.PublicKey)
	require.NoError(t, err)
	require.NoError(t, pub.Set(jwk.KeyIDKey, kid))
	return ecPair{priv: priv, jwk: pub}
}

// --- JWKS-serving test server ----------------------------------------------

// jwksServer serves a JWKS built from the given keys and counts fetches.
type jwksServer struct {
	srv *httptest.Server
	set *atomic.Pointer[jwk.Set]
	// hits counts JWKS fetches, so tests can assert exactly one refresh.
	hits *atomic.Int32
	// override, when set, replaces the default JWKS-serving behavior for the
	// next requests. This indirection (rather than swapping
	// srv.Config.Handler after the server is already serving) avoids a data
	// race: http.Server reads Config.Handler per connection, and a keep-alive
	// connection left over from construction's JWKS fetch can race a later
	// assignment to that field.
	override *atomic.Pointer[http.HandlerFunc]
}

func newJWKSServer(t *testing.T, keys ...jwk.Key) *jwksServer {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, set.AddKey(k))
	}
	js := &jwksServer{
		set:      &atomic.Pointer[jwk.Set]{},
		hits:     &atomic.Int32{},
		override: &atomic.Pointer[http.HandlerFunc]{},
	}
	js.set.Store(&set)
	js.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h := js.override.Load(); h != nil {
			(*h)(w, r)
			return
		}
		js.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(*js.set.Load())
		require.NoError(t, err)
		_, _ = w.Write(data)
	}))
	t.Cleanup(js.srv.Close)
	return js
}

// settle waits for a freshly-constructed Validator's JWKS fetches to
// quiesce. NewValidator's init registers the JWKS URL with
// jwk.WithWaitReady(false) AND performs an explicit synchronous Refresh, so
// construction can cause one or two fetches (the async Register fetch races
// the synchronous Refresh and usually loses, but not always). Call this
// after NewValidator returns and before taking a baseline js.hits snapshot,
// so a delta assertion measures only fetches caused by the test body, not a
// straggling construction fetch that lands late under load.
func (js *jwksServer) settle(t *testing.T) {
	t.Helper()
	last := int32(-1)
	require.Eventually(t, func() bool {
		cur := js.hits.Load()
		stable := cur == last
		last = cur
		return stable
	}, 2*time.Second, 100*time.Millisecond, "JWKS hit count never settled after construction")
}

// setOverride installs h as the server's next-request handler, replacing the
// default JWKS-serving behavior. Pass nil to clear it.
func (js *jwksServer) setOverride(h http.HandlerFunc) {
	if h == nil {
		js.override.Store(nil)
		return
	}
	js.override.Store(&h)
}

// configFor returns a Config pointed at the JWKS server.
func (js *jwksServer) configFor() Config {
	cfg := validConfig()
	cfg.Issuer = js.srv.URL
	cfg.JWKSURL = js.srv.URL + "/jwks.json"
	cfg.InsecureAllowHTTP = true
	// httptest servers listen on loopback, which the default client's dial guard
	// blocks. A localhost issuer is exactly the case AllowPrivateIP exists for.
	cfg.AllowPrivateIP = true
	return cfg
}

// rotate swaps the served JWKS for the given keys (simulating key rotation).
func (js *jwksServer) rotate(t *testing.T, keys ...jwk.Key) {
	t.Helper()
	set := jwk.NewSet()
	for _, k := range keys {
		require.NoError(t, set.AddKey(k))
	}
	js.set.Store(&set)
}

// --- token minting ---------------------------------------------------------

// mintOption mutates claims or signing-key choice before signing.
type mintOption func(*mintSpec)

type mintSpec struct {
	claims jwt.MapClaims
	method jwt.SigningMethod
	key    any
	kid    string
	// extraHeader is merged into the token header (e.g. crit).
	extraHeader map[string]any
}

func withClaim(k string, v any) mintOption {
	return func(s *mintSpec) { s.claims[k] = v }
}

func withoutClaim(k string) mintOption {
	return func(s *mintSpec) { delete(s.claims, k) }
}

func withMethod(m jwt.SigningMethod, key any) mintOption {
	return func(s *mintSpec) { s.method = m; s.key = key }
}

// withKid overrides the kid written into the token header. An empty string
// produces a kid-less token.
func withKid(kid string) mintOption {
	return func(s *mintSpec) { s.kid = kid }
}

func withHeader(k string, v any) mintOption {
	return func(s *mintSpec) { s.extraHeader[k] = v }
}

// sign builds and signs the token described by spec.
func sign(t *testing.T, spec mintSpec) string {
	t.Helper()
	tok := jwt.NewWithClaims(spec.method, spec.claims)
	if spec.kid != "" {
		tok.Header["kid"] = spec.kid
	}
	for k, v := range spec.extraHeader {
		tok.Header[k] = v
	}
	signed, err := tok.SignedString(spec.key)
	require.NoError(t, err)
	return signed
}

func defaultClaims(issuer string) jwt.MapClaims {
	return jwt.MapClaims{
		claimIss: issuer,
		claimSub: testSubject,
		claimAud: testAPIAud,
		claimIat: time.Now().Unix(),
		claimExp: time.Now().Add(time.Hour).Unix(),
	}
}

// mint signs a token with the RSA key. The token kid defaults to the key's
// JWK kid.
func (rp rsaPair) mint(t *testing.T, issuer string, opts ...mintOption) string {
	t.Helper()
	kid, _ := rp.jwk.KeyID()
	spec := mintSpec{
		method:      jwt.SigningMethodRS256,
		key:         rp.priv,
		kid:         kid,
		claims:      defaultClaims(issuer),
		extraHeader: map[string]any{},
	}
	for _, o := range opts {
		o(&spec)
	}
	return sign(t, spec)
}

func (ep ecPair) mint(t *testing.T, issuer string, opts ...mintOption) string {
	t.Helper()
	kid, _ := ep.jwk.KeyID()
	spec := mintSpec{
		method:      jwt.SigningMethodES256,
		key:         ep.priv,
		kid:         kid,
		claims:      defaultClaims(issuer),
		extraHeader: map[string]any{},
	}
	for _, o := range opts {
		o(&spec)
	}
	return sign(t, spec)
}

// requireAuthnError asserts err is an *Error with the given code/reason.
func requireAuthnError(t *testing.T, err error, code Code, reason Reason) {
	t.Helper()
	require.Error(t, err)
	var authnErr *Error
	require.ErrorAs(t, err, &authnErr, "error must be an *Error")
	assert.Equal(t, code, authnErr.Code, "error code")
	assert.Equal(t, reason, authnErr.Reason, "error reason")
}

// --- Validate: acceptance --------------------------------------------------

func TestValidateAcceptance(t *testing.T) {
	t.Parallel()

	t.Run("valid RS256 yields correct principal", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL, withClaim("name", "Alice"))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, js.srv.URL, p.Issuer)
		assert.Equal(t, testSubject, p.Subject)
		assert.Equal(t, "Alice", p.Name)
		assert.NotEmpty(t, p.Claims)
		assert.Equal(t, testSubject, p.Claims[claimSub])
	})

	t.Run("valid ES256 accepted", func(t *testing.T) {
		t.Parallel()
		ecKey := mintEC(t, "ec-1")
		js := newJWKSServer(t, ecKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := ecKey.mint(t, js.srv.URL)
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, testSubject, p.Subject)
	})

	t.Run("valid ES384 with P-384 key accepted", func(t *testing.T) {
		t.Parallel()
		ecKey := mintECCurve(t, "ec-p384", elliptic.P384())
		js := newJWKSServer(t, ecKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := ecKey.mint(t, js.srv.URL, withMethod(jwt.SigningMethodES384, ecKey.priv))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, testSubject, p.Subject)
	})

	t.Run("valid ES512 with P-521 key accepted", func(t *testing.T) {
		t.Parallel()
		ecKey := mintECCurve(t, "ec-p521", elliptic.P521())
		js := newJWKSServer(t, ecKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := ecKey.mint(t, js.srv.URL, withMethod(jwt.SigningMethodES512, ecKey.priv))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, testSubject, p.Subject)
	})

	t.Run("valid PS256 accepted", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL, withMethod(jwt.SigningMethodPS256, rsaKey.priv))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, testSubject, p.Subject)
	})

	t.Run("kid-less token against multi-key JWKS", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		other := mintRSA(t, "rsa-2")
		// The signing key is published with no kid so the token's kid-less
		// header matches it.
		noKid, err := jwk.Import(&rsaKey.priv.PublicKey)
		require.NoError(t, err)
		js := newJWKSServer(t, noKid, other.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL, withKid(""))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
		assert.Equal(t, testSubject, p.Subject)
	})

	t.Run("aud as bare string", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL, withClaim(claimAud, testAPIAud))
		_, err = v.Validate(context.Background(), token)
		require.NoError(t, err)
	})

	t.Run("aud as array any-match", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		cfg := js.configFor()
		cfg.Audiences = []string{"https://api-a.example.com", testAPIAud}
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimAud, []string{"https://unrelated.example.com", testAPIAud}))
		_, err = v.Validate(context.Background(), token)
		require.NoError(t, err)
	})

	t.Run("far-future exp not truncated", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		cfg := js.configFor()
		cfg.MaxTokenLifetime = 100 * 365 * 24 * time.Hour // 100y
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		farFuture := time.Now().Add(50 * 365 * 24 * time.Hour).Unix()
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimExp, farFuture))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "a far-future exp must not be truncated by the decoder")
		assert.Equal(t, testSubject, p.Subject)
	})

	t.Run("two keys same kid: correct one is tried", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "shared-kid")
		other := mintRSA(t, "shared-kid") // same kid, different key
		js := newJWKSServer(t, other.jwk, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL)
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "golang-jwt must iterate all same-kid candidates")
		assert.Equal(t, testSubject, p.Subject)
	})
}

// --- Validate: rejection ---------------------------------------------------

func TestValidateRejection(t *testing.T) {
	t.Parallel()

	// newValidatorWithKey is the common setup: one RSA key, one validator.
	setup := func(t *testing.T) (rsaPair, *jwksServer, *Validator) {
		t.Helper()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)
		// The "HS256 rejected" subtest below snapshots js.hits as a baseline;
		// settle construction's fetches first so that baseline is stable.
		js.settle(t)
		return rsaKey, js, v
	}

	t.Run("alg none rejected", func(t *testing.T) {
		t.Parallel()
		_, js, v := setup(t)
		// Hand-craft an alg:none token; golang-jwt refuses to sign with
		// SigningMethodNone unless the unsafe magic key is used.
		claims := jwt.MapClaims{
			claimIss: js.srv.URL, claimSub: testSubject, claimAud: testAPIAud,
			claimIat: time.Now().Unix(), claimExp: time.Now().Add(time.Hour).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
		token, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
		require.NoError(t, err)

		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnsupportedAlg)
	})

	t.Run("HS256 rejected (algorithm confusion)", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		claims := jwt.MapClaims{
			claimIss: js.srv.URL, claimSub: testSubject, claimAud: testAPIAud,
			claimIat: time.Now().Unix(), claimExp: time.Now().Add(time.Hour).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		// The real confusion attack: the attacker signs with the server's
		// PUBLIC key bytes as the HMAC secret, expecting the verifier to use
		// that same public key as the HMAC secret. Rejection must happen at
		// the alg gate, before any key material is consulted.
		pubDER, err := x509.MarshalPKIXPublicKey(&rsaKey.priv.PublicKey)
		require.NoError(t, err)
		token, err := tok.SignedString(pubDER)
		require.NoError(t, err)

		hitsBefore := js.hits.Load()
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnsupportedAlg)
		assert.Equal(t, hitsBefore, js.hits.Load(),
			"an off-allowlist alg must be rejected before any JWKS fetch")
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, _, v := setup(t)
		token := rsaKey.mint(t, "https://evil.example.com")
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonIssuer)
	})

	t.Run("whitespace-padded issuer rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		// "https://idp \n" must NOT be trimmed to match; iss is byte-exact.
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimIss, js.srv.URL+" \n"))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonIssuer)
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimAud, "https://other.example.com"))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonAudience)
	})

	t.Run("expired token rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimExp, time.Now().Add(-2*time.Hour).Unix()),
			withClaim(claimIat, time.Now().Add(-3*time.Hour).Unix()))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonExpired)
	})

	t.Run("nbf in future rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim("nbf", time.Now().Add(2*time.Hour).Unix()))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonNotYetValid)
	})

	t.Run("bad signature rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		// Sign with a DIFFERENT key than the one the server publishes, but the
		// same kid, so the lookup finds the key and the signature check fails.
		other := mintRSA(t, "rsa-1")
		token := rsaKey.mint(t, js.srv.URL, withMethod(jwt.SigningMethodRS256, other.priv))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonSignature)
	})

	t.Run("crit header rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		// RFC 7515 §4.1.11: we understand NO crit extensions, so any crit
		// member must be rejected.
		token := rsaKey.mint(t, js.srv.URL, withHeader("crit", []string{claimExp}))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonCriticalHeader)
	})

	t.Run("exp-iat exceeds MaxTokenLifetime rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		cfg := js.configFor()
		cfg.MaxTokenLifetime = time.Hour
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimIat, time.Now().Unix()),
			withClaim(claimExp, time.Now().Add(2*time.Hour).Unix()))
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonLifetime)
	})

	t.Run("exp-iat exactly MaxTokenLifetime accepted", func(t *testing.T) {
		t.Parallel()
		// Boundary: checkLifetime rejects only spans STRICTLY greater than
		// MaxTokenLifetime, so a span exactly equal to it must be accepted
		// (an inverted comparison would reject this token). Pin the iat to
		// 'now' once so exp-iat is exactly the bound at any validation time.
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		cfg := js.configFor()
		cfg.MaxTokenLifetime = 2 * time.Hour
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		now := time.Now()
		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimIat, now.Unix()),
			withClaim(claimExp, now.Add(2*time.Hour).Unix()))
		_, err = v.Validate(context.Background(), token)
		require.NoError(t, err, "a lifetime exactly equal to MaxTokenLifetime must be accepted")
	})

	t.Run("missing iat skips MaxTokenLifetime check", func(t *testing.T) {
		t.Parallel()
		// The exp-iat span here (7 days) WOULD exceed MaxTokenLifetime if iat
		// were present, but a token without iat must skip the lifetime check
		// entirely (many IdPs omit it; validate.go checkLifetime).
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		cfg := js.configFor()
		cfg.MaxTokenLifetime = time.Hour
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		token := rsaKey.mint(t, js.srv.URL,
			withoutClaim(claimIat),
			withClaim(claimExp, time.Now().Add(7*24*time.Hour).Unix()))
		_, err = v.Validate(context.Background(), token)
		require.NoError(t, err, "a token without iat must skip the lifetime check")
	})

	t.Run("missing sub rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL, withoutClaim(claimSub))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonSubject)
	})

	t.Run("empty sub rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimSub, ""))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonSubject)
	})

	t.Run("EC key not selected for RS256 token", func(t *testing.T) {
		t.Parallel()
		// The token carries kid "rsa-1" but the server publishes ONLY an EC
		// key under that kid. The kty backstop must filter the EC key out of
		// the candidate set (an EC key handed to an RS256 verify would be a
		// confused verification); the refresh then finds nothing, so the
		// result is unknown_kid.
		ecKey := mintEC(t, "rsa-1")
		js := newJWKSServer(t, ecKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		rsaKey := mintRSA(t, "rsa-1")
		token := rsaKey.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	})

	t.Run("P-384 key not selected for ES256 token (curve confusion)", func(t *testing.T) {
		t.Parallel()
		// The ES256 token's kid resolves to a P-384 key. The curve backstop
		// (curveMatchesAlg) must filter it BEFORE verify: a "curveMatchesAlg
		// returns true" mutant would hand the P-384 key to the ES256 verify
		// path instead of rejecting here.
		wrongCurve := mintECCurve(t, "ec-1", elliptic.P384())
		js := newJWKSServer(t, wrongCurve.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		signing := mintEC(t, "ec-1")
		token := signing.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	})

	t.Run("RSA key not selected for ES256 token", func(t *testing.T) {
		t.Parallel()
		// The ES256 token's kid resolves to an RSA key; the kty backstop must
		// filter it out of the candidate set before any verify attempt.
		rsaKey := mintRSA(t, "ec-1")
		js := newJWKSServer(t, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		ecKey := mintEC(t, "ec-1")
		token := ecKey.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	})

	t.Run("signed token without alg header is unsupported_alg", func(t *testing.T) {
		t.Parallel()
		_, js, v := setup(t)
		// Sign a real RS256 token, then strip alg from the (now unsigned)
		// header. Per errors.go a missing alg is ReasonUnsupportedAlg, not
		// ReasonMalformed; unverifiedAlg must return "" (not an error) here.
		rsaKey := mintRSA(t, "rsa-1")
		signed := rsaKey.mint(t, js.srv.URL)
		parts := strings.Split(signed, ".")
		require.Len(t, parts, 3)
		hdr, err := jwt.NewParser().DecodeSegment(parts[0])
		require.NoError(t, err)
		var header map[string]any
		require.NoError(t, json.Unmarshal(hdr, &header))
		delete(header, "alg")
		rawHdr, err := json.Marshal(header)
		require.NoError(t, err)
		token := base64.RawURLEncoding.EncodeToString(rawHdr) + "." + parts[1] + "." + parts[2]

		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnsupportedAlg)
	})

	t.Run("kid-less token with no alg-eligible key is signature", func(t *testing.T) {
		t.Parallel()
		// The JWKS holds only a P-256 EC key, ineligible for the RS256 token,
		// so the candidate set is empty. With NO kid in the header the H1
		// refresh path is skipped (kid == ""), the keyfunc returns an empty
		// VerificationKeySet, golang-jwt reports ErrTokenUnverifiable, and
		// mapParseError (kidSeen=false) maps it to ReasonSignature.
		ecKey := mintEC(t, "ec-1")
		js := newJWKSServer(t, ecKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		rsaKey := mintRSA(t, "rsa-1")
		token := rsaKey.mint(t, js.srv.URL, withKid(""))
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonSignature)
	})

	t.Run("kid matching only an alg-ineligible key is unknown_kid", func(t *testing.T) {
		t.Parallel()
		// Same empty candidate set as above, but the token CARRIES a kid that
		// matches the ineligible key, so verificationKeys DOES fire the H1
		// recovery (len(keys)==0 && kid!=""): it fetches once, negatively
		// caches the kid, and returns its own ReasonUnknownKID *Error (the
		// ErrTokenUnverifiable kidSeen=true branch in mapParseError is never
		// reached on this path). Any later attempt with the same kid is
		// rejected straight from the negative cache — no further fetch.
		ecKey := mintEC(t, "ec-1")
		js := newJWKSServer(t, ecKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		rsaKey := mintRSA(t, "ec-1")
		token := rsaKey.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)

		afterFirst := js.hits.Load()
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
		assert.Equal(t, afterFirst, js.hits.Load(),
			"a negatively-cached kid must not trigger another refresh fetch")
	})

	t.Run("use enc key not selected but absent use is", func(t *testing.T) {
		t.Parallel()
		// The signing key has use:"enc" (must be skipped); the only eligible
		// key is one with NO use field.
		encKey := mintRSA(t, "enc-1")
		require.NoError(t, encKey.jwk.Set(jwk.KeyUsageKey, jwk.ForEncryption))
		sigKey := mintRSA(t, "sig-1") // no use set
		js := newJWKSServer(t, encKey.jwk, sigKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		// Sign with sigKey; token has kid "sig-1", only sigKey matches.
		token := sigKey.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token)
		require.NoError(t, err, "absent use must pass the filter")

		// Sign with encKey; its use:"enc" excludes it, leaving no eligible
		// candidate for kid "enc-1". The refresh finds nothing → unknown_kid.
		token2 := encKey.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token2)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	})

	t.Run("unknown kid after refresh is unknown_kid", func(t *testing.T) {
		t.Parallel()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)

		stranger := mintRSA(t, "stranger")
		token := stranger.mint(t, js.srv.URL)
		_, err = v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	})
}

// TestValidateRequiredClaimMissing covers FIX 1: a signed JWT missing iss,
// aud, or exp (or carrying a wrong-type aud) raises
// jwt.ErrTokenRequiredClaimMissing, which must map to a per-claim reason —
// never ReasonMalformed. The CodeInvalidToken+ReasonMalformed pair is the
// load-bearing introspection-fallback trigger (errors.go), so a signed token
// that only fails a claim policy must NOT feed introspection.
func TestValidateRequiredClaimMissing(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	tests := []struct {
		name       string
		mutate     func(*mintSpec)
		wantReason Reason
	}{
		{
			name:       "missing iss maps to ReasonIssuer",
			mutate:     func(s *mintSpec) { delete(s.claims, claimIss) },
			wantReason: ReasonIssuer,
		},
		{
			name:       "missing aud maps to ReasonAudience",
			mutate:     func(s *mintSpec) { delete(s.claims, claimAud) },
			wantReason: ReasonAudience,
		},
		{
			name:       "missing exp maps to ReasonExpirationMissing",
			mutate:     func(s *mintSpec) { delete(s.claims, claimExp) },
			wantReason: ReasonExpirationMissing,
		},
		{
			// golang-jwt surfaces a wrong-type aud as "aud claim is required"
			// (ErrTokenRequiredClaimMissing), so it maps to ReasonAudience,
			// not ReasonMalformed.
			name:       "wrong-type aud (number) maps to ReasonAudience",
			mutate:     func(s *mintSpec) { s.claims[claimAud] = 12345 },
			wantReason: ReasonAudience,
		},
		{
			name:       "wrong-type aud (object) maps to ReasonAudience",
			mutate:     func(s *mintSpec) { s.claims[claimAud] = map[string]any{"x": 1} },
			wantReason: ReasonAudience,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token := rsaKey.mint(t, js.srv.URL, tt.mutate)
			_, err := v.Validate(context.Background(), token)
			requireAuthnError(t, err, CodeInvalidToken, tt.wantReason)
			assert.NotEqual(t, ReasonMalformed, err.(*Error).Reason,
				"a missing required claim must NOT map to ReasonMalformed (introspection trigger)")
		})
	}
}

// TestValidateWrongTypedClaim covers FIX 1: a signed JWT whose iss/exp/iat
// claim carries the wrong JSON type raises jwt.ErrInvalidType, which
// mapParseError's default arm must map to ReasonInvalidClaims — never
// ReasonMalformed, which is the load-bearing introspection-fallback trigger
// (errors.go). A wrong-typed claim on an otherwise-signed JWT is a
// claim-policy failure, not a possibly-opaque token worth introspecting.
func TestValidateWrongTypedClaim(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	tests := []struct {
		name   string
		mutate func(*mintSpec)
	}{
		{name: "iss as number", mutate: func(s *mintSpec) { s.claims[claimIss] = 12345 }},
		{name: "iss as array", mutate: func(s *mintSpec) { s.claims[claimIss] = []string{"a", "b"} }},
		{name: "iss as object", mutate: func(s *mintSpec) { s.claims[claimIss] = map[string]any{"x": 1} }},
		{name: "exp as string", mutate: func(s *mintSpec) { s.claims[claimExp] = "not-a-number" }},
		{name: "iat as string", mutate: func(s *mintSpec) { s.claims[claimIat] = "not-a-number" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			token := rsaKey.mint(t, js.srv.URL, tt.mutate)
			_, err := v.Validate(context.Background(), token)
			requireAuthnError(t, err, CodeInvalidToken, ReasonInvalidClaims)
			assert.NotEqual(t, ReasonMalformed, err.(*Error).Reason,
				"a wrong-typed claim on a signed JWT must NOT map to ReasonMalformed (introspection trigger)")
		})
	}
}

// --- H1 unknown-kid recovery ----------------------------------------------

// TestUnknownKidRecovery covers H1: an unknown kid triggers exactly one JWKS
// refresh and then succeeds once the key is present post-rotation; a second
// unknown kid within the negative-cache TTL does NOT re-fetch.
func TestUnknownKidRecovery(t *testing.T) {
	t.Parallel()

	oldKey := mintRSA(t, "old")
	js := newJWKSServer(t, oldKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Baseline: how many fetches construction caused. Settle first: Register
	// with WithWaitReady(false) starts its own async fetch in addition to
	// init's synchronous Refresh, so construction may perform one or two
	// fetches. Without settling, a straggling async fetch can land during the
	// test body and inflate the delta below.
	js.settle(t)
	baseline := js.hits.Load()
	require.Positive(t, baseline, "construction must fetch the JWKS")

	// Rotate: the new key is published under a NEW kid.
	newKey := mintRSA(t, "new")
	js.rotate(t, newKey.jwk)

	// A token signed by the new key has an unknown kid in the CACHED set. The
	// keyfunc must trigger exactly one refresh, re-resolve, and succeed.
	token := newKey.mint(t, js.srv.URL)
	p, err := v.Validate(context.Background(), token)
	require.NoError(t, err, "unknown kid must trigger exactly one refresh, then succeed post-rotation")
	assert.Equal(t, testSubject, p.Subject)

	afterRecovery := js.hits.Load()
	// baseline was taken after settle(t), so it already reflects both of
	// construction's possible fetches; recovery adds exactly one more:
	// refreshOnce is synchronous, so a single Validate performs exactly one
	// refresh fetch.
	assert.Equal(t, int32(1), afterRecovery-baseline,
		"exactly one recovery refresh fetch beyond the construction baseline")

	// A second, distinct unknown kid within the negative-cache TTL must NOT
	// re-fetch: the first unknown-kid recovery above refreshed the cache, and
	// this kid is now recorded negatively.
	stranger := mintRSA(t, "stranger")
	strangerToken := stranger.mint(t, js.srv.URL)
	_, err = v.Validate(context.Background(), strangerToken)
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)

	afterStranger := js.hits.Load()
	// The stranger kid triggers one refresh (it's a NEW kid, not yet
	// negatively cached), then is recorded negatively. A repeat of the SAME
	// stranger kid must NOT re-fetch.
	_, err = v.Validate(context.Background(), strangerToken)
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	assert.Equal(t, afterStranger, js.hits.Load(),
		"a repeat of an already-failed kid within the TTL must not re-fetch")
}

// TestConcurrentUnknownKidSingleRefresh proves the mutex+floor serializes
// concurrent unknown-kid recoveries into exactly one refresh fetch.
func TestConcurrentUnknownKidSingleRefresh(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Settle construction's fetches before the baseline; see settle's doc
	// comment for why construction can cause more than one fetch.
	js.settle(t)
	baseline := js.hits.Load()
	stranger := mintRSA(t, "stranger")
	token := stranger.mint(t, js.srv.URL)

	const callers = 16
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			_, err := v.Validate(context.Background(), token)
			// All callers get unknown_kid (the key never appears).
			assert.Error(t, err)
		}()
	}
	wg.Wait()

	// The mutex+floor collapses the concurrent refresh attempts to exactly one
	// fetch. httprc's Controller.Refresh is synchronous, so lastRefresh is
	// stamped only after the fetch completes; any caller that then acquires
	// refreshMu sees a fresh timestamp and skips the network. No race window.
	assert.Equal(t, int32(1), js.hits.Load()-baseline,
		"concurrent unknown-kid recoveries must be collapsed to exactly one refresh fetch")
}

// TestUnknownKidNotNegativeCachedWithinFloor covers FIX 4: when an unknown kid
// is presented within refreshFloor (so refreshOnce skips the fetch and reports
// refreshed=false), the kid must NOT be negative-cached. A rotation that
// published a new kid just after the last refresh would otherwise be
// blackholed for negativeCacheTTL even though no fetch actually inspected the
// new JWKS. After the floor elapses, a subsequent Validate must refresh and
// succeed.
func TestUnknownKidNotNegativeCachedWithinFloor(t *testing.T) {
	t.Parallel()
	// This test sleeps past refreshFloor; it is safe in parallel because it
	// uses its own validator/JWKS server instance and the timing is relative
	// to that validator's own lastRefresh.
	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// First unknown-kid recovery: stamp lastRefresh with a real fetch, so the
	// next recovery is inside refreshFloor.
	stranger := mintRSA(t, "stranger")
	strangerToken := stranger.mint(t, js.srv.URL)
	_, err = v.Validate(context.Background(), strangerToken)
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)

	// Rotate the JWKS to publish a brand-new key under a new kid.
	newKey := mintRSA(t, "rotated")
	js.rotate(t, newKey.jwk)
	newToken := newKey.mint(t, js.srv.URL)

	// Pin lastRefresh to NOW so the next recovery is unambiguously inside
	// refreshFloor. Setting it directly rather than relying on the wall clock is
	// deliberate: under load the first recovery above can be more than
	// refreshFloor in the past by the time we get here, which would let the
	// fetch through and make this test assert the opposite of its intent.
	setLastRefresh(v, time.Now())

	// Within the floor: refreshOnce skips the fetch (refreshed=false), the
	// new kid is not in the stale cached set, so Validate rejects with
	// unknown_kid — but must NOT negative-cache the kid.
	_, err = v.Validate(context.Background(), newToken)
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
	assert.False(t, v.knownBadKID("rotated"),
		"a kid must not be negative-cached when no fetch actually happened")

	// Past the floor: refreshOnce now fetches, sees the rotated key, and
	// Validate succeeds. This is the regression the refreshed-flag gating
	// prevents — under the old behavior the kid was blackholed for 30s and this
	// failed. Backdating lastRefresh is equivalent to sleeping past the floor,
	// without the sleep or the timing assumption.
	setLastRefresh(v, time.Now().Add(-2*refreshFloor))
	p, err := v.Validate(context.Background(), newToken)
	require.NoError(t, err, "after the floor, a rotated kid must refresh and validate")
	assert.Equal(t, testSubject, p.Subject)
}

// setLastRefresh overwrites the validator's unknown-kid refresh floor timestamp
// under its mutex, so a test can place itself inside or outside refreshFloor
// deterministically instead of racing the wall clock.
func setLastRefresh(v *Validator, at time.Time) {
	v.refreshMu.Lock()
	defer v.refreshMu.Unlock()
	v.lastRefresh = at
}

// --- ParseBearer -----------------------------------------------------------

func TestParseBearer(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		// wantToken is the expected token on success.
		wantToken string
		// wantReason, when non-empty, asserts the failure reason.
		wantReason Reason
	}{
		{name: "empty value", in: "", wantReason: ReasonMissingHeader},
		{name: "bearer exact", in: "Bearer abc.def.ghi", wantToken: testToken},
		{name: "bearer lowercase", in: "bearer abc.def.ghi", wantToken: testToken},
		{name: "bearer uppercase", in: "BEARER abc.def.ghi", wantToken: testToken},
		{name: "bearer mixed case", in: "BeArEr abc.def.ghi", wantToken: testToken},
		{name: "no scheme", in: testToken, wantReason: ReasonMalformed},
		{name: "scheme only", in: "Bearer", wantReason: ReasonMalformed},
		{name: "scheme trailing space no token", in: "Bearer ", wantReason: ReasonMalformed},
		{name: "empty token part", in: "Bearer  ", wantReason: ReasonMalformed},
		{name: "extra whitespace segment", in: "Bearer abc def", wantReason: ReasonMalformed},
		{name: "tab separator", in: "Bearer\tabc.def.ghi", wantReason: ReasonMalformed},
		{name: "leading whitespace", in: " Bearer abc.def.ghi", wantReason: ReasonMalformed},
		{name: "wrong scheme", in: "Basic abc.def.ghi", wantReason: ReasonMalformed},
		{name: "digest scheme", in: "Digest abc.def.ghi", wantReason: ReasonMalformed},
		{
			name:       "token at max length",
			in:         "Bearer " + strings.Repeat("a", maxTokenLength),
			wantToken:  strings.Repeat("a", maxTokenLength),
			wantReason: "",
		},
		{
			name:       "token over max length",
			in:         "Bearer " + strings.Repeat("a", maxTokenLength+1),
			wantReason: ReasonMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseBearer(tt.in)
			if tt.wantReason != "" {
				requireAuthnError(t, err, CodeInvalidRequest, tt.wantReason)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantToken, got)
		})
	}
}

// --- malformed / non-JWT (load-bearing §8) ---------------------------------

// TestMalformedTokens pin the CodeInvalidToken+ReasonMalformed contract that
// ToolHive's introspection fallback depends on: a non-JWT, a 2-segment and a
// 4-segment token must all be malformed, never a signature or other error.
func TestMalformedTokens(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	tests := []struct {
		name  string
		token string
	}{
		{name: "empty", token: ""},
		{name: "opaque string", token: "not-a-jwt"},
		{name: "2 segments", token: "abc.def"},
		{name: "4 segments", token: "abc.def.ghi.jkl"},
		{name: "bad base64 header", token: "!!!.def.ghi"},
		{name: "bad base64 payload", token: "abc.!!!.ghi"},
		{name: "non-JSON header", token: "Z29vZA.Z29vZA.Z29vZA"}, // "good"."good"."good"
		{name: "token over max length", token: strings.Repeat("a", maxTokenLength+1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := v.Validate(context.Background(), tt.token)
			// PIN: CodeInvalidToken + ReasonMalformed (§8).
			requireAuthnError(t, err, CodeInvalidToken, ReasonMalformed)
		})
	}
}

// --- leeway ----------------------------------------------------------------

func TestLeeway(t *testing.T) {
	t.Parallel()

	// A fixed small leeway makes just-inside/just-outside assertions precise.
	const leeway = 30 * time.Second

	setup := func(t *testing.T) (rsaPair, *jwksServer, *Validator) {
		t.Helper()
		rsaKey := mintRSA(t, "rsa-1")
		js := newJWKSServer(t, rsaKey.jwk)
		cfg := js.configFor()
		cfg.Leeway = leeway
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)
		return rsaKey, js, v
	}

	t.Run("exp just inside leeway accepted", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimExp, time.Now().Add(-(leeway/2)).Unix()),
			withClaim(claimIat, time.Now().Add(-time.Hour).Unix()))
		_, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "exp within leeway must be accepted")
	})

	t.Run("exp just outside leeway rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimExp, time.Now().Add(-(leeway*2)).Unix()),
			withClaim(claimIat, time.Now().Add(-3*time.Hour).Unix()))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonExpired)
	})

	t.Run("nbf just inside leeway accepted", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim("nbf", time.Now().Add(leeway/2).Unix()))
		_, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "nbf within leeway must be accepted")
	})

	t.Run("nbf just outside leeway rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim("nbf", time.Now().Add(leeway*2).Unix()))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonNotYetValid)
	})

	t.Run("iat just inside leeway accepted", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimIat, time.Now().Add(leeway/2).Unix()))
		_, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "iat within leeway must be accepted")
	})

	t.Run("iat just outside leeway rejected", func(t *testing.T) {
		t.Parallel()
		rsaKey, js, v := setup(t)
		token := rsaKey.mint(t, js.srv.URL,
			withClaim(claimIat, time.Now().Add(leeway*2).Unix()))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonIssuedInFuture)
	})
}

// --- Principal hygiene ------------------------------------------------------

// TestPrincipalNeverContainsRawToken proves the serialized token never
// appears in the Principal, both on the struct and on its JSON marshaling.
func TestPrincipalNeverContainsRawToken(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	token := rsaKey.mint(t, js.srv.URL)
	p, err := v.Validate(context.Background(), token)
	require.NoError(t, err)

	// The struct fields never carry the token.
	assert.NotContains(t, p.Issuer, token)
	assert.NotContains(t, p.Subject, token)
	assert.NotContains(t, p.Name, token)

	// Nor does the JSON marshaling of the whole Principal.
	data, err := json.Marshal(p)
	require.NoError(t, err)
	assert.NotContains(t, string(data), token,
		"the serialized token must never appear in the Principal's JSON form")
}

// TestErrorDetailIsLogOnly confirms the log-vs-wire split: for a failure
// carrying detail, Error() differs from the bare Reason (detail is present in
// the log string but not in the client-safe Reason).
func TestErrorDetailIsLogOnly(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	stranger := mintRSA(t, "stranger")
	_, err = v.Validate(context.Background(), stranger.mint(t, js.srv.URL))
	require.Error(t, err)
	var authnErr *Error
	require.ErrorAs(t, err, &authnErr)
	assert.NotEqual(t, string(authnErr.Reason), authnErr.Error(),
		"Error() must carry detail beyond the bare Reason")
	assert.Contains(t, authnErr.Error(), string(authnErr.Reason),
		"Error() should still embed the Reason")
}

// --- concurrency -------------------------------------------------------------

// TestValidateConcurrent exercises Validate under -race: many goroutines
// validating a mix of valid and invalid tokens concurrently must not race or
// panic.
func TestValidateConcurrent(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	ecKey := mintEC(t, "ec-1")
	js := newJWKSServer(t, rsaKey.jwk, ecKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	goodRSA := rsaKey.mint(t, js.srv.URL)
	goodEC := ecKey.mint(t, js.srv.URL)
	stranger := mintRSA(t, "stranger")
	badKID := stranger.mint(t, js.srv.URL)

	tokens := []string{goodRSA, goodEC, badKID, "not-a-jwt"}

	// Each worker writes only its own results slot; outcomes are asserted in
	// the main goroutine below so every concurrent Validate pins its expected
	// result, not just the absence of a data race.
	type outcome struct {
		p   Principal
		err error
	}
	const workers = 32
	results := make([]outcome, workers)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := range workers {
		go func() {
			defer wg.Done()
			p, err := v.Validate(context.Background(), tokens[i%len(tokens)])
			results[i] = outcome{p: p, err: err}
		}()
	}
	wg.Wait()

	for i, r := range results {
		switch i % len(tokens) {
		case 0, 1: // goodRSA, goodEC
			require.NoError(t, r.err)
			assert.Equal(t, testSubject, r.p.Subject)
		case 2: // badKID: unknown kid, recovered by one refresh then rejected
			requireAuthnError(t, r.err, CodeInvalidToken, ReasonUnknownKID)
		case 3: // "not-a-jwt"
			requireAuthnError(t, r.err, CodeInvalidToken, ReasonMalformed)
		}
	}
}

// --- key eligibility filters -------------------------------------------------

// TestKeyOpsFilter covers the RFC 7517 §4.3 key_ops filter: a key whose
// key_ops lacks "verify" is not selected; one with "verify" is.
func TestKeyOpsFilter(t *testing.T) {
	t.Parallel()

	// Key with key_ops=["sign"] only: not eligible for verification.
	signOnly := mintRSA(t, "sign-only")
	require.NoError(t, signOnly.jwk.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign}))
	// Key with key_ops=["verify"]: eligible.
	verifyKey := mintRSA(t, "verify")
	require.NoError(t, verifyKey.jwk.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpVerify}))

	js := newJWKSServer(t, signOnly.jwk, verifyKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// The verify key works.
	token := verifyKey.mint(t, js.srv.URL)
	_, err = v.Validate(context.Background(), token)
	require.NoError(t, err, "key_ops containing verify must be eligible")

	// The sign-only key does not: no eligible candidate for kid "sign-only".
	token2 := signOnly.mint(t, js.srv.URL)
	_, err = v.Validate(context.Background(), token2)
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
}

// TestKeyAlgFilter covers RFC 8725 §3.9: a JWK that declares alg must match
// the token's alg; one that omits alg falls through to the kty backstop.
func TestKeyAlgFilter(t *testing.T) {
	t.Parallel()

	// Key declares alg "RS384"; a token signed RS256 must not select it.
	declared := mintRSA(t, "declared")
	require.NoError(t, declared.jwk.Set(jwk.AlgorithmKey, "RS384"))
	js := newJWKSServer(t, declared.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// RS256 token against a key declaring RS384 → alg mismatch → filtered →
	// unknown_kid after refresh.
	token := declared.mint(t, js.srv.URL, withMethod(jwt.SigningMethodRS256, declared.priv))
	_, err = v.Validate(context.Background(), token)
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
}

// TestKeyExportEdgeCases unit-tests the internal key helpers directly. The
// alg gate in Validate admits only RS/PS/ES algs, so the off-allowlist default
// branches below are unreachable through Validate; this test keeps them honest
// as defense-in-depth and covers cross-type export failures.
func TestKeyExportEdgeCases(t *testing.T) {
	t.Parallel()

	ecKey := mintEC(t, "ec-1")
	rsaKey := mintRSA(t, "rsa-1")

	// Non-RS/PS/ES algs hit the default (defensive) branches.
	assert.False(t, keyTypeMatchesAlg(ecKey.jwk, "HS256"))
	assert.False(t, curveMatchesAlg("P-256", "HS256"))
	_, err := exportKey(rsaKey.jwk, "HS256")
	assert.Error(t, err, "off-allowlist alg must fail export")

	// Cross-type exports must fail: an RSA JWK is not an EC key and vice
	// versa (this is why the kty/curve backstop filters before export).
	_, err = exportKey(rsaKey.jwk, "ES256")
	assert.Error(t, err, "an RSA JWK must not export as an EC key")
	_, err = exportKey(ecKey.jwk, "RS256")
	assert.Error(t, err, "an EC JWK must not export as an RSA key")
}

// TestNegativeCacheEviction proves the negative cache is bounded in entry
// count: filling it past its bound evicts the oldest entry rather than
// growing unboundedly.
func TestNegativeCacheEviction(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Record negativeCacheMaxEntries + a few distinct kids directly (bypassing
	// Validate) to test the bound without 130 network refreshes.
	for i := range negativeCacheMaxEntries + 4 {
		v.recordBadKID(fmt.Sprintf("kid-%d", i))
	}
	v.negativeMu.Lock()
	got := len(v.negativeKids)
	v.negativeMu.Unlock()
	assert.LessOrEqual(t, got, negativeCacheMaxEntries,
		"negative cache must be bounded in entry count")
}

// TestErrorUnwrapTraversesDetail pins the wrapping contract that
// mapParseError's errors.As-first ordering relies on: errors.Is must traverse
// through the *Error to the wrapped golang-jwt sentinel detail, and errors.As
// must extract the *Error itself.
func TestErrorUnwrapTraversesDetail(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	token := rsaKey.mint(t, js.srv.URL,
		withClaim(claimExp, time.Now().Add(-2*time.Hour).Unix()),
		withClaim(claimIat, time.Now().Add(-3*time.Hour).Unix()))
	_, err = v.Validate(context.Background(), token)
	require.Error(t, err)

	// Unwrap: errors.Is reaches the wrapped golang-jwt sentinel.
	assert.ErrorIs(t, err, jwt.ErrTokenExpired,
		"errors.Is must traverse through *Error to the wrapped detail")

	// errors.As extracts the *Error itself.
	var authnErr *Error
	require.ErrorAs(t, err, &authnErr)
	assert.Equal(t, ReasonExpired, authnErr.Reason)
}

// TestKeysUnavailable distinguishes "key material source unreachable" from
// "kid not found": a validator whose JWKS becomes unreachable and has no
// cached key for the kid reports CodeUnavailable/ReasonKeysUnavailable.
func TestKeysUnavailable(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Close the server so the JWKS endpoint is unreachable, then force a
	// refresh that fails: a token with an unknown kid now hits the
	// keys-unavailable path rather than unknown_kid.
	js.srv.Close()
	stranger := mintRSA(t, "stranger")
	_, err = v.Validate(context.Background(), stranger.mint(t, js.srv.URL))
	requireAuthnError(t, err, CodeUnavailable, ReasonKeysUnavailable)
}

// TestRefreshOnceUsesLifetimeContext covers FIX 3: the unknown-kid recovery
// refresh must run on a context derived from the validator's lifetime context
// (v.ctx), NOT the per-request context. A client that disconnects mid-refresh
// (canceling the request ctx) must not cancel the shared JWKS fetch. We
// trigger a recovery, cancel the request ctx once the JWKS GET is in flight,
// and assert the fetch still completes (the JWKS server records the hit) —
// which would fail if refreshOnce bound the fetch to the request ctx.
func TestRefreshOnceUsesLifetimeContext(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Force the next recovery to actually fetch by backdating the refresh floor
	// past refreshFloor. Backdating rather than sleeping keeps this deterministic
	// under load and shaves a second off the run.
	setLastRefresh(v, time.Now().Add(-2*refreshFloor))
	js.settle(t)
	baseline := js.hits.Load()

	// started fires when the JWKS GET arrives; the handler then blocks until
	// the test signals it may answer, giving us a window to cancel reqCtx
	// while the fetch is in flight.
	started := make(chan struct{})
	release := make(chan struct{})
	js.setOverride(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		select {
		case <-release:
		case <-time.After(2 * time.Second):
		}
		js.hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		data, err := json.Marshal(*js.set.Load())
		if err != nil {
			t.Errorf("marshal jwks: %v", err)
			return
		}
		_, _ = w.Write(data)
	})
	t.Cleanup(func() { js.setOverride(nil) })

	// A new unknown kid triggers the recovery refresh inside the keyfunc.
	stranger := mintRSA(t, "stranger")
	token := stranger.mint(t, js.srv.URL)

	reqCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	validateDone := make(chan struct{})
	go func() {
		defer close(validateDone)
		_, _ = v.Validate(reqCtx, token)
	}()

	// Wait for the JWKS GET to arrive, then cancel the request ctx while the
	// fetch is still in flight.
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("the recovery refresh did not hit the JWKS server in time")
	}
	cancel()

	// Release the handler so the fetch can answer. If refreshOnce used reqCtx,
	// the canceled context would abort the in-flight GET before this point and
	// the handler would never reach the hit counter (the transport returns a
	// context-canceled error and the request completes without the handler
	// finishing). Using v.ctx the GET completes and the hit is recorded.
	close(release)

	<-validateDone

	assert.Equal(t, int32(1), js.hits.Load()-baseline,
		"the recovery refresh must complete on v.ctx even when the request ctx is canceled mid-fetch")
}

// --- ToolHive compatibility relaxations (Phase B) --------------------------

// TestIssuerlessValidation covers B1: a JWKSURL-only config (no Issuer) must
// construct and must validate tokens WITHOUT verifying iss, matching ToolHive,
// which skips the issuer check when its Issuer is unset (pkg/auth/token.go
// `if v.issuer != ""`). Principal.Issuer must still report the token's actual
// iss claim, since Config no longer carries it.
func TestIssuerlessValidation(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.Issuer = "" // JWKSURL-only: the JWKS endpoint is the trust boundary
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err, "a JWKSURL-only config must construct")
	t.Cleanup(v.Close)

	t.Run("any issuer accepted", func(t *testing.T) {
		t.Parallel()
		token := rsaKey.mint(t, "https://some-other-issuer.example.com")
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "iss must not be verified when Issuer is empty")
		assert.Equal(t, "https://some-other-issuer.example.com", p.Issuer,
			"Principal.Issuer must come from the verified claim, not Config")
	})

	t.Run("absent issuer accepted", func(t *testing.T) {
		t.Parallel()
		token := rsaKey.mint(t, js.srv.URL, withoutClaim(claimIss))
		p, err := v.Validate(context.Background(), token)
		require.NoError(t, err, "a missing iss must be accepted when Issuer is empty")
		assert.Empty(t, p.Issuer)
	})
}

// TestIssuerStillVerifiedWhenConfigured is the other half of B1: relaxing the
// requirement must not weaken the configured case.
func TestIssuerStillVerifiedWhenConfigured(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	token := rsaKey.mint(t, "https://attacker.example.com")
	_, err = v.Validate(context.Background(), token)
	requireAuthnError(t, err, CodeInvalidToken, ReasonIssuer)
}

// TestAllowAnyAudience covers B2: AllowAnyAudience disables audience
// verification, matching ToolHive's behavior when its Audience is unset.
func TestAllowAnyAudience(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.Audiences = nil
	cfg.AllowAnyAudience = true
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	for _, tt := range []struct {
		name string
		opt  mintOption
	}{
		{name: "unrelated audience accepted", opt: withClaim(claimAud, "https://someone-elses-api.example.com")},
		{name: "bare-identifier audience accepted", opt: withClaim(claimAud, "some-client-id")},
		{name: "absent audience accepted", opt: withoutClaim(claimAud)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := v.Validate(context.Background(), rsaKey.mint(t, js.srv.URL, tt.opt))
			require.NoError(t, err, "audience must not be verified under AllowAnyAudience")
		})
	}
}

// TestNonURIAudienceMatching covers the other half of B2: non-URI audiences are
// not merely accepted by config validation, they must actually MATCH a token's
// aud claim, and a mismatch must still be rejected.
func TestNonURIAudienceMatching(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.Audiences = []string{"550e8400-e29b-41d4-a716-446655440000", "my-client-id"}
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	t.Run("GUID audience matches", func(t *testing.T) {
		t.Parallel()
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimAud, "550e8400-e29b-41d4-a716-446655440000"))
		_, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
	})

	t.Run("second entry matches (any-of)", func(t *testing.T) {
		t.Parallel()
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimAud, "my-client-id"))
		_, err := v.Validate(context.Background(), token)
		require.NoError(t, err)
	})

	t.Run("mismatch still rejected", func(t *testing.T) {
		t.Parallel()
		token := rsaKey.mint(t, js.srv.URL, withClaim(claimAud, "not-my-client-id"))
		_, err := v.Validate(context.Background(), token)
		requireAuthnError(t, err, CodeInvalidToken, ReasonAudience)
	})
}

// TestMaxTokenLifetimeDisabledByDefault covers B3: a zero MaxTokenLifetime
// imposes no exp-iat bound, so a long-lived token that ToolHive accepts today
// (it has no lifetime check at all) is not rejected merely by adopting authn.
func TestMaxTokenLifetimeDisabledByDefault(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	require.Zero(t, cfg.MaxTokenLifetime, "the test fixture must not set a lifetime bound")
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// A 30-day span: comfortably beyond the 24h cap that used to be defaulted.
	iat := time.Now().Add(-time.Hour)
	token := rsaKey.mint(t, js.srv.URL,
		withClaim(claimIat, iat.Unix()),
		withClaim(claimExp, iat.Add(30*24*time.Hour).Unix()))
	_, err = v.Validate(context.Background(), token)
	require.NoError(t, err, "a zero MaxTokenLifetime must impose no exp-iat bound")
}

// --- log-safety, shutdown, and iat:0 (review follow-ups) -------------------

// TestParseBearerNeverLeaksCredential covers the credential-disclosure finding:
// Error() is documented as log-safe, and a malformed header routinely still
// carries a live token ("Bearer <token> junk", or a token sent with no scheme).
// No error from ParseBearer may contain any byte of the header value.
func TestParseBearerNeverLeaksCredential(t *testing.T) {
	t.Parallel()

	const secret = "s3cr3t-live-token-do-not-log"
	for _, tt := range []struct {
		name   string
		header string
	}{
		{name: "trailing junk after a valid token", header: "Bearer " + secret + " junk"},
		{name: "token with no scheme", header: secret},
		{name: "tab separator", header: "Bearer\t" + secret},
		{name: "wrong scheme", header: "Basic " + secret},
		{name: "internal whitespace", header: "Bearer " + secret + " " + secret},
		{name: "over-long token", header: "Bearer " + strings.Repeat("x", maxTokenLength+1)},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseBearer(tt.header)
			require.Error(t, err)
			assert.NotContains(t, err.Error(), secret,
				"the error text must not carry the credential: Error() is logged")
			// Stronger: no substring of the header at all beyond the scheme name.
			assert.NotContains(t, err.Error(), tt.header,
				"the error text must not echo the header value")
		})
	}
}

// TestParseBearerAcceptsMultipleSeparatorSpaces covers RFC 7235's
// `auth-scheme 1*SP token68`: one or more spaces are legal between the scheme
// and the credential, so "Bearer  <token>" must parse rather than be rejected.
func TestParseBearerAcceptsMultipleSeparatorSpaces(t *testing.T) {
	t.Parallel()

	for _, hv := range []string{"Bearer " + testToken, "Bearer  " + testToken, "Bearer   " + testToken} {
		got, err := ParseBearer(hv)
		require.NoError(t, err, "1*SP between scheme and credential is legal (RFC 7235)")
		assert.Equal(t, testToken, got)
	}
}

// TestValidateAfterCloseFailsFast covers the shutdown-hang finding: the jwx
// cache's controller goroutines stop when the validator's lifetime context is
// canceled, so a Lookup carrying only the request context would block forever
// on a channel with no receiver. Validate must report CodeUnavailable promptly
// instead.
func TestValidateAfterCloseFailsFast(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	token := rsaKey.mint(t, js.srv.URL)
	v.Close()

	done := make(chan error, 1)
	go func() {
		_, e := v.Validate(context.Background(), token)
		done <- e
	}()
	select {
	case e := <-done:
		requireAuthnError(t, e, CodeUnavailable, ReasonKeysUnavailable)
	case <-time.After(5 * time.Second):
		t.Fatal("Validate hung after Close instead of failing fast")
	}
}

// TestValidateUnblocksOnConcurrentClose covers the same hazard from the other
// side: a Close racing an in-flight Validate must let that request finish rather
// than leave it parked on a stopped controller.
func TestValidateUnblocksOnConcurrentClose(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)

	// An unknown kid forces the recovery path, which touches the cache more than
	// a plain hit would.
	stranger := mintRSA(t, "stranger")
	token := stranger.mint(t, js.srv.URL)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = v.Validate(context.Background(), token)
	}()
	v.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("an in-flight Validate did not unblock after a concurrent Close")
	}
}

// TestIatZeroDoesNotBypassLifetime covers the iat:0 finding: 0 is a valid
// NumericDate (the Unix epoch), but jwt.MapClaims.GetIssuedAt reports it as
// absent, which silently skipped the lifetime check no matter how distant exp
// was.
func TestIatZeroDoesNotBypassLifetime(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.MaxTokenLifetime = time.Hour
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	token := rsaKey.mint(t, js.srv.URL,
		withClaim(claimIat, 0),
		withClaim(claimExp, time.Now().Add(24*time.Hour).Unix()))
	_, err = v.Validate(context.Background(), token)
	requireAuthnError(t, err, CodeInvalidToken, ReasonLifetime)
}

// TestAudiencesClonedAtConstruction covers the aliasing finding: Config is
// copied by value, but the Audiences slice shared its backing array with the
// caller, so mutating it afterwards rewrote the trusted policy (and raced
// Validate while doing it).
func TestAudiencesClonedAtConstruction(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.Audiences = []string{testAPIAud}
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Rewrite the caller's slice to an audience the validator must NOT trust.
	cfg.Audiences[0] = "https://attacker.example.com"

	token := rsaKey.mint(t, js.srv.URL, withClaim(claimAud, "https://attacker.example.com"))
	_, err = v.Validate(context.Background(), token)
	requireAuthnError(t, err, CodeInvalidToken, ReasonAudience)

	// And the originally configured audience still validates.
	_, err = v.Validate(context.Background(), rsaKey.mint(t, js.srv.URL))
	require.NoError(t, err)
}

// --- hardening policies: RSA strength, JWKS staleness, token type ----------

// TestWeakRSAKeyRejected covers the RFC 7518 §3.3 strength floor: RS*/PS*
// require a modulus of at least 2048 bits, so a shorter key must not be used
// even though it came from the configured JWKS.
func TestWeakRSAKeyRejected(t *testing.T) {
	t.Parallel()

	weak := mintRSABits(t, "weak", 1024)
	js := newJWKSServer(t, weak.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err, "a weak key must not break construction, only verification")
	t.Cleanup(v.Close)

	_, err = v.Validate(context.Background(), weak.mint(t, js.srv.URL))
	// The key is filtered out as a candidate, so the kid resolves to nothing.
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownKID)
}

// TestStrongRSAKeyStillAccepted is the control for the floor.
func TestStrongRSAKeyStillAccepted(t *testing.T) {
	t.Parallel()

	strong := mintRSABits(t, "strong", 2048)
	js := newJWKSServer(t, strong.jwk)
	v, err := NewValidator(context.Background(), js.configFor())
	require.NoError(t, err)
	t.Cleanup(v.Close)

	_, err = v.Validate(context.Background(), strong.mint(t, js.srv.URL))
	require.NoError(t, err)
}

// TestWeakRSAKeyFromProviderRejected applies the same floor to in-process keys:
// a KeyProvider is trusted, but not trusted to be correctly configured.
func TestWeakRSAKeyFromProviderRejected(t *testing.T) {
	t.Parallel()

	weak := mintRSABits(t, "weak", 1024)
	kp := &fakeKeyProvider{keys: []PublicKey{{KeyID: "weak", Key: weak.priv.Public()}}}
	cfg := providerConfig(t, kp)
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	_, err = v.Validate(context.Background(), weak.mint(t, validConfig().Issuer))
	require.Error(t, err, "a sub-2048-bit provider key must not verify a token")
	var authnErr *Error
	require.ErrorAs(t, err, &authnErr)
	assert.NotEqual(t, ReasonSignature, authnErr.Reason)
}

// TestMaxJWKSStalenessRejectsRevokedKeyAfterOutage covers the staleness bound:
// the cache keeps serving its last good key set after every failed refresh, so
// without a bound a key revoked at the IdP stays trusted for the whole outage.
func TestMaxJWKSStalenessRejectsRevokedKeyAfterOutage(t *testing.T) {
	t.Parallel()

	compromised := mintRSA(t, "compromised")
	js := newJWKSServer(t, compromised.jwk)
	cfg := js.configFor()
	cfg.MaxJWKSStaleness = 50 * time.Millisecond // tiny, so the test need not wait
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)
	token := compromised.mint(t, js.srv.URL)

	// While the issuer is reachable the bound must NOT bite, even though the
	// window is far shorter than the refresh interval: exceeding it triggers a
	// refresh, which succeeds.
	time.Sleep(2 * cfg.MaxJWKSStaleness)
	_, err = v.Validate(context.Background(), token)
	require.NoError(t, err, "a healthy issuer must never trip the staleness bound")

	// Now the issuer becomes unreachable. Once the bound elapses with no
	// successful fetch, the cached key must stop being trusted.
	js.setOverride(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	assert.Eventually(t, func() bool {
		setLastRefresh(v, time.Now().Add(-2*refreshFloor)) // allow a refresh attempt
		_, err := v.Validate(context.Background(), token)
		var authnErr *Error
		return errors.As(err, &authnErr) && authnErr.Reason == ReasonKeysStale
	}, 3*time.Second, 50*time.Millisecond,
		"a revoked key must stop validating once cached material exceeds MaxJWKSStaleness")
}

// TestStalenessBoundDisabledByDefault is the availability half: with the bound
// off (the default), an unreachable issuer must NOT break validation of tokens
// signed by already-cached keys.
func TestStalenessBoundDisabledByDefault(t *testing.T) {
	t.Parallel()

	key := mintRSA(t, "k1")
	js := newJWKSServer(t, key.jwk)
	cfg := js.configFor()
	require.Zero(t, cfg.MaxJWKSStaleness, "the bound must be off by default")
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)
	token := key.mint(t, js.srv.URL)

	js.setOverride(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	setLastRefresh(v, time.Now().Add(-2*refreshFloor))
	_, err = v.Validate(context.Background(), token)
	require.NoError(t, err,
		"with the bound disabled an issuer outage must not break validation of cached keys")
}

// typAccessToken is RFC 9068's access-token media type.
const typAccessToken = "at+jwt"

// TestAcceptedTokenTypes covers the typ gate, including the ID-token
// substitution it exists to stop.
func TestAcceptedTokenTypes(t *testing.T) {
	t.Parallel()

	key := mintRSA(t, "k1")
	js := newJWKSServer(t, key.jwk)

	t.Run("unset accepts any typ", func(t *testing.T) {
		t.Parallel()
		v, err := NewValidator(context.Background(), js.configFor())
		require.NoError(t, err)
		t.Cleanup(v.Close)
		for _, typ := range []string{"JWT", typAccessToken, "id_token+jwt", "anything"} {
			_, err := v.Validate(context.Background(), key.mint(t, js.srv.URL, withHeader("typ", typ)))
			require.NoError(t, err, "typ %q must be accepted when the gate is unset", typ)
		}
	})

	t.Run("configured gate", func(t *testing.T) {
		t.Parallel()
		cfg := js.configFor()
		cfg.AcceptedTokenTypes = []string{typAccessToken}
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		accepted := []any{typAccessToken, "AT+JWT", "application/" + typAccessToken, "application/AT+JWT"}
		for _, typ := range accepted {
			_, err := v.Validate(context.Background(), key.mint(t, js.srv.URL, withHeader("typ", typ)))
			require.NoError(t, err, "typ %v must match the accepted type (case- and prefix-insensitive)", typ)
		}

		// The substitution this gate exists to stop.
		_, err = v.Validate(context.Background(), key.mint(t, js.srv.URL, withHeader("typ", "id_token+jwt")))
		requireAuthnError(t, err, CodeInvalidToken, ReasonTokenType)

		_, err = v.Validate(context.Background(), key.mint(t, js.srv.URL, withHeader("typ", "JWT")))
		requireAuthnError(t, err, CodeInvalidToken, ReasonTokenType)

		// A missing typ cannot satisfy a gate that demands a positive statement.
		_, err = v.Validate(context.Background(), key.mint(t, js.srv.URL))
		requireAuthnError(t, err, CodeInvalidToken, ReasonTokenType)

		// Nor can a non-string typ.
		_, err = v.Validate(context.Background(), key.mint(t, js.srv.URL, withHeader("typ", 42)))
		requireAuthnError(t, err, CodeInvalidToken, ReasonTokenType)
	})
}
