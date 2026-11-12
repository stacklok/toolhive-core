// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tsIssuer is a TrustSet test issuer: a JWKS server and the key it serves.
type tsIssuer struct {
	js  *jwksServer
	key rsaPair
}

func newTSIssuer(t *testing.T) tsIssuer {
	t.Helper()
	key := mintRSA(t, "k1")
	return tsIssuer{js: newJWKSServer(t, key.jwk), key: key}
}

func (i tsIssuer) url() string { return i.js.srv.URL }

func (i tsIssuer) trust(id string) Trust {
	cfg := validConfig()
	cfg.Issuer = i.url()
	cfg.JWKSURL = i.url() + "/jwks.json"
	cfg.AllowPrivateIP = true
	cfg.InsecureAllowHTTP = true
	return Trust{ID: id, Config: cfg}
}

func (i tsIssuer) mint(t *testing.T, opts ...mintOption) string {
	t.Helper()
	return i.key.mint(t, i.url(), opts...)
}

// providerTrust is a ProviderOnly trust for issuer, signed by key.
func providerTrust(id, issuer string, key rsaPair) Trust {
	cfg := validConfig()
	cfg.Issuer = issuer
	kid, _ := key.jwk.KeyID()
	cfg.KeyProvider = &fakeKeyProvider{keys: []PublicKey{{KeyID: kid, Key: key.priv.Public()}}}
	cfg.ProviderOnly = true
	return Trust{ID: id, Config: cfg}
}

func newSet(t *testing.T, trusts []Trust, opts ...SetOption) *TrustSet {
	t.Helper()
	s, errs := NewTrustSet(context.Background(), trusts, opts...)
	require.Empty(t, errs)
	t.Cleanup(s.Close)
	return s
}

func TestTrustSetRouting(t *testing.T) {
	t.Parallel()

	a, b := newTSIssuer(t), newTSIssuer(t)
	ta := a.trust("a")
	ta.Tag = "tag-a"
	s := newSet(t, []Trust{ta, b.trust("b")})
	ctx := context.Background()

	p, err := s.Verify(ctx, a.mint(t))
	require.NoError(t, err)
	assert.Equal(t, TrustRef{ID: "a", Issuer: a.url(), Tag: "tag-a"}, p.Trust)
	assert.Equal(t, testSubject, p.Subject)

	p, err = s.Verify(ctx, b.mint(t))
	require.NoError(t, err)
	assert.Equal(t, "b", p.Trust.ID)

	// Both keys have kid k1. A token claiming a's issuer but signed with b's
	// key is verified with a's keys only, so it fails.
	_, err = s.Verify(ctx, b.key.mint(t, a.url()))
	require.Error(t, err)
	assert.NotEqual(t, ReasonUnknownIssuer, reasonOf(t, err))
}

// TestTrustSetPerTrustPolicy checks that a token is accepted under the policy
// of the trust it routes to, and only that one: another trust's audience or
// Check never applies.
func TestTrustSetPerTrustPolicy(t *testing.T) {
	t.Parallel()

	const audA, audB, blocked = "https://a.example.com", "https://b.example.com", "mallory"
	a, b := newTSIssuer(t), newTSIssuer(t)
	ta := a.trust("a")
	ta.Config.Audiences = []string{audA}
	ta.Config.Checks = []Check{CheckFunc(func(claims map[string]any, _ time.Time) error {
		if claims[claimSub] == blocked {
			return errors.New("blocked subject")
		}
		return nil
	})}
	tb := b.trust("b")
	tb.Config.Audiences = []string{audB}
	s := newSet(t, []Trust{ta, tb})

	tests := []struct {
		name   string
		token  string
		want   Reason // empty means accepted
		wantID string
	}{
		{"a with a's audience", a.mint(t, withClaim(claimAud, audA)), "", "a"},
		{"a with b's audience", a.mint(t, withClaim(claimAud, audB)), ReasonAudience, ""},
		{"b with b's audience", b.mint(t, withClaim(claimAud, audB)), "", "b"},
		{"b with a's audience", b.mint(t, withClaim(claimAud, audA)), ReasonAudience, ""},
		{"a's check rejects", a.mint(t, withClaim(claimAud, audA), withClaim(claimSub, blocked)), ReasonCheck, ""},
		{"a's check does not apply to b", b.mint(t, withClaim(claimAud, audB), withClaim(claimSub, blocked)), "", "b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := s.Verify(context.Background(), tt.token)
			if tt.want != "" {
				requireAuthnError(t, err, CodeInvalidToken, tt.want)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantID, p.Trust.ID)
		})
	}
}

func TestTrustSetUnroutableTokens(t *testing.T) {
	t.Parallel()

	a := newTSIssuer(t)
	s := newSet(t, []Trust{a.trust("a")})
	payload := func(json string) string {
		enc := base64.RawURLEncoding
		return enc.EncodeToString([]byte(`{"alg":"RS256","kid":"k1"}`)) + "." + enc.EncodeToString([]byte(json)) + ".sig"
	}
	tests := []struct {
		name  string
		token string
		want  Reason
	}{
		{"unknown issuer", a.key.mint(t, "https://other.example.com"), ReasonUnknownIssuer},
		{"issuer with a trailing slash", a.key.mint(t, a.url()+"/"), ReasonUnknownIssuer},
		{"no iss", a.mint(t, withClaim(claimIss, nil)), ReasonUnknownIssuer},
		{"non-string iss", payload(`{"iss":5}`), ReasonUnknownIssuer},
		{"upper-case ISS only", payload(`{"ISS":"` + a.url() + `"}`), ReasonUnknownIssuer},
		{"not a JWT", "opaque-token", ReasonMalformed},
		{"payload not base64", "e30.%%%.sig", ReasonMalformed},
		{"payload not JSON", payload(`not json`), ReasonMalformed},
		{"payload not an object", payload(`["iss"]`), ReasonMalformed},
		{"empty", "", ReasonMalformed},
		{"too long", strings.Repeat("a", maxTokenLength+1), ReasonMalformed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := s.Verify(context.Background(), tt.token)
			requireAuthnError(t, err, CodeInvalidToken, tt.want)
			assert.Equal(t, tt.want == ReasonMalformed, PossiblyOpaque(err))
		})
	}
}

func TestNewTrustSetRefusesTrusts(t *testing.T) {
	t.Parallel()

	const bad = "bad"
	a, b := newTSIssuer(t), newTSIssuer(t)
	mod := func(f func(*Trust)) Trust { tr := a.trust(bad); f(&tr); return tr }
	tests := []struct {
		name   string
		trusts []Trust
		bad    []string
	}{
		{"empty ID", []Trust{mod(func(t *Trust) { t.ID = "" })}, []string{""}},
		{"control character in ID", []Trust{mod(func(t *Trust) { t.ID = "a\nb" })}, []string{"a\nb"}},
		{"long ID", []Trust{mod(func(t *Trust) { t.ID = strings.Repeat("a", maxTrustIDLength+1) })},
			[]string{strings.Repeat("a", maxTrustIDLength+1)}},
		{"no issuer", []Trust{mod(func(t *Trust) { t.Config.Issuer = "" })}, []string{bad}},
		{"invalid config", []Trust{mod(func(t *Trust) { t.Config.Audiences = nil })}, []string{bad}},
		{"unreachable keys", []Trust{mod(func(t *Trust) { t.Config.JWKSURL = unreachableJWKSURL })}, []string{bad}},
		{"shared ID refuses both", []Trust{a.trust("x"), b.trust("x")}, []string{"x", "x"}},
		{"shared issuer refuses both, ignoring trailing slashes", []Trust{
			a.trust("one"), mod(func(t *Trust) { t.ID = "two"; t.Config.Issuer = a.url() + "/" }),
		}, []string{"one", "two"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// A valid trust of another issuer is installed regardless.
			other := newTSIssuer(t)
			ok := other.trust("ok")
			s, errs := NewTrustSet(context.Background(), append(tt.trusts, ok))
			t.Cleanup(s.Close)
			var ids []string
			for _, e := range errs {
				ids = append(ids, e.ID)
				assert.NotEmpty(t, e.Error())
				require.Error(t, e.Unwrap())
			}
			assert.Equal(t, tt.bad, ids)
			_, err := s.Verify(context.Background(), a.mint(t))
			requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownIssuer)
			_, err = s.Verify(context.Background(), other.mint(t))
			require.NoError(t, err, "the valid trust is installed")
		})
	}
}

func TestTrustSetNotAfter(t *testing.T) {
	t.Parallel()

	a := newTSIssuer(t)
	now := time.Now()
	tr := a.trust("a")
	tr.NotAfter = now.Add(time.Minute)
	var mu sync.Mutex
	clock := now
	s := newSet(t, []Trust{tr}, WithClock(func() time.Time { mu.Lock(); defer mu.Unlock(); return clock }))

	_, err := s.Verify(context.Background(), a.mint(t))
	require.NoError(t, err)

	mu.Lock()
	clock = tr.NotAfter
	mu.Unlock()
	_, err = s.Verify(context.Background(), a.mint(t))
	requireAuthnError(t, err, CodeUnavailable, ReasonTrustStale)
}

func TestTrustSetProviderOnly(t *testing.T) {
	t.Parallel()

	key := mintRSA(t, "dir-1")
	const iss = "https://workload.example.com"
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// A canceled ctx does not matter: a ProviderOnly trust does no I/O.
	s, errs := NewTrustSet(ctx, []Trust{providerTrust("w", iss, key)})
	require.Empty(t, errs)

	assert.Nil(t, s.routes[iss].v.jwksCache, "a ProviderOnly trust has no JWKS cache and no refresh goroutines")
	p, err := s.Verify(context.Background(), key.mint(t, iss))
	require.NoError(t, err)
	assert.Equal(t, "w", p.Trust.ID)
}

func TestNewTrustSetCanceledContext(t *testing.T) {
	t.Parallel()

	a := newTSIssuer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s, errs := NewTrustSet(ctx, []Trust{a.trust("a")})
	t.Cleanup(s.Close)
	require.Len(t, errs, 1)
	_, err := s.Verify(context.Background(), a.mint(t))
	requireAuthnError(t, err, CodeInvalidToken, ReasonUnknownIssuer)
}

func TestTrustSetClose(t *testing.T) {
	t.Parallel()

	a := newTSIssuer(t)
	s, errs := NewTrustSet(context.Background(), []Trust{a.trust("a")})
	require.Empty(t, errs)
	s.Close()
	s.Close()
	_, err := s.Verify(context.Background(), a.mint(t))
	requireAuthnError(t, err, CodeUnavailable, ReasonKeysUnavailable)
}

func TestTrustSetCloseRacesVerify(t *testing.T) {
	t.Parallel()

	a := newTSIssuer(t)
	s, errs := NewTrustSet(context.Background(), []Trust{a.trust("a")})
	require.Empty(t, errs)
	tok := a.mint(t)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i == 16 {
				s.Close()
			}
			_, err := s.Verify(context.Background(), tok)
			if err != nil {
				var ae *Error
				if assert.ErrorAs(t, err, &ae) {
					assert.Equal(t, CodeUnavailable, ae.Code)
				}
			}
		}()
	}
	wg.Wait()
}

func TestNewTrustSetInvalidTrustDoesNotRefuseValid(t *testing.T) {
	t.Parallel()

	a := newTSIssuer(t)
	invalid := a.trust("invalid")
	invalid.Config.Audiences = nil
	s, errs := NewTrustSet(context.Background(), []Trust{a.trust("valid"), invalid})
	t.Cleanup(s.Close)
	require.Len(t, errs, 1)
	assert.Equal(t, "invalid", errs[0].ID)
	p, err := s.Verify(context.Background(), a.mint(t))
	require.NoError(t, err)
	assert.Equal(t, "valid", p.Trust.ID)
}

func TestTrustSetConcurrentVerify(t *testing.T) {
	t.Parallel()

	a, b := newTSIssuer(t), newTSIssuer(t)
	s := newSet(t, []Trust{a.trust("a"), b.trust("b")})
	tokA, tokB := a.mint(t), b.mint(t)
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok := tokA
			if i%2 == 1 {
				tok = tokB
			}
			_, err := s.Verify(context.Background(), tok)
			assert.NoError(t, err)
		}()
	}
	wg.Wait()
}

func TestQuoteUntrusted(t *testing.T) {
	t.Parallel()

	assert.Equal(t, `"a\nb"`, quoteUntrusted("a\nb"))
	long := strings.Repeat("é", maxQuoted)
	got := quoteUntrusted(long)
	assert.True(t, strings.HasSuffix(got, "...(truncated)"))
	assert.LessOrEqual(t, len(got), maxQuoted+len(`""...(truncated)`))
}
