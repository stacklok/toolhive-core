// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/networking"
)

// unreachableJWKSURL is a JWKS URL on a closed port: any fetch against it fails
// immediately, which is what several tests need to exercise the fail-closed and
// provider-tolerant construction paths.
const unreachableJWKSURL = "http://127.0.0.1:1/jwks.json"

// wantErrExceeds is the substring shared by the "over a configured limit"
// errors (leeway, audience length, token length, body cap).
const wantErrExceeds = "exceeds"

const idTokenJWT = "id_token+jwt"

// validConfig returns a Config that passes validation.
func validConfig() Config {
	return Config{
		Issuer:    "https://issuer.example.com",
		Audiences: []string{"https://api.example.com"},
	}
}

func TestNewValidatorConfigValidation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr string
		check   func(t *testing.T, cfg Config)
	}{
		{
			name:    "empty issuer AND empty jwks_url rejected",
			mutate:  func(c *Config) { c.Issuer = ""; c.JWKSURL = "" },
			wantErr: "at least one of issuer or jwks_url is required",
		},
		{
			name:    "issuer non-https rejected",
			mutate:  func(c *Config) { c.Issuer = "http://issuer.example.com" },
			wantErr: "https",
		},
		{
			// The scheme check runs before any I/O; with it relaxed the
			// validator would attempt discovery against the issuer, so point
			// at a local discovery server and assert success.
			name: "issuer non-https permitted with InsecureAllowHTTP",
			mutate: func(c *Config) {
				srv := newDiscoveryOnlyServer(t)
				c.Issuer = srv.URL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
			},
		},
		{
			name:    "issuer with fragment",
			mutate:  func(c *Config) { c.Issuer = "https://issuer.example.com#frag" },
			wantErr: "fragment",
		},
		{
			name:    "issuer without scheme",
			mutate:  func(c *Config) { c.Issuer = "issuer.example.com" },
			wantErr: "scheme",
		},
		{
			name:    "issuer without host",
			mutate:  func(c *Config) { c.Issuer = "https:///path" },
			wantErr: "host",
		},
		{
			name:    "empty audiences without AllowAnyAudience rejected",
			mutate:  func(c *Config) { c.Audiences = nil },
			wantErr: "at least one audience is required",
		},
		{
			// RFC 7519 §4.1.3 types aud as StringOrURI, so a bare identifier
			// (an OAuth client_id) is conformant and MUST be accepted: this is
			// the ToolHive-compatibility case.
			name: "bare-identifier audience accepted",
			mutate: func(c *Config) {
				srv := newDiscoveryOnlyServer(t)
				c.Issuer = srv.URL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
				c.Audiences = []string{"my-client-id"}
			},
		},
		{
			// Entra ID issues opaque GUID audiences.
			name: "GUID audience accepted",
			mutate: func(c *Config) {
				srv := newDiscoveryOnlyServer(t)
				c.Issuer = srv.URL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
				c.Audiences = []string{"550e8400-e29b-41d4-a716-446655440000"}
			},
		},
		{
			name:    "empty audience entry rejected",
			mutate:  func(c *Config) { c.Audiences = []string{""} },
			wantErr: "must not be empty",
		},
		{
			name:    "audience with CRLF rejected",
			mutate:  func(c *Config) { c.Audiences = []string{"https://api.example.com\r\nX: y"} },
			wantErr: "control characters",
		},
		{
			name:    "over-long audience rejected",
			mutate:  func(c *Config) { c.Audiences = []string{strings.Repeat("a", maxAudienceLength+1)} },
			wantErr: wantErrExceeds,
		},
		{
			name: "AllowAnyAudience permits an empty list",
			mutate: func(c *Config) {
				srv := newDiscoveryOnlyServer(t)
				c.Issuer = srv.URL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
				c.Audiences = nil
				c.AllowAnyAudience = true
			},
		},
		{
			name: "AllowAnyAudience with a populated list rejected",
			mutate: func(c *Config) {
				c.AllowAnyAudience = true
			},
			wantErr: "must not be set together with",
		},
		{
			name:    "jwks_url non-https rejected",
			mutate:  func(c *Config) { c.JWKSURL = "http://issuer.example.com/jwks.json" },
			wantErr: "https",
		},
		{
			// InsecureAllowHTTP relaxes the scheme check only; construction
			// then fails closed because the fake endpoint serves no JWKS.
			name: "jwks_url non-https permitted with InsecureAllowHTTP but unfetchable",
			mutate: func(c *Config) {
				c.JWKSURL = unreachableJWKSURL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
			},
			wantErr: "failed to fetch JWKS",
		},
		{
			name:    "jwks_url without host",
			mutate:  func(c *Config) { c.JWKSURL = "https:///jwks.json" },
			wantErr: "host",
		},
		{
			name:    "negative leeway",
			mutate:  func(c *Config) { c.Leeway = -time.Second },
			wantErr: "negative",
		},
		{
			name:    "leeway above max",
			mutate:  func(c *Config) { c.Leeway = maxLeeway + time.Second },
			wantErr: wantErrExceeds,
		},
		{
			name: "leeway at max accepted",
			mutate: func(c *Config) {
				c.Leeway = maxLeeway
				// Discovery now runs when JWKSURL is empty; point the issuer
				// at a local discovery server so construction succeeds.
				srv := newDiscoveryOnlyServer(t)
				c.Issuer = srv.URL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
			},
		},
		{
			name:    "negative max token lifetime",
			mutate:  func(c *Config) { c.MaxTokenLifetime = -time.Hour },
			wantErr: "negative",
		},
		{
			name: "defaults applied",
			mutate: func(c *Config) {
				// Discovery now runs when JWKSURL is empty; point the issuer
				// at a local discovery server so construction succeeds.
				srv := newDiscoveryOnlyServer(t)
				c.Issuer = srv.URL
				c.InsecureAllowHTTP = true
				c.AllowPrivateIP = true
			},
			check: func(t *testing.T, cfg Config) {
				t.Helper()
				assert.Equal(t, defaultLeeway, cfg.Leeway)
				// MaxTokenLifetime is deliberately NOT defaulted: zero means
				// "no lifetime bound", so adopting this package cannot start
				// rejecting long-lived tokens a resource server accepts today.
				assert.Zero(t, cfg.MaxTokenLifetime)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}

			v, err := NewValidator(context.Background(), cfg)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Nil(t, v)
				assert.Contains(t, err.Error(), tt.wantErr)
				// Construction errors are ordinary Go errors, not *Error.
				var authnErr *Error
				assert.NotErrorAs(t, err, &authnErr)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, v)
			t.Cleanup(v.Close)
			if tt.check != nil {
				tt.check(t, v.cfg)
			}
		})
	}
}

// TestValidateConfigAgreesWithNewValidator pins the single-validation-path
// requirement: NewValidator routes through ValidateConfig, so the exported check
// and the constructor cannot drift into disagreeing about what a valid Config is.
// Rather than duplicate the table above, this asserts the two produce the SAME
// error for each rejection. Every case here fails before any I/O, so calling
// NewValidator is offline and cheap.
func TestValidateConfigAgreesWithNewValidator(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no issuer and no jwks_url", func(c *Config) { c.Issuer = ""; c.JWKSURL = "" }},
		{"non-https issuer", func(c *Config) { c.Issuer = "http://issuer.example.com" }},
		{"no audience and no AllowAnyAudience", func(c *Config) { c.Audiences = nil }},
		{"audiences together with AllowAnyAudience", func(c *Config) { c.AllowAnyAudience = true }},
		{"negative leeway", func(c *Config) { c.Leeway = -time.Second }},
		{"leeway above the maximum", func(c *Config) { c.Leeway = time.Hour }},
		{"DisableLeeway with a non-zero leeway", func(c *Config) {
			c.DisableLeeway = true
			c.Leeway = 30 * time.Second
		}},
		{"negative max token lifetime", func(c *Config) { c.MaxTokenLifetime = -time.Second }},
		{"negative max JWKS staleness", func(c *Config) { c.MaxJWKSStaleness = -time.Second }},
		{"empty accepted token type", func(c *Config) { c.AcceptedTokenTypes = []string{" "} }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tt.mutate(&cfg)

			got, valErr := ValidateConfig(cfg)
			require.Error(t, valErr, "ValidateConfig must reject this config")
			assert.Equal(t, Config{}, got, "a rejected config must come back zeroed, not half-defaulted")

			v, ctorErr := NewValidator(context.Background(), cfg)
			require.Error(t, ctorErr, "NewValidator must reject the same config")
			assert.Nil(t, v)
			assert.Equal(t, valErr.Error(), ctorErr.Error(),
				"both paths must report the identical error, or they have drifted")
		})
	}
}

// TestValidateConfigNormalizesWithoutTouchingTheCaller covers the two promises a
// caller relies on when holding a validated Config: the defaults are actually
// applied, and neither the caller's struct nor its slice backing arrays are
// touched.
func TestValidateConfigNormalizesWithoutTouchingTheCaller(t *testing.T) {
	t.Parallel()

	t.Run("defaults are applied", func(t *testing.T) {
		t.Parallel()
		got, err := ValidateConfig(validConfig())
		require.NoError(t, err)
		assert.Equal(t, defaultLeeway, got.Leeway, "zero leeway must default")
	})

	t.Run("DisableLeeway keeps zero leeway", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.DisableLeeway = true
		got, err := ValidateConfig(cfg)
		require.NoError(t, err)
		assert.Zero(t, got.Leeway, "DisableLeeway must not be overwritten by the default")
	})

	t.Run("the caller's Config is not mutated", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		_, err := ValidateConfig(cfg)
		require.NoError(t, err)
		assert.Zero(t, cfg.Leeway, "defaulting must land on the copy, not the caller's struct")
	})

	t.Run("caller slice mutations cannot rewrite the returned policy", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.AcceptedTokenTypes = []string{"at+jwt"}
		got, err := ValidateConfig(cfg)
		require.NoError(t, err)

		// Rewrite both slices through the caller's own headers. Without the clone
		// these writes would land in the returned Config's backing arrays and
		// silently redefine the trusted policy.
		cfg.Audiences[0] = "https://attacker.example.com"
		cfg.AcceptedTokenTypes[0] = idTokenJWT

		assert.Equal(t, []string{"https://api.example.com"}, got.Audiences)
		assert.Equal(t, []string{"at+jwt"}, got.AcceptedTokenTypes)
	})
}

// TestValidateConfigPerformsNoIO is the contract that makes the function useful to
// a caller deferring construction: it must reject static policy errors without
// doing any of the work that can fail dynamically.
//
// Both cases assert the sharper version of that claim — not merely that
// ValidateConfig succeeds, but that NewValidator on the SAME config fails on the
// I/O ValidateConfig skipped. That doubles as a check on the documented caveat:
// a successful ValidateConfig is no promise that construction will succeed.
func TestValidateConfigPerformsNoIO(t *testing.T) {
	t.Parallel()

	t.Run("no CA bundle is read", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.CACertPath = filepath.Join(t.TempDir(), "does-not-exist.pem")

		_, err := ValidateConfig(cfg)
		require.NoError(t, err, "a missing CA bundle is not a static policy error")

		// newHTTPClient reads the bundle, so construction is where this surfaces.
		v, err := NewValidator(context.Background(), cfg)
		require.Error(t, err, "NewValidator must be the one to read the bundle and fail")
		assert.Nil(t, v)
	})

	t.Run("no JWKS or discovery fetch is attempted", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		// Port 1 on loopback refuses connections, so any fetch fails.
		cfg.JWKSURL = unreachableJWKSURL
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true

		_, err := ValidateConfig(cfg)
		require.NoError(t, err, "an unreachable JWKS is not a static policy error")

		v, err := NewValidator(context.Background(), cfg)
		require.Error(t, err, "NewValidator must be the one to fetch and fail")
		assert.Nil(t, v)
	})
}

func TestValidatorCloseIdempotentAndConcurrent(t *testing.T) {
	t.Parallel()

	srv := newDiscoveryOnlyServer(t)
	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)

	// Double Close plus concurrent Close must not panic or race.
	v.Close()
	v.Close()

	const callers = 16
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			v.Close()
		}()
	}
	wg.Wait()

	assert.True(t, v.ctx.Err() != nil, "internal context should be canceled after Close")
}

func TestDefaultHTTPClientRefusesRedirects(t *testing.T) {
	t.Parallel()

	srv := newDiscoveryOnlyServer(t)
	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example.com/jwks.json", nil)
	require.NoError(t, err)
	err = v.httpClient.CheckRedirect(req, nil)
	require.Error(t, err)
	var refused *errRedirectRefused
	assert.ErrorAs(t, err, &refused, "a refused redirect must be a real error, not http.ErrUseLastResponse")
	assert.Contains(t, err.Error(), req.URL.String(), "the refused target must be named in the error")
	assert.Equal(t, defaultHTTPTimeout, v.httpClient.Timeout)
}

// TestSuppliedHTTPClientEnforcesRedirectRefusalAndTimeout covers FIX 2: a
// caller-supplied &http.Client{} with nil CheckRedirect and zero Timeout must
// still have the redirect-refusal policy and the default timeout applied, so
// the SSRF redirect-refusal and fetch bound are not silently dropped for the
// deployments that supply a client. A caller that sets CheckRedirect
// explicitly is preserved.
func TestSuppliedHTTPClientEnforcesRedirectRefusalAndTimeout(t *testing.T) {
	t.Parallel()

	t.Run("bare supplied client gets redirect-refusal and timeout", func(t *testing.T) {
		t.Parallel()
		srv := newDiscoveryOnlyServer(t)
		cfg := validConfig()
		cfg.Issuer = srv.URL
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		cfg.HTTPClient = &http.Client{} // nil CheckRedirect, zero Timeout
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		// The nil CheckRedirect was replaced with the redirect-refusing policy.
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example.com/jwks.json", nil)
		require.NoError(t, err)
		err = v.httpClient.CheckRedirect(req, nil)
		require.Error(t, err)
		var refused *errRedirectRefused
		assert.ErrorAs(t, err, &refused)
		// The zero Timeout was replaced with the default.
		assert.Equal(t, defaultHTTPTimeout, v.httpClient.Timeout)
	})

	t.Run("supplied client refuses a 302 from the JWKS URL", func(t *testing.T) {
		t.Parallel()
		// An httptest server that 302-redirects its JWKS URL to a different
		// host. A bare &http.Client{} passed through newHTTPClient must refuse
		// the redirect (SSRF): the JWKS GET fails with errRedirectRefused
		// rather than following it to the redirect target or returning the raw
		// 302. We exercise newHTTPClient directly to isolate the
		// redirect-refusal behavior from construction's fail-closed fetch
		// (which would also surface this as an error, just a less direct
		// assertion).
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"keys":[]}`))
		}))
		t.Cleanup(target.Close)

		redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, "/jwks.json") {
				http.Redirect(w, r, target.URL+"/jwks.json", http.StatusFound)
				return
			}
			w.WriteHeader(http.StatusNotFound)
		}))
		t.Cleanup(redirector.Close)

		// The bare supplied client must get the redirect-refusal policy applied.
		client, err := newHTTPClient(&http.Client{}, false, "", "") // nil CheckRedirect, zero Timeout
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirector.URL+"/jwks.json", nil)
		require.NoError(t, err)
		_, err = client.Do(req)
		require.Error(t, err, "a bare supplied client must refuse the JWKS redirect (SSRF), not follow it to the target")
		var refused *errRedirectRefused
		assert.ErrorAs(t, err, &refused)
		assert.Contains(t, err.Error(), target.URL, "the error must name the refused redirect target")
	})

	t.Run("explicit CheckRedirect is preserved", func(t *testing.T) {
		t.Parallel()
		srv := newDiscoveryOnlyServer(t)
		// An explicit redirect-following policy (distinct from the default
		// refusal) must be preserved by newHTTPClient, not overwritten.
		var followed atomic.Int32
		explicit := func(*http.Request, []*http.Request) error {
			followed.Add(1)
			return nil // follow redirects
		}
		cfg := validConfig()
		cfg.Issuer = srv.URL
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		cfg.HTTPClient = &http.Client{CheckRedirect: explicit}
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)

		// The caller's CheckRedirect is preserved (it is the redirect-following
		// policy, not the default refusal).
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example.com/jwks.json", nil)
		require.NoError(t, err)
		err = v.httpClient.CheckRedirect(req, nil)
		require.NoError(t, err, "explicit CheckRedirect must be preserved, not overridden")
		assert.Equal(t, int32(1), followed.Load())
		// A zero Timeout is still filled in with the default; only an explicit
		// non-zero Timeout is preserved (not tested here to keep the test small).
		assert.Equal(t, defaultHTTPTimeout, v.httpClient.Timeout)
	})

	t.Run("explicit Timeout is preserved", func(t *testing.T) {
		t.Parallel()
		srv := newDiscoveryOnlyServer(t)
		const explicit = 42 * time.Second
		cfg := validConfig()
		cfg.Issuer = srv.URL
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		cfg.HTTPClient = &http.Client{Timeout: explicit}
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)
		assert.Equal(t, explicit, v.httpClient.Timeout,
			"an explicit caller Timeout must be preserved, not overwritten with the default")
	})
}

func TestHTTPClientBodyCap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		base *http.Client
		// wantConstructionErr, when non-empty, asserts NewValidator fails
		// with this substring (the body cap defeats the JWKS fetch itself).
		wantConstructionErr string
	}{
		{name: "default client", base: nil},
		{
			name: "caller-supplied client with transport",
			base: &http.Client{Transport: roundTripFunc(bigBody)},
			// bigBody answers the discovery document but serves a body larger
			// than the cap for the JWKS URL, so construction fails closed at
			// the first JWKS fetch; the cap assertion below still exercises
			// the wrapped transport directly.
			wantConstructionErr: wantErrExceeds,
		},
		{name: "caller-supplied client without transport", base: &http.Client{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := validConfig()
			cfg.HTTPClient = tt.base
			// Discovery runs when JWKSURL is empty. The nil/zero-transport
			// bases fall through to http.DefaultTransport, so they need a
			// real discovery server; the roundTripFunc base answers discovery
			// itself (below) so construction never leaves the test.
			if tt.base == nil || tt.base.Transport == nil {
				srv := newDiscoveryOnlyServer(t)
				cfg.Issuer = srv.URL
				cfg.InsecureAllowHTTP = true
				cfg.AllowPrivateIP = true
			} else {
				cfg.Issuer = bigBodyIssuer
			}
			v, err := NewValidator(context.Background(), cfg)
			if tt.wantConstructionErr != "" {
				require.Error(t, err)
				assert.Nil(t, v)
				assert.Contains(t, err.Error(), tt.wantConstructionErr,
					"the body cap must surface an error, not silent truncation")
				return
			}
			require.NoError(t, err)
			t.Cleanup(v.Close)

			require.NotNil(t, v.httpClient.Transport)
			var req *http.Request
			if tt.base == nil || tt.base.Transport == nil {
				// Transport wraps http.DefaultTransport; a request would hit
				// the network, so only assert the wrapper is in place.
				_, ok := v.httpClient.Transport.(limitedTransport)
				assert.True(t, ok)
				return
			}

			req, err = http.NewRequestWithContext(t.Context(), http.MethodGet, "https://issuer.example.com/jwks.json", nil)
			require.NoError(t, err)
			resp, err := v.httpClient.Transport.RoundTrip(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.Error(t, err, "body larger than the cap must surface an error, not silent truncation")
			assert.Contains(t, err.Error(), wantErrExceeds)
			assert.LessOrEqual(t, len(body), maxResponseBody, "no more than the cap may be delivered")
		})
	}
}

// TestValidatorLifetimeContextOutlivesConstruction guards the invariant that
// the JWKS cache is bound to the validator's lifetime context (v.ctx), which
// Close cancels — not to a short-lived construction context that is canceled
// when NewValidator returns. Regressing this (binding the cache to a
// construction-bounded ctx) silently kills background refresh.
func TestValidatorLifetimeContextOutlivesConstruction(t *testing.T) {
	t.Parallel()

	srv := newDiscoveryOnlyServer(t)
	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)

	require.NotNil(t, v.jwksCache, "cache should be started during construction")
	assert.NoError(t, v.ctx.Err(), "lifetime ctx must not be canceled when NewValidator returns")

	v.Close()
	assert.ErrorIs(t, v.ctx.Err(), context.Canceled, "Close must cancel the lifetime ctx")
}

// roundTripFunc adapts a function to http.RoundTripper.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

// TestLimitedBodyCapBoundary pins the exact-cap boundary: a body of exactly
// maxResponseBody bytes must be delivered in full with a clean io.EOF, while
// one byte more must produce the terminal "exceeds limit" error.
func TestLimitedBodyCapBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		size    int
		wantErr bool
		wantLen int
	}{
		{name: "below cap", size: maxResponseBody - 1, wantErr: false, wantLen: maxResponseBody - 1},
		{name: "exactly at cap", size: maxResponseBody, wantErr: false, wantLen: maxResponseBody},
		{name: "one past cap", size: maxResponseBody + 1, wantErr: true, wantLen: maxResponseBody},
		{name: "well past cap", size: maxResponseBody * 2, wantErr: true, wantLen: maxResponseBody},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			lb := &limitedBody{body: io.NopCloser(strings.NewReader(strings.Repeat("x", tt.size)))}
			got, err := io.ReadAll(lb)
			assert.Len(t, got, tt.wantLen)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), wantErrExceeds)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// bigBodyIssuer is the fake issuer the bigBody transport answers discovery
// for, letting TestHTTPClientBodyCap construct a Validator without network.
const bigBodyIssuer = "https://issuer.example.com"

// bigBody returns a response whose body is larger than maxResponseBody. As a
// special case it answers the OIDC discovery document for bigBodyIssuer so
// the transport can drive NewValidator's discovery path hermetically.
func bigBody(req *http.Request) (*http.Response, error) {
	if req.URL.String() == bigBodyIssuer+oidcDiscoveryPath {
		doc := fmt.Sprintf(`{"issuer":%q,"jwks_uri":%q}`, bigBodyIssuer, bigBodyIssuer+"/jwks.json")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(doc)),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", maxResponseBody*2))),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

// TestDefaultClientBlocksPrivateIPJWKS covers Phase C: the DEFAULT client must
// refuse to fetch a JWKS whose host resolves to a private, loopback, or
// link-local address. Without this, a jwks_uri pointing at cloud instance
// metadata (169.254.169.254) or an in-cluster address would be fetched — the
// https scheme check and redirect refusal do not classify resolved addresses.
//
// This is the protection ToolHive has on by default today
// (--jwks-allow-private-ip defaults false), so losing it would be a silent
// security regression for deployments that changed nothing.
func TestDefaultClientBlocksPrivateIPJWKS(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		jwksURL string
	}{
		{name: "cloud instance metadata", jwksURL: "http://169.254.169.254/latest/meta-data/jwks.json"},
		{name: "RFC1918 private", jwksURL: "http://10.0.0.1/jwks.json"},
		{name: "loopback", jwksURL: "http://127.0.0.1:9/jwks.json"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.JWKSURL = tt.jwksURL
			cfg.InsecureAllowHTTP = true // isolate the address check from the scheme check
			v, err := NewValidator(context.Background(), cfg)
			require.Error(t, err, "the default client must refuse a private-IP JWKS target")
			assert.Nil(t, v)
			assert.Contains(t, err.Error(), "private IP address",
				"the failure must come from the address guard, not some incidental error")
		})
	}
}

// TestAllowPrivateIPOptsOut is the other half: an operator with a legitimately
// in-cluster or localhost issuer can opt out, and then the fetch proceeds.
func TestAllowPrivateIPOptsOut(t *testing.T) {
	t.Parallel()

	srv := newDiscoveryOnlyServer(t) // listens on loopback
	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err, "AllowPrivateIP must permit a loopback issuer")
	t.Cleanup(v.Close)
}

// TestAcceptedTokenTypesClonedAtConstruction covers the aliasing finding: like
// Audiences, AcceptedTokenTypes shares its backing array with the caller
// unless cloned, so mutating it after construction would silently rewrite the
// trusted typ policy. Modeled on TestAudiencesClonedAtConstruction.
func TestAcceptedTokenTypesClonedAtConstruction(t *testing.T) {
	t.Parallel()

	rsaKey := mintRSA(t, "rsa-1")
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.AcceptedTokenTypes = []string{typAccessToken}
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	// Rewrite the caller's slice to a type the validator must NOT accept.
	cfg.AcceptedTokenTypes[0] = idTokenJWT

	token := rsaKey.mint(t, js.srv.URL, withHeader("typ", idTokenJWT))
	_, err = v.Validate(context.Background(), token)
	requireAuthnError(t, err, CodeInvalidToken, ReasonTokenType)

	// And the originally configured type still validates.
	token = rsaKey.mint(t, js.srv.URL, withHeader("typ", typAccessToken))
	_, err = v.Validate(context.Background(), token)
	require.NoError(t, err)
}

// TestLastSuccessStampedWithKeyProvider covers the MEDIUM finding that
// lastSuccess was stamped after the `if v.cfg.KeyProvider != nil { return nil
// }` early return in init, making it unreachable whenever a provider was
// configured. Left unfixed, staleness() stays enormous from construction
// onward, so MaxJWKSStaleness rejects with ReasonKeysStale the moment the
// JWKS endpoint becomes unreachable — exactly the outage KeyProvider exists to
// tolerate.
func TestLastSuccessStampedWithKeyProvider(t *testing.T) {
	t.Parallel()

	const keyID = "provider-key-1"
	rsaKey := mintRSA(t, keyID)
	js := newJWKSServer(t, rsaKey.jwk)
	cfg := js.configFor()
	cfg.KeyProvider = &fakeKeyProvider{keys: []PublicKey{{KeyID: keyID, Key: rsaKey.priv.Public()}}}
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	assert.Less(t, v.staleness(), time.Minute,
		"a successful construction fetch must stamp lastSuccess even with a KeyProvider configured")
}

// TestValidateHTTPSURISchemeAllowlist covers the MEDIUM finding that
// InsecureAllowHTTP was implemented as "anything but https", so ftp://,
// file://, and gopher:// all passed through once the flag was set. The fix
// makes it an explicit allowlist: https always, http only with the flag, and
// every other scheme always rejected.
func TestValidateHTTPSURISchemeAllowlist(t *testing.T) {
	t.Parallel()

	tests := []struct {
		scheme string
		wantOK bool // whether it is accepted when insecureAllowHTTP is true
	}{
		{scheme: schemeHTTPS, wantOK: true},
		{scheme: schemeHTTP, wantOK: true},
		{scheme: "ftp", wantOK: false},
		{scheme: "file", wantOK: false},
		{scheme: "gopher", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			t.Parallel()
			raw := tt.scheme + "://host/jwks"

			// https is always accepted regardless of the flag; every other
			// scheme is always rejected when the flag is unset.
			err := validateHTTPSURI("field", raw, false)
			if tt.scheme == schemeHTTPS {
				require.NoError(t, err)
			} else {
				require.Error(t, err, "non-https scheme must be rejected with InsecureAllowHTTP unset")
			}

			err = validateHTTPSURI("field", raw, true)
			if tt.wantOK {
				require.NoError(t, err, "scheme %q must be accepted with InsecureAllowHTTP set", tt.scheme)
			} else {
				require.Error(t, err, "scheme %q must stay rejected even with InsecureAllowHTTP set: "+
					"the flag widens https-only to https-or-http, not to any scheme", tt.scheme)
			}
		})
	}
}

// TestKeyProviderDiscoveryFailureFatality covers the MEDIUM finding that
// init's construction switch tolerated ANY discovery failure once a
// KeyProvider was configured, including a REJECTED document (issuer
// mismatch, missing/non-https jwks_uri) rather than only a transient
// transport failure. A rejected document is a configuration error, not a
// startup race, and must stay fatal even with a provider: tolerating it
// silently abandons JWKS forever, leaving every token the provider does not
// offer failing with unknown_kid and no evidence beyond one log line.
func TestKeyProviderDiscoveryFailureFatality(t *testing.T) {
	t.Parallel()

	kp := &fakeKeyProvider{}

	t.Run("transient discovery failure is tolerated", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		// Unreachable issuer: discovery fails transiently on every retry.
		cfg.Issuer = "http://127.0.0.1:1"
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		cfg.KeyProvider = kp
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err, "a transient discovery failure must not be fatal with a KeyProvider configured")
		t.Cleanup(v.Close)
		assert.Nil(t, v.jwksCache, "JWKS must be abandoned when discovery never succeeded")
	})

	t.Run("rejected discovery document is fatal even with a provider", func(t *testing.T) {
		t.Parallel()
		// The discovery document's issuer does not match the configured
		// issuer: the endpoint answered, and the answer is a poisoned/
		// misconfigured document, not a race.
		srv := discoveryServer(t, func(_ string) http.HandlerFunc {
			return serveDiscovery("https://a-different-issuer.example.com", "https://a-different-issuer.example.com/jwks.json", nil)
		})
		cfg := validConfig()
		cfg.Issuer = srv.URL
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		cfg.KeyProvider = kp
		v, err := NewValidator(context.Background(), cfg)
		require.Error(t, err, "a rejected discovery document must stay fatal even with a KeyProvider configured")
		assert.Nil(t, v)
		assert.Contains(t, err.Error(), "does not match configured issuer")
	})
}

// TestAuthTokenFileAttachesBearerToken covers finding 5: AuthTokenFile must
// attach a bearer token (read from the file) to outbound discovery/JWKS
// requests, for an IdP whose own endpoints are gated. Without this the only
// route was a caller-supplied HTTPClient, which opts out of the private-IP
// dial guard entirely.
func TestAuthTokenFileAttachesBearerToken(t *testing.T) {
	t.Parallel()

	const wantToken = "s3cr3t-token"
	tokenFile := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(tokenFile, []byte(wantToken), 0o600))

	var gotAuth atomic.Value
	srv := discoveryServer(t, func(srvURL string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			gotAuth.Store(r.Header.Get("Authorization"))
			serveDiscovery(srvURL, srvURL+"/jwks.json", nil)(w, r)
		}
	})

	cfg := validConfig()
	cfg.Issuer = srv.URL
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true
	cfg.AuthTokenFile = tokenFile
	v, err := NewValidator(context.Background(), cfg)
	require.NoError(t, err)
	t.Cleanup(v.Close)

	got, _ := gotAuth.Load().(string)
	assert.Equal(t, "Bearer "+wantToken, got,
		"AuthTokenFile must attach the token as a Bearer Authorization header on outbound requests")
}

// TestDisableLeewayValidation covers finding 6: DisableLeeway must let a
// caller express zero clock-skew tolerance (Leeway==0 alone means "use the
// 60s default"), and setting it together with a non-zero Leeway must be a
// validation error, mirroring AllowAnyAudience's explicit-opt-out style.
func TestDisableLeewayValidation(t *testing.T) {
	t.Parallel()

	t.Run("DisableLeeway alone leaves Leeway at zero", func(t *testing.T) {
		t.Parallel()
		srv := newDiscoveryOnlyServer(t)
		cfg := validConfig()
		cfg.Issuer = srv.URL
		cfg.InsecureAllowHTTP = true
		cfg.AllowPrivateIP = true
		cfg.DisableLeeway = true
		v, err := NewValidator(context.Background(), cfg)
		require.NoError(t, err)
		t.Cleanup(v.Close)
		assert.Zero(t, v.cfg.Leeway, "DisableLeeway must not be overwritten by the 60s default")
	})

	t.Run("DisableLeeway with a non-zero Leeway is rejected", func(t *testing.T) {
		t.Parallel()
		cfg := validConfig()
		cfg.DisableLeeway = true
		cfg.Leeway = 30 * time.Second
		v, err := NewValidator(context.Background(), cfg)
		require.Error(t, err)
		assert.Nil(t, v)
		assert.Contains(t, err.Error(), "DisableLeeway must not be set together with")
	})
}

// TestDefaultClientDisablesKeepAlives asserts the structural pairing: whenever
// the dial guard is installed, keep-alives must be off, or a pooled connection
// would skip the per-dial address check on a later JWKS refresh. authn refreshes
// every 15 minutes over a long-lived client, so this matters here specifically.
func TestDefaultClientDisablesKeepAlives(t *testing.T) {
	t.Parallel()

	client, err := newHTTPClient(nil, false, "", "")
	require.NoError(t, err)
	// The default chain is limitedTransport (authn's body cap) ->
	// networking.ValidatingTransport -> *http.Transport. Unwrap to the bottom.
	capped, ok := client.Transport.(limitedTransport)
	require.True(t, ok, "the default transport must be body-capped")
	validating, ok := capped.base.(*networking.ValidatingTransport)
	require.True(t, ok, "the default client must use networking's validating transport")
	transport, ok := validating.Transport.(*http.Transport)
	require.True(t, ok, "the default client must bottom out in an *http.Transport")
	assert.True(t, transport.DisableKeepAlives,
		"keep-alives must be disabled whenever the dial guard is installed")
	assert.NotNil(t, transport.DialContext, "the dial guard must be installed by default")
}

// TestFailedConstructionDoesNotLeakGoroutines pins a property a consumer depends
// on: NewValidator cancels its lifetime context before returning an error, so a
// caller that retries construction in a loop — the recommended way to tolerate an
// unreachable issuer without a lazy mode inside this package — does not
// accumulate jwx cache goroutines with every failed attempt.
//
// It is a regression test, not a discovery: the cancel is already there. But it
// is one line inside an error path, and losing it would leak silently and only
// show up as slow memory growth in a service that retries.
//
//nolint:paralleltest // counts goroutines; a parallel sibling would make the measurement meaningless
func TestFailedConstructionDoesNotLeakGoroutines(t *testing.T) {
	// Deliberately NOT parallel: it counts goroutines, so a sibling test
	// starting servers concurrently would make the measurement meaningless.
	cfg := validConfig()
	cfg.JWKSURL = unreachableJWKSURL // refuses connections
	cfg.InsecureAllowHTTP = true
	cfg.AllowPrivateIP = true

	// One failure first, so any one-off lazy initialisation is already paid for
	// and not counted as a leak below.
	_, err := NewValidator(context.Background(), cfg)
	require.Error(t, err)
	settleGoroutines()
	baseline := runtime.NumGoroutine()

	const attempts = 40
	for range attempts {
		v, err := NewValidator(context.Background(), cfg)
		require.Error(t, err, "an unreachable JWKS with no KeyProvider must fail construction")
		require.Nil(t, v)
	}

	// Cancellation is asynchronous: the goroutines observe the cancelled context
	// and exit shortly after. Poll rather than assert immediately.
	require.Eventually(t, func() bool {
		return runtime.NumGoroutine() <= baseline+attempts/4
	}, 10*time.Second, 100*time.Millisecond,
		"goroutines grew across %d failed constructions (baseline %d, now %d): "+
			"NewValidator must cancel its context before returning an error",
		attempts, baseline, runtime.NumGoroutine())
}

// settleGoroutines gives recently-cancelled goroutines a chance to exit so a
// count taken afterwards is stable.
func settleGoroutines() {
	for range 20 {
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}
}
