// SPDX-FileCopyrightText: Copyright 2026 Stacklok, Inc.
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/stacklok/toolhive-core/networking"
)

// wantErrExceeds is the substring shared by the "over a configured limit"
// errors (leeway, audience length, token length, body cap).
const wantErrExceeds = "exceeds"

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
				c.JWKSURL = "http://127.0.0.1:1/jwks.json"
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
	assert.ErrorIs(t, err, http.ErrUseLastResponse)
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
		assert.ErrorIs(t, err, http.ErrUseLastResponse)
		// The zero Timeout was replaced with the default.
		assert.Equal(t, defaultHTTPTimeout, v.httpClient.Timeout)
	})

	t.Run("supplied client refuses a 302 from the JWKS URL", func(t *testing.T) {
		t.Parallel()
		// An httptest server that 302-redirects its JWKS URL to a different
		// host. A bare &http.Client{} passed through newHTTPClient must refuse
		// the redirect (SSRF): the JWKS GET surfaces the 302 rather than
		// following it to the redirect target. We exercise newHTTPClient
		// directly to isolate the redirect-refusal behavior from
		// construction's fail-closed fetch (which would also surface the 302
		// as an error, just a less direct assertion).
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
		client, err := newHTTPClient(&http.Client{}, false, "") // nil CheckRedirect, zero Timeout
		require.NoError(t, err)
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, redirector.URL+"/jwks.json", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		assert.Equal(t, http.StatusFound, resp.StatusCode,
			"a bare supplied client must refuse the JWKS redirect (SSRF), not follow it to the target")
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

// TestDefaultClientDisablesKeepAlives asserts the structural pairing: whenever
// the dial guard is installed, keep-alives must be off, or a pooled connection
// would skip the per-dial address check on a later JWKS refresh. authn refreshes
// every 15 minutes over a long-lived client, so this matters here specifically.
func TestDefaultClientDisablesKeepAlives(t *testing.T) {
	t.Parallel()

	client, err := newHTTPClient(nil, false, "")
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
